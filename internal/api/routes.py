from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from internal.db.database import get_db
from internal.models.models import Target, Asset, ScanJob, AlertConfig, AlertEvent, AssetHistory, ScanProfile, User, ApiKey, Workspace
from internal.scanner.discovery import engine as discovery_engine
from internal.scanner.portscan import engine as portscan_engine
from internal.scanner.cert import engine as cert_engine
from internal.scanner.tech import engine as tech_engine
from internal.scanner.vuln import engine as vuln_engine
from internal.scanner.passive import engine as passive_engine
from internal.scanner.ssl import engine as ssl_engine
from internal.scanner.screenshot import engine as screenshot_engine
from internal.export import exporter
from internal.auth.auth import hash_password, create_session_token, generate_api_key, verify_api_key, get_current_user
from internal.monitor.monitor import check_new_assets
import asyncio
import re
import json

router = APIRouter()
active_connections: dict[int, list[WebSocket]] = {}


def sanitize_domain(domain: str) -> str:
    domain = domain.strip().rstrip("/")
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split(":")[0]
    domain = domain.split("/")[0]
    return domain.lower()


# ─── Pydantic Schemas ───────────────────────────────────────

class TargetCreate(BaseModel):
    domain: str
    description: Optional[str] = None
    tags: Optional[list[str]] = None

class TargetUpdate(BaseModel):
    description: Optional[str] = None
    tags: Optional[list[str]] = None

class ScanRequest(BaseModel):
    scan_type: str = "full"
    scan_profile: Optional[str] = "standard"

class AlertConfigCreate(BaseModel):
    name: str
    channel: str
    config: dict
    events: list[str] = ["new_asset", "cert_expiry"]
    target_id: Optional[int] = None

class UserCreate(BaseModel):
    email: str
    username: str
    password: str

class AssetUpdate(BaseModel):
    tags: Optional[list[str]] = None
    risk_score: Optional[float] = None
    is_active: Optional[bool] = None


# ─── Auth Routes ─────────────────────────────────────────────

@router.post("/auth/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter((User.email == user.email) | (User.username == user.username)).first():
        raise HTTPException(status_code=400, detail="User already exists")
    db_user = User(email=user.email, username=user.username, hashed_password=hash_password(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    workspace = Workspace(name=f"{user.username}'s Workspace", owner_id=db_user.id)
    db.add(workspace)
    db.commit()
    return {"id": db_user.id, "email": db_user.email, "username": db_user.username}

@router.post("/auth/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or user.hashed_password != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session_token(user.id)
    return {"token": token, "user": {"id": user.id, "username": user.username, "email": user.email}}

@router.get("/auth/me")
def get_me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "email": user.email, "role": user.role}

@router.post("/auth/api-keys")
def create_api_key(name: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    key, key_hash = generate_api_key()
    api_key = ApiKey(key_hash=key_hash, name=name, user_id=user.id)
    db.add(api_key)
    db.commit()
    return {"key": key, "name": name, "id": api_key.id}


# ─── Target Routes ───────────────────────────────────────────

@router.get("/targets")
def list_targets(search: Optional[str] = None, page: int = Query(1, ge=1), per_page: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    query = db.query(Target)
    if search:
        query = query.filter(Target.domain.ilike(f"%{search}%"))
    total = query.count()
    targets = query.order_by(Target.added_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    result = []
    for t in targets:
        asset_count = db.query(Asset).filter(Asset.target_id == t.id).count()
        high_risk = db.query(Asset).filter(Asset.target_id == t.id, Asset.risk_score >= 7.0).count()
        result.append({
            "id": t.id,
            "domain": t.domain,
            "description": t.description,
            "tags": t.tags or [],
            "risk_score": t.risk_score or 0,
            "asset_count": asset_count,
            "high_risk_count": high_risk,
            "added_at": t.added_at,
            "last_scanned": t.last_scanned,
            "is_active": t.is_active,
        })
    return {"targets": result, "total": total, "page": page, "per_page": per_page}

@router.post("/targets")
def create_target(target: TargetCreate, db: Session = Depends(get_db)):
    domain = sanitize_domain(target.domain)
    existing = db.query(Target).filter(Target.domain == domain).first()
    if existing:
        raise HTTPException(status_code=400, detail="Target already exists")
    new_target = Target(domain=domain, description=target.description, tags=target.tags or [])
    db.add(new_target)
    db.commit()
    db.refresh(new_target)
    return new_target

@router.get("/targets/{target_id}")
def get_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    asset_count = db.query(Asset).filter(Asset.target_id == target_id).count()
    assets_by_type = {}
    for t in ["subdomain", "port", "certificate", "technology", "vulnerability", "dns_record"]:
        assets_by_type[t] = db.query(Asset).filter(Asset.target_id == target_id, Asset.asset_type == t).count()
    return {
        "id": target.id,
        "domain": target.domain,
        "description": target.description,
        "tags": target.tags or [],
        "risk_score": target.risk_score or 0,
        "asset_count": asset_count,
        "assets_by_type": assets_by_type,
        "added_at": target.added_at,
        "last_scanned": target.last_scanned,
        "is_active": target.is_active,
    }

@router.put("/targets/{target_id}")
def update_target(target_id: int, update: TargetUpdate, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if update.description is not None:
        target.description = update.description
    if update.tags is not None:
        target.tags = update.tags
    db.commit()
    return target

@router.delete("/targets/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.query(AssetHistory).filter(AssetHistory.target_id == target_id).delete()
    db.query(Asset).filter(Asset.target_id == target_id).delete()
    db.query(ScanJob).filter(ScanJob.target_id == target_id).delete()
    db.delete(target)
    db.commit()
    return {"message": "Target deleted"}


# ─── Asset Routes ────────────────────────────────────────────

@router.get("/targets/{target_id}/assets")
def list_assets(
    target_id: int,
    asset_type: Optional[str] = None,
    search: Optional[str] = None,
    risk_min: Optional[float] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = db.query(Asset).filter(Asset.target_id == target_id)
    if asset_type and asset_type != "all":
        query = query.filter(Asset.asset_type == asset_type)
    if search:
        query = query.filter(Asset.value.ilike(f"%{search}%"))
    if risk_min is not None:
        query = query.filter(Asset.risk_score >= risk_min)
    total = query.count()
    assets = query.order_by(Asset.risk_score.desc(), Asset.discovered_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {"assets": assets, "total": total, "page": page, "per_page": per_page}

@router.put("/assets/{asset_id}")
def update_asset(asset_id: int, update: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if update.tags is not None:
        asset.tags = update.tags
    if update.risk_score is not None:
        asset.risk_score = update.risk_score
    if update.is_active is not None:
        asset.is_active = update.is_active
    db.commit()
    return asset

@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.query(AssetHistory).filter(AssetHistory.asset_id == asset_id).delete()
    db.delete(asset)
    db.commit()
    return {"message": "Asset deleted"}

@router.get("/assets/{asset_id}/history")
def get_asset_history(asset_id: int, db: Session = Depends(get_db)):
    history = db.query(AssetHistory).filter(AssetHistory.asset_id == asset_id).order_by(AssetHistory.changed_at.desc()).all()
    return history


# ─── Scan Routes ─────────────────────────────────────────────

SCAN_PROFILES = {
    "light": {
        "discovery": True,
        "portscan": {"ports": [80, 443, 22, 21]},
        "cert": False,
        "tech": False,
        "vuln": False,
        "passive": False,
        "ssl": False,
        "screenshot": False,
    },
    "standard": {
        "discovery": True,
        "portscan": {"ports": None},
        "cert": True,
        "tech": True,
        "vuln": True,
        "passive": True,
        "ssl": False,
        "screenshot": False,
    },
    "deep": {
        "discovery": True,
        "portscan": {"ports": None},
        "cert": True,
        "tech": True,
        "vuln": True,
        "passive": True,
        "ssl": True,
        "screenshot": True,
    },
}

@router.post("/targets/{target_id}/scan")
async def trigger_scan(target_id: int, request: Optional[ScanRequest] = None, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan_type = request.scan_type if request else "full"
    profile_name = request.scan_profile if request and request.scan_profile else "standard"
    profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["standard"])

    job = ScanJob(
        target_id=target_id,
        scan_type=scan_type,
        scan_profile=profile_name,
        status="running",
        started_at=datetime.utcnow(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        all_results = []
        steps = []
        domain = target.domain

        if profile.get("discovery") and scan_type in ("full", "discovery"):
            steps.append(("discovery",))
        step_count = len([k for k in profile if profile[k] is not False]) or 1

        await update_progress(db, job, 0, "Starting scan...")
        await notify_clients(target_id, job)

        # Passive recon
        if profile.get("passive") and scan_type in ("full", "discovery"):
            await update_progress(db, job, 10, "Running passive reconnaissance...")
            await notify_clients(target_id, job)
            try:
                passive_results = await passive_engine.discover_passive(domain)
                all_results.extend(passive_results)
            except Exception:
                pass

        # DNS discovery
        if profile.get("discovery") and scan_type in ("full", "discovery"):
            await update_progress(db, job, 20, "Discovering subdomains...")
            await notify_clients(target_id, job)
            all_results.extend(await discovery_engine.discover_subdomains(domain))
            all_results.extend(await discovery_engine.discover_dns_records(domain))

        # Port scan
        if profile.get("portscan") and scan_type in ("full", "portscan"):
            await update_progress(db, job, 35, "Scanning ports...")
            await notify_clients(target_id, job)
            port_config = profile["portscan"]
            ports = port_config.get("ports") if isinstance(port_config, dict) else None
            all_results.extend(await portscan_engine.scan_ports(domain, ports))

        # Certificate
        if profile.get("cert") and scan_type in ("full", "cert"):
            await update_progress(db, job, 50, "Checking certificates...")
            await notify_clients(target_id, job)
            cert_result = await cert_engine.check_certificate(domain)
            if cert_result:
                all_results.append(cert_result)

        # Tech fingerprinting
        if profile.get("tech") and scan_type in ("full", "tech"):
            await update_progress(db, job, 60, "Fingerprinting technologies...")
            await notify_clients(target_id, job)
            all_results.extend(await tech_engine.fingerprint_tech(domain))

        # Screenshot
        if profile.get("screenshot") and scan_type in ("full", "tech"):
            await update_progress(db, job, 70, "Capturing screenshots...")
            await notify_clients(target_id, job)
            shot = await screenshot_engine.capture_screenshot(domain)
            if shot:
                all_results.append(shot)

        # SSL analysis
        if profile.get("ssl") and scan_type in ("full", "vuln"):
            await update_progress(db, job, 80, "Analyzing SSL/TLS...")
            await notify_clients(target_id, job)
            all_results.extend(await ssl_engine.analyze_ssl(domain))

        # Vulnerabilities
        if profile.get("vuln") and scan_type in ("full", "vuln"):
            await update_progress(db, job, 90, "Scanning for vulnerabilities...")
            await notify_clients(target_id, job)
            all_results.extend(await vuln_engine.scan_vulnerabilities(domain))
            vuln_port_results = await vuln_engine.scan_vulnerabilities(domain, 80)
            all_results.extend(vuln_port_results)

        # Save results
        new_assets = []
        seen = set()
        for r in all_results:
            key = (r["asset_type"], r["value"])
            if key in seen:
                continue
            seen.add(key)
            existing = db.query(Asset).filter(
                Asset.target_id == target_id,
                Asset.asset_type == r["asset_type"],
                Asset.value == r["value"],
            ).first()
            if existing:
                existing.last_seen_at = datetime.utcnow()
                existing.details = r.get("details", existing.details)
                if "severity" in r:
                    severity_map = {"critical": 9, "high": 7, "medium": 5, "low": 2, "info": 0}
                    existing.risk_score = max(existing.risk_score or 0, severity_map.get(r.get("severity", "info"), 0))
            else:
                severity_map = {"critical": 9, "high": 7, "medium": 5, "low": 2, "info": 0}
                risk = severity_map.get(r.get("severity", "info"), 0)
                asset = Asset(
                    target_id=target_id,
                    asset_type=r["asset_type"],
                    value=r["value"],
                    details=r.get("details", ""),
                    risk_score=risk,
                )
                db.add(asset)
                db.flush()
                new_assets.append(asset)
                db.add(AssetHistory(
                    asset_id=asset.id,
                    target_id=target_id,
                    field_changed="discovered",
                    new_value=r["value"],
                    change_type="new",
                ))

        target.last_scanned = datetime.utcnow()
        high_risk_count = db.query(Asset).filter(
            Asset.target_id == target_id, Asset.risk_score >= 7.0
        ).count()
        target.risk_score = high_risk_count * 2.0

        job.status = "completed"
        job.completed_at = datetime.utcnow()
        job.results_count = len(seen)
        db.commit()

        await check_new_assets(target_id, new_assets)
        await update_progress(db, job, 100, "Scan complete")
        await notify_clients(target_id, job)

        return {"job_id": job.id, "status": job.status, "results_count": job.results_count}

    except Exception as e:
        job.status = "failed"
        job.error_message = str(e)
        job.completed_at = datetime.utcnow()
        db.commit()
        await update_progress(db, job, -1, f"Failed: {str(e)}")
        await notify_clients(target_id, job)
        raise HTTPException(status_code=500, detail=str(e))


# ─── WebSocket ──────────────────────────────────────────────

@router.websocket("/ws/{target_id}")
async def websocket_endpoint(websocket: WebSocket, target_id: int):
    await websocket.accept()
    if target_id not in active_connections:
        active_connections[target_id] = []
    active_connections[target_id].append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections[target_id].remove(websocket)
        if not active_connections[target_id]:
            del active_connections[target_id]


async def notify_clients(target_id: int, job: ScanJob):
    if target_id in active_connections:
        message = json.dumps({
            "job_id": job.id,
            "status": job.status,
            "progress": job.progress,
            "progress_message": job.progress_message,
            "results_count": job.results_count,
        })
        for ws in active_connections[target_id]:
            try:
                await ws.send_text(message)
            except Exception:
                pass


async def update_progress(db: Session, job: ScanJob, progress: float, message: str):
    job.progress = progress
    job.progress_message = message
    db.commit()


# ─── Job Routes ──────────────────────────────────────────────

@router.get("/jobs")
def list_jobs(target_id: Optional[int] = None, status: Optional[str] = None, page: int = Query(1, ge=1), per_page: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    query = db.query(ScanJob)
    if target_id:
        query = query.filter(ScanJob.target_id == target_id)
    if status:
        query = query.filter(ScanJob.status == status)
    total = query.count()
    jobs = query.order_by(ScanJob.started_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    result = []
    for j in jobs:
        target = db.query(Target).filter(Target.id == j.target_id).first()
        result.append({
            "id": j.id,
            "target_id": j.target_id,
            "target_domain": target.domain if target else "Deleted",
            "scan_type": j.scan_type,
            "scan_profile": j.scan_profile,
            "status": j.status,
            "progress": j.progress,
            "progress_message": j.progress_message,
            "results_count": j.results_count,
            "error_message": j.error_message,
            "started_at": j.started_at,
            "completed_at": j.completed_at,
        })
    return {"jobs": result, "total": total, "page": page, "per_page": per_page}


# ─── Dashboard ───────────────────────────────────────────────

@router.get("/dashboard")
def dashboard_stats(db: Session = Depends(get_db)):
    total_targets = db.query(Target).count()
    total_assets = db.query(Asset).count()
    assets_by_type = {}
    for t in ["subdomain", "port", "certificate", "technology", "vulnerability", "dns_record"]:
        assets_by_type[t] = db.query(Asset).filter(Asset.asset_type == t).count()
    completed_jobs = db.query(ScanJob).filter(ScanJob.status == "completed").count()
    total_jobs = db.query(ScanJob).count()
    high_risk = db.query(Asset).filter(Asset.risk_score >= 7.0).count()
    medium_risk = db.query(Asset).filter(Asset.risk_score >= 4.0, Asset.risk_score < 7.0).count()
    unread_alerts = db.query(AlertEvent).filter(AlertEvent.is_read == False).count()
    recent_alerts = db.query(AlertEvent).order_by(AlertEvent.created_at.desc()).limit(5).all()
    top_risky = db.query(Target).order_by(Target.risk_score.desc()).limit(5).all()
    return {
        "total_targets": total_targets,
        "total_assets": total_assets,
        "assets_by_type": assets_by_type,
        "total_scans": total_jobs,
        "completed_scans": completed_jobs,
        "high_risk_assets": high_risk,
        "medium_risk_assets": medium_risk,
        "unread_alerts": unread_alerts,
        "recent_alerts": [{"id": a.id, "title": a.title, "severity": a.severity, "created_at": a.created_at} for a in recent_alerts],
        "top_risky_targets": [{"id": t.id, "domain": t.domain, "risk_score": t.risk_score or 0} for t in top_risky],
    }


# ─── Alert Routes ────────────────────────────────────────────

@router.get("/alerts")
def list_alerts(page: int = Query(1, ge=1), per_page: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    total = db.query(AlertEvent).count()
    alerts = db.query(AlertEvent).order_by(AlertEvent.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {"alerts": alerts, "total": total, "page": page, "per_page": per_page}

@router.post("/alerts/{alert_id}/read")
def mark_alert_read(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(AlertEvent).filter(AlertEvent.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_read = True
    db.commit()
    return {"message": "Alert marked as read"}

@router.post("/alerts/read-all")
def mark_all_alerts_read(db: Session = Depends(get_db)):
    db.query(AlertEvent).filter(AlertEvent.is_read == False).update({"is_read": True})
    db.commit()
    return {"message": "All alerts marked as read"}

@router.post("/alert-configs")
def create_alert_config(config: AlertConfigCreate, db: Session = Depends(get_db)):
    ac = AlertConfig(
        name=config.name,
        channel=config.channel,
        config=config.config,
        events=config.events,
        target_id=config.target_id,
    )
    db.add(ac)
    db.commit()
    db.refresh(ac)
    return ac

@router.get("/alert-configs")
def list_alert_configs(target_id: Optional[int] = None, db: Session = Depends(get_db)):
    query = db.query(AlertConfig)
    if target_id:
        query = query.filter(AlertConfig.target_id == target_id)
    return query.all()

@router.delete("/alert-configs/{config_id}")
def delete_alert_config(config_id: int, db: Session = Depends(get_db)):
    ac = db.query(AlertConfig).filter(AlertConfig.id == config_id).first()
    if not ac:
        raise HTTPException(status_code=404, detail="Alert config not found")
    db.delete(ac)
    db.commit()
    return {"message": "Alert config deleted"}


# ─── Export Routes ───────────────────────────────────────────

@router.get("/export/targets")
def export_targets(format: str = "csv", db: Session = Depends(get_db)):
    if format == "csv":
        csv_data = exporter.export_targets_csv(db)
        return StreamingResponse(iter([csv_data]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=targets.csv"})
    elif format == "json":
        return exporter.export_targets_json(db)
    raise HTTPException(status_code=400, detail="Unsupported format")

@router.get("/export/assets")
def export_assets(format: str = "csv", target_id: Optional[int] = None, db: Session = Depends(get_db)):
    if format == "csv":
        csv_data = exporter.export_assets_csv(db, target_id)
        return StreamingResponse(iter([csv_data]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=assets.csv"})
    raise HTTPException(status_code=400, detail="Unsupported format")

@router.get("/export/alerts")
def export_alerts(db: Session = Depends(get_db)):
    return exporter.export_alerts_json(db)

@router.get("/export/report")
def get_report(db: Session = Depends(get_db)):
    return exporter.generate_report_summary(db)


# ─── Graph Data ──────────────────────────────────────────────

@router.get("/targets/{target_id}/graph")
def get_asset_graph(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    assets = db.query(Asset).filter(Asset.target_id == target_id).all()
    nodes = {}
    edges = []
    nodes[target.domain] = {"id": target.domain, "label": target.domain, "type": "target", "risk": target.risk_score or 0}
    for a in assets:
        nodes[a.value] = {"id": a.value, "label": a.value, "type": a.asset_type, "risk": a.risk_score or 0}
        edges.append({"source": target.domain, "target": a.value, "type": a.asset_type})
    return {"nodes": list(nodes.values()), "edges": edges}


# ─── Scan Profiles ──────────────────────────────────────────

@router.get("/scan-profiles")
def list_scan_profiles():
    return [
        {"name": "light", "description": "Quick scan - subdomains + common ports only"},
        {"name": "standard", "description": "Balanced scan - all modules except SSL deep analysis"},
        {"name": "deep", "description": "Full scan - all modules including SSL cipher analysis + screenshots"},
    ]
