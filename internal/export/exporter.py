import csv
import json
import io
from datetime import datetime
from sqlalchemy.orm import Session
from internal.models.models import Target, Asset, ScanJob, AlertEvent


def export_targets_csv(db: Session) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Domain", "Description", "Risk Score", "Tags", "Added At", "Last Scanned", "Asset Count"])
    targets = db.query(Target).all()
    for t in targets:
        asset_count = db.query(Asset).filter(Asset.target_id == t.id).count()
        writer.writerow([
            t.id, t.domain, t.description or "",
            t.risk_score or 0, json.dumps(t.tags or []),
            t.added_at, t.last_scanned or "", asset_count,
        ])
    return output.getvalue()


def export_targets_json(db: Session) -> str:
    targets = db.query(Target).all()
    data = []
    for t in targets:
        assets = db.query(Asset).filter(Asset.target_id == t.id).all()
        data.append({
            "id": t.id,
            "domain": t.domain,
            "description": t.description,
            "risk_score": t.risk_score or 0,
            "tags": t.tags or [],
            "added_at": t.added_at.isoformat() if t.added_at else None,
            "last_scanned": t.last_scanned.isoformat() if t.last_scanned else None,
            "assets": [{
                "id": a.id,
                "type": a.asset_type,
                "value": a.value,
                "risk_score": a.risk_score or 0,
                "tags": a.tags or [],
                "discovered_at": a.discovered_at.isoformat() if a.discovered_at else None,
            } for a in assets],
        })
    return json.dumps(data, indent=2)


def export_assets_csv(db: Session, target_id: int | None = None) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Target", "Type", "Value", "Port", "Protocol", "Risk Score", "Tags", "CPE", "CVE IDs", "Discovered At", "Last Seen"])
    query = db.query(Asset).join(Target)
    if target_id:
        query = query.filter(Asset.target_id == target_id)
    for a in query.all():
        writer.writerow([
            a.id, a.target.domain if a.target else "", a.asset_type, a.value,
            a.port or "", a.protocol or "", a.risk_score or 0,
            json.dumps(a.tags or []), a.cpe or "",
            json.dumps(a.cve_ids or []), a.discovered_at, a.last_seen_at or "",
        ])
    return output.getvalue()


def export_alerts_json(db: Session) -> str:
    alerts = db.query(AlertEvent).order_by(AlertEvent.created_at.desc()).limit(100).all()
    data = [{
        "id": a.id,
        "event_type": a.event_type,
        "severity": a.severity,
        "title": a.title,
        "message": a.message,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    } for a in alerts]
    return json.dumps(data, indent=2)


def generate_report_summary(db: Session) -> dict:
    targets = db.query(Target).count()
    total_assets = db.query(Asset).count()
    assets_by_type = {}
    for t in ["subdomain", "port", "certificate", "technology", "vulnerability", "dns_record"]:
        assets_by_type[t] = db.query(Asset).filter(Asset.asset_type == t).count()
    high_risk = db.query(Asset).filter(Asset.risk_score >= 7.0).count()
    medium_risk = db.query(Asset).filter(Asset.risk_score >= 4.0, Asset.risk_score < 7.0).count()
    low_risk = db.query(Asset).filter(Asset.risk_score < 4.0, Asset.risk_score > 0).count()
    total_scans = db.query(ScanJob).count()
    completed = db.query(ScanJob).filter(ScanJob.status == "completed").count()
    failed = db.query(ScanJob).filter(ScanJob.status == "failed").count()
    recent_alerts = db.query(AlertEvent).filter(
        AlertEvent.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_targets": targets,
        "total_assets": total_assets,
        "assets_by_type": assets_by_type,
        "risk_distribution": {
            "high": high_risk,
            "medium": medium_risk,
            "low": low_risk,
        },
        "scans": {"total": total_scans, "completed": completed, "failed": failed},
        "alerts_today": recent_alerts,
    }
