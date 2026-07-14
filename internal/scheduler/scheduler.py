import schedule
import time
import asyncio
import threading
from datetime import datetime
from internal.db.database import SessionLocal
from internal.models.models import Target, ScanJob, Asset, AssetHistory
from internal.scanner.discovery import engine as discovery_engine
from internal.scanner.portscan import engine as portscan_engine
from internal.scanner.cert import engine as cert_engine
from internal.scanner.tech import engine as tech_engine
from internal.scanner.vuln import engine as vuln_engine
from internal.scanner.passive import engine as passive_engine
from internal.scanner.ssl import engine as ssl_engine
from internal.scanner.screenshot import engine as screenshot_engine
from internal.monitor.monitor import run_monitor
import logging

logger = logging.getLogger(__name__)


async def run_full_scan(target_id: int, domain: str, profile: str = "standard"):
    db = SessionLocal()
    try:
        job = ScanJob(
            target_id=target_id,
            scan_type="scheduled_full",
            scan_profile=profile,
            status="running",
            started_at=datetime.utcnow(),
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        results = []
        try:
            results.extend(await passive_engine.discover_passive(domain))
        except Exception as e:
            logger.warning(f"Passive scan failed for {domain}: {e}")

        try:
            results.extend(await discovery_engine.discover_subdomains(domain))
            results.extend(await discovery_engine.discover_dns_records(domain))
        except Exception as e:
            logger.warning(f"Discovery failed for {domain}: {e}")

        try:
            results.extend(await portscan_engine.scan_ports(domain))
        except Exception as e:
            logger.warning(f"Port scan failed for {domain}: {e}")

        try:
            cert_result = await cert_engine.check_certificate(domain)
            if cert_result:
                results.append(cert_result)
        except Exception as e:
            logger.warning(f"Cert check failed for {domain}: {e}")

        try:
            results.extend(await tech_engine.fingerprint_tech(domain))
        except Exception as e:
            logger.warning(f"Tech fingerprinting failed for {domain}: {e}")

        try:
            results.extend(await vuln_engine.scan_vulnerabilities(domain))
        except Exception as e:
            logger.warning(f"Vuln scan failed for {domain}: {e}")

        try:
            results.extend(await ssl_engine.analyze_ssl(domain))
        except Exception as e:
            logger.warning(f"SSL analysis failed for {domain}: {e}")

        try:
            shot = await screenshot_engine.capture_screenshot(domain)
            if shot:
                results.append(shot)
        except Exception as e:
            logger.warning(f"Screenshot failed for {domain}: {e}")

        seen = set()
        for r in results:
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

        target = db.query(Target).filter(Target.id == target_id).first()
        if target:
            target.last_scanned = datetime.utcnow()

        job.status = "completed"
        job.completed_at = datetime.utcnow()
        job.results_count = len(seen)
        db.commit()

    except Exception as e:
        db.rollback()
        job.status = "failed"
        job.error_message = str(e)
        job.completed_at = datetime.utcnow()
        db.commit()
        logger.error(f"Scheduled scan failed for target {target_id}: {e}")
    finally:
        db.close()


def scheduled_scan(target_id: int, domain: str):
    asyncio.run(run_full_scan(target_id, domain))


def start_scheduler(interval_hours: int = 24):
    def scan_all():
        db = SessionLocal()
        try:
            targets = db.query(Target).filter(Target.is_active == True).all()
            for target in targets:
                logger.info(f"Starting scheduled scan for {target.domain}")
                scheduled_scan(target.id, target.domain)
        except Exception as e:
            logger.error(f"Scheduled scan iteration failed: {e}")
        finally:
            db.close()

    def monitor_check():
        asyncio.run(run_monitor())

    schedule.every(interval_hours).hours.do(scan_all)
    schedule.every(6).hours.do(monitor_check)

    def run():
        while True:
            schedule.run_pending()
            time.sleep(60)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    logger.info(f"Scheduler started: scans every {interval_hours}h, monitor every 6h")
