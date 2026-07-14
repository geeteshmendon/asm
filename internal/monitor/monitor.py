import asyncio
from datetime import datetime
from internal.db.database import SessionLocal
from internal.models.models import Asset, AlertConfig, AlertEvent, Target, AssetHistory
from internal.monitor.notifier import send_alert


async def check_certificate_expiry(target_id: int, asset: Asset):
    if asset.asset_type != "certificate":
        return
    details = asset.details or ""
    try:
        for part in details.split(", "):
            if part.startswith("days_remaining="):
                days = int(part.split("=")[1])
                db = SessionLocal()
                try:
                    alert_configs = db.query(AlertConfig).filter(
                        AlertConfig.is_active == True,
                        AlertConfig.target_id == target_id,
                    ).all()
                    for ac in alert_configs:
                        if "cert_expiry" in (ac.events or []):
                            severity = "info"
                            if days < 0:
                                severity = "critical"
                                title = f"Certificate EXPIRED for {asset.value}"
                            elif days < 7:
                                severity = "high"
                                title = f"Certificate expires in {days} days for {asset.value}"
                            elif days < 14:
                                severity = "medium"
                                title = f"Certificate expires in {days} days for {asset.value}"
                            elif days < 30:
                                severity = "low"
                                title = f"Certificate expires in {days} days for {asset.value}"
                            else:
                                continue
                            message = f"Target: {asset.value}\nIssuer: {details}\nDays remaining: {days}"
                            await send_alert(ac, title, message, severity)
                            create_alert_event(
                                target_id=target_id,
                                alert_config_id=ac.id,
                                event_type="cert_expiry",
                                severity=severity,
                                title=title,
                                message=message,
                                extra_data={"days_remaining": days, "asset_id": asset.id},
                            )
                finally:
                    db.close()
                break
    except Exception:
        pass


async def check_new_assets(target_id: int, new_assets: list[Asset]):
    db = SessionLocal()
    try:
        alert_configs = db.query(AlertConfig).filter(
            AlertConfig.is_active == True,
            AlertConfig.target_id == target_id,
        ).all()
        target = db.query(Target).filter(Target.id == target_id).first()
        for asset in new_assets:
            for ac in alert_configs:
                if "new_asset" in (ac.events or []):
                    title = f"New {asset.asset_type} discovered: {asset.value}"
                    message = f"Target: {target.domain if target else 'unknown'}\nType: {asset.asset_type}\nValue: {asset.value}"
                    await send_alert(ac, title, message, "info")
                    create_alert_event(
                        target_id=target_id,
                        alert_config_id=ac.id,
                        event_type="new_asset",
                        severity="info",
                        title=title,
                        message=message,
                        extra_data={"asset_type": asset.asset_type, "asset_value": asset.value},
                    )
    finally:
        db.close()


def create_alert_event(target_id: int | None, alert_config_id: int | None,
                       event_type: str, severity: str, title: str, message: str,
                       extra_data: dict | None = None) -> AlertEvent:
    db = SessionLocal()
    try:
        event = AlertEvent(
            alert_config_id=alert_config_id,
            target_id=target_id,
            event_type=event_type,
            severity=severity,
            title=title,
            message=message,
            extra_data=extra_data or {},
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    finally:
        db.close()


async def run_monitor():
    db = SessionLocal()
    try:
        targets = db.query(Target).all()
        for target in targets:
            assets = db.query(Asset).filter(Asset.target_id == target.id).all()
            for asset in assets:
                await check_certificate_expiry(target.id, asset)
    finally:
        db.close()
