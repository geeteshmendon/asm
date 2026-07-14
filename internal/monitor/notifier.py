import httpx
from datetime import datetime, timedelta
from internal.db.database import SessionLocal
from internal.models.models import AlertConfig, AlertEvent


async def send_slack(webhook_url: str, title: str, message: str, severity: str = "info") -> bool:
    color = {"info": "#38bdf8", "low": "#22c55e", "medium": "#f59e0b", "high": "#ef4444", "critical": "#dc2626"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json={
                "attachments": [{
                    "color": color.get(severity, "#38bdf8"),
                    "title": title,
                    "text": message,
                    "footer": "ASM Monitor",
                    "ts": datetime.utcnow().timestamp(),
                }]
            })
            return resp.status_code == 200
    except Exception:
        return False


async def send_discord(webhook_url: str, title: str, message: str, severity: str = "info") -> bool:
    color_map = {"info": 5814783, "low": 2273789, "medium": 16098827, "high": 15728640, "critical": 14426368}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json={
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": color_map.get(severity, 5814783),
                    "timestamp": datetime.utcnow().isoformat(),
                }]
            })
            return resp.status_code == 204
    except Exception:
        return False


async def send_email(smtp_config: dict, title: str, message: str, severity: str = "info") -> bool:
    try:
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg.set_content(message)
        msg["Subject"] = f"[ASM Alert] {title}"
        msg["From"] = smtp_config.get("from_email", "asm@localhost")
        msg["To"] = smtp_config.get("to_email", "")
        with smtplib.SMTP(
            smtp_config.get("host", "localhost"),
            smtp_config.get("port", 25),
            timeout=10,
        ) as server:
            if smtp_config.get("use_tls"):
                server.starttls()
            if smtp_config.get("username"):
                server.login(smtp_config["username"], smtp_config.get("password", ""))
            server.send_message(msg)
        return True
    except Exception:
        return False


async def send_alert(alert_config: AlertConfig, title: str, message: str, severity: str = "info") -> bool:
    channel = alert_config.channel
    config = alert_config.config or {}
    if channel == "slack":
        return await send_slack(config.get("webhook_url", ""), title, message, severity)
    elif channel == "discord":
        return await send_discord(config.get("webhook_url", ""), title, message, severity)
    elif channel == "email":
        return await send_email(config, title, message, severity)
    return False


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
