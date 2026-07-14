from datetime import datetime
from internal.db.database import SessionLocal
from internal.models.models import AlertEvent


class Integration:
    name = ""
    config_schema = {}

    async def send_finding(self, config: dict, finding: dict) -> bool:
        raise NotImplementedError

    def log_event(self, integration_name: str, target_id: int | None,
                  title: str, message: str, severity: str = "info"):
        db = SessionLocal()
        try:
            event = AlertEvent(
                target_id=target_id,
                event_type="integration",
                severity=severity,
                title=title,
                message=message,
                extra_data={"integration": integration_name},
            )
            db.add(event)
            db.commit()
        finally:
            db.close()
