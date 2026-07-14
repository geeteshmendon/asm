import json
from datetime import datetime
from sqlalchemy.orm import Session
from internal.models.models import Asset


def generate_modsecurity_rules(assets: list[dict]) -> str:
    rules = []
    rules.append("# Auto-generated ModSecurity rules by ASM")
    rules.append(f"# Generated: {datetime.utcnow().isoformat()}")
    rules.append("")

    for asset in assets:
        if asset.get("asset_type") != "vulnerability":
            continue
        value = asset.get("value", "")
        details = asset.get("details", "")
        severity = asset.get("severity", "medium")

        if "exposed path" in details:
            path = value.split("/", 3)[-1] if "/" in value else ""
            if path:
                rules.append(f'SecRule REQUEST_URI "@contains {path}" "id:100000,phase:1,deny,status:403,severity:\'{severity}\'"')

        if "missing security headers" in details:
            rules.append(f'SecRule RESPONSE_HEADERS "^$" "id:100001,phase:3,log,severity:\'{severity}\',msg:\'Missing security header: {value}\'"')

    return "\n".join(rules)


def generate_cloudflare_rules(assets: list[dict]) -> list[dict]:
    rules = []
    for asset in assets:
        if asset.get("asset_type") != "vulnerability":
            continue
        value = asset.get("value", "")
        details = asset.get("details", "")
        severity = asset.get("severity", "medium")

        if "exposed path" in details:
            path = value.split("/", 3)[-1] if "/" in value else ""
            if path:
                rules.append({
                    "description": f"Block {path} - ASM auto-generated",
                    "expression": f'(http.request.uri.path contains "{path}")',
                    "action": "block",
                    "severity": severity,
                })
    return rules


async def generate_waf_rules(db: Session, target_id: int | None = None) -> dict:
    query = db.query(Asset).filter(Asset.asset_type == "vulnerability")
    if target_id:
        query = query.filter(Asset.target_id == target_id)
    assets = query.all()

    asset_dicts = [{
        "asset_type": a.asset_type,
        "value": a.value,
        "details": a.details or "",
        "severity": "high" if (a.risk_score or 0) >= 7 else "medium",
    } for a in assets]

    return {
        "modsecurity": generate_modsecurity_rules(asset_dicts),
        "cloudflare": generate_cloudflare_rules(asset_dicts),
        "total_rules": len(asset_dicts),
    }
