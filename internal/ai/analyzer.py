import json
import os
from datetime import datetime
from internal.db.database import SessionLocal
from internal.models.models import Asset, Target

AI_PROVIDERS = {
    "openai": {"url": "https://api.openai.com/v1/chat/completions", "model": "gpt-4o-mini"},
    "anthropic": {"url": "https://api.anthropic.com/v1/messages", "model": "claude-3-haiku-20240307"},
}


async def analyze_with_ai(target_id: int, provider: str = "openai") -> dict | None:
    api_key = os.environ.get(f"{provider.upper()}_API_KEY")
    if not api_key:
        return {"error": f"No {provider} API key configured. Set {provider.upper()}_API_KEY env var."}

    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            return {"error": "Target not found"}

        assets = db.query(Asset).filter(Asset.target_id == target_id).all()
        if not assets:
            return {"error": "No assets found for this target"}

        vulns = [a for a in assets if a.asset_type == "vulnerability"]
        techs = [a for a in assets if a.asset_type == "technology"]
        ports = [a for a in assets if a.asset_type == "port"]
        certs = [a for a in assets if a.asset_type == "certificate"]
        subs = [a for a in assets if a.asset_type == "subdomain"]

        summary = {
            "domain": target.domain,
            "total_assets": len(assets),
            "vulnerabilities": len(vulns),
            "technologies": len(techs),
            "open_ports": len(ports),
            "subdomains": len(subs),
            "top_vulns": [{"value": v.value, "risk": v.risk_score, "details": v.details[:100]} for v in vulns[:5]],
            "top_tech": [{"value": t.value, "details": t.details[:80]} for t in techs[:5]],
        }

        prompt = f"""You are a security analyst. Analyze this attack surface data and provide:
1. Executive summary of the biggest risks
2. Top 3 remediation priorities
3. Overall security rating (A-F)

Data: {json.dumps(summary, indent=2)}"""

        if provider == "openai":
            return await analyze_openai(api_key, prompt)
        elif provider == "anthropic":
            return await analyze_anthropic(api_key, prompt)
        return {"error": "Unsupported AI provider"}

    finally:
        db.close()


async def analyze_openai(api_key: str, prompt: str) -> dict:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                },
            )
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                return {"analysis": content, "provider": "openai"}
            return {"error": f"OpenAI API error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


async def analyze_anthropic(api_key: str, prompt: str) -> dict:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if resp.status_code == 200:
                content = resp.json()["content"][0]["text"]
                return {"analysis": content, "provider": "anthropic"}
            return {"error": f"Anthropic API error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}
