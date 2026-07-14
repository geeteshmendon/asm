import httpx
import json
from datetime import datetime


async def discover_from_crtsh(domain: str) -> list[dict]:
    results = []
    try:
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            resp = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if resp.status_code == 200:
                entries = resp.json()
                seen = set()
                for entry in entries:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and sub not in seen and sub != domain:
                            seen.add(sub)
                            results.append({
                                "asset_type": "subdomain",
                                "value": sub,
                                "details": "discovered via crt.sh Certificate Transparency",
                                "source": "crt.sh",
                            })
    except Exception:
        pass
    return results


async def discover_from_shodan(domain: str, api_key: str | None = None) -> list[dict]:
    if not api_key:
        return []
    results = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
            )
            if resp.status_code == 200:
                data = resp.json()
                for tag in data.get("tags", []):
                    results.append({
                        "asset_type": "technology",
                        "value": domain,
                        "details": f"shodan tag: {tag}",
                        "source": "shodan",
                    })
                for s in data.get("subdomains", []):
                    results.append({
                        "asset_type": "subdomain",
                        "value": f"{s}.{domain}",
                        "details": "discovered via Shodan",
                        "source": "shodan",
                    })
    except Exception:
        pass
    return results


async def discover_from_securitytrails(domain: str, api_key: str | None = None) -> list[dict]:
    if not api_key:
        return []
    results = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers={"APIKEY": api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    results.append({
                        "asset_type": "subdomain",
                        "value": f"{sub}.{domain}",
                        "details": "discovered via SecurityTrails",
                        "source": "securitytrails",
                    })
    except Exception:
        pass
    return results


async def discover_passive(domain: str,
                           shodan_key: str | None = None,
                           securitytrails_key: str | None = None) -> list[dict]:
    results = []
    results.extend(await discover_from_crtsh(domain))
    results.extend(await discover_from_shodan(domain, shodan_key))
    results.extend(await discover_from_securitytrails(domain, securitytrails_key))
    return results
