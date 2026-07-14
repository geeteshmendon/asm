import httpx
import json
import re
import dns.resolver
from datetime import datetime


async def whois_lookup(domain: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"https://rdap.verisign.com/com/v1/domain/{domain}")
            if resp.status_code == 200:
                data = resp.json()
                events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
                entities = []
                for e in data.get("entities", []):
                    for vcard in e.get("vcardArray", [[]])[1:]:
                        for item in vcard:
                            if item[0] == "fn":
                                entities.append(item[3])
                return {
                    "asset_type": "technology",
                    "value": f"{domain} (whois)",
                    "details": f"domain: {domain}, created: {events.get('registration', 'N/A')}, "
                              f"expires: {events.get('expiration', 'N/A')}, "
                              f"nameservers: {', '.join(data.get('nameservers', [])[:5]) if data.get('nameservers') else 'N/A'}, "
                              f"registrar: {data.get('port43', 'N/A')}",
                    "source": "rdap",
                }
    except Exception:
        pass
    return None


async def find_emails(domain: str) -> list[dict]:
    results = []
    patterns = [
        f"admin@{domain}", f"info@{domain}", f"contact@{domain}",
        f"support@{domain}", f"sales@{domain}", f"hello@{domain}",
        f"webmaster@{domain}", f"postmaster@{domain}", f"hostmaster@{domain}",
        f"security@{domain}", f"abuse@{domain}", f"noreply@{domain}",
    ]
    whois_email = None
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://rdap.verisign.com/com/v1/domain/{domain}")
            if resp.status_code == 200:
                data = resp.json()
                for entity in data.get("entities", []):
                    for vcard in entity.get("vcardArray", [[]])[1:]:
                        for item in vcard:
                            if item[0] == "email":
                                whois_email = item[3]
    except Exception:
        pass

    for email in patterns:
        results.append({
            "asset_type": "technology",
            "value": f"{domain} (osint)",
            "details": f"potential_email: {email}",
            "source": "osint_email_pattern",
        })

    if whois_email:
        results.append({
            "asset_type": "technology",
            "value": f"{domain} (osint)",
            "details": f"registrant_email: {whois_email}",
            "source": "osint_whois",
        })

    return results


async def find_social_media(domain: str) -> list[dict]:
    results = []
    name = domain.split(".")[0]
    platforms = {
        "twitter": [f"https://twitter.com/{name}", f"https://twitter.com/{domain.replace('.', '')}"],
        "linkedin": [f"https://linkedin.com/company/{name}", f"https://linkedin.com/company/{domain}"],
        "github": [f"https://github.com/{name}", f"https://github.com/{domain.replace('.', '')}"],
        "facebook": [f"https://facebook.com/{name}"],
        "instagram": [f"https://instagram.com/{name}"],
        "youtube": [f"https://youtube.com/@{name}"],
    }
    async with httpx.AsyncClient(timeout=5, verify=False) as client:
        for platform, urls in platforms.items():
            for url in urls:
                try:
                    resp = await client.head(url, follow_redirects=False)
                    if resp.status_code < 400:
                        results.append({
                            "asset_type": "technology",
                            "value": f"{domain} (osint)",
                            "details": f"social_media: {platform} at {url}",
                            "source": "osint_social",
                        })
                        break
                except Exception:
                    continue
    return results


async def github_search(domain: str) -> list[dict]:
    results = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://api.github.com/search/code?q={domain}&per_page=5",
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", [])[:5]:
                    repo = item.get("repository", {})
                    results.append({
                        "asset_type": "technology",
                        "value": f"{domain} (osint)",
                        "details": f"github: {repo.get('full_name', '')} - {item.get('html_url', '')}",
                        "source": "osint_github",
                    })
    except Exception:
        pass
    return results


async def wayback_machine(domain: str) -> list[dict]:
    results = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=10&fl=original,timestamp"
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data[1:][:10] if len(data) > 1 else []:
                    if len(entry) >= 2:
                        results.append({
                            "asset_type": "technology",
                            "value": f"{domain} (osint)",
                            "details": f"wayback: {entry[0]} (snapshot: {entry[1]})",
                            "source": "osint_wayback",
                        })
    except Exception:
        pass
    return results


async def google_dorks(domain: str) -> list[dict]:
    dorks = [
        f"site:{domain} intitle:index.of",
        f"site:{domain} ext:pdf",
        f"site:{domain} ext:doc ext:docx",
        f"site:{domain} ext:xls ext:xlsx",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:backup",
        f"site:{domain} inurl:wp-admin",
        f"site:{domain} intitle:login",
        f"site:github.com {domain} password",
        f"site:pastebin.com {domain}",
    ]
    return [{
        "asset_type": "technology",
        "value": f"{domain} (osint)",
        "details": f"google_dork: {dork}",
        "source": "osint_dork",
    } for dork in dorks]


async def reverse_dns(domain: str) -> list[dict]:
    results = []
    try:
        answers = dns.resolver.resolve(domain, "A")
        for rdata in answers:
            ip = rdata.address
            try:
                reverse = dns.resolver.resolve_address(ip)
                for r in reverse:
                    results.append({
                        "asset_type": "technology",
                        "value": f"{domain} (osint)",
                        "details": f"reverse_dns: {ip} → {str(r)}",
                        "source": "osint_reverse_dns",
                    })
            except Exception:
                results.append({
                    "asset_type": "technology",
                    "value": f"{domain} (osint)",
                    "details": f"ip_address: {ip}",
                    "source": "osint_ip",
                })
    except Exception:
        pass
    return results


async def run_osint(domain: str) -> list[dict]:
    results = []

    whois = await whois_lookup(domain)
    if whois:
        results.append(whois)

    results.extend(await find_emails(domain))
    results.extend(await find_social_media(domain))
    results.extend(await github_search(domain))
    results.extend(await wayback_machine(domain))
    results.extend(await google_dorks(domain))
    results.extend(await reverse_dns(domain))

    return results
