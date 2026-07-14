import httpx
import json
import re
from datetime import datetime

CVE_CACHE = {}

VERSION_PATTERNS = {
    "nginx": r"nginx[\/\s]?([\d\.]+)",
    "apache": r"apache[\/\s]?([\d\.]+)",
    "php": r"php[\/\s]?([\d\.]+)",
    "iis": r"microsoft\-iis[\/\s]?([\d\.]+)",
    "tomcat": r"tomcat[\/\s]?([\d\.]+)",
    "wordpress": r"wordpress[\/\s]?([\d\.]+)",
    "drupal": r"drupal[\/\s]?([\d\.]+)",
    "joomla": r"joomla[\/\s]?([\d\.]+)",
    "node.js": r"node[\/\s]?([\d\.]+)",
    "python": r"python[\/\s]?([\d\.]+)",
    "ruby": r"ruby[\/\s]?([\d\.]+)",
    "openssh": r"openssh[\/\s]?([\d\.]+)",
    "mysql": r"mysql[\/\s]?([\d\.]+)",
    "redis": r"redis[\/\s]?([\d\.]+)",
    "elasticsearch": r"elasticsearch[\/\s]?([\d\.]+)",
    "kubernetes": r"kubernetes[\/\s]?([\d\.]+)",
    "docker": r"docker[\/\s]?([\d\.]+)",
}


def extract_version(tech_name: str, details: str) -> str | None:
    tech_lower = tech_name.lower()
    for key, pattern in VERSION_PATTERNS.items():
        if key in tech_lower or tech_lower in key:
            match = re.search(pattern, details, re.I)
            if match:
                return match.group(1)
    return None


async def fetch_cves(tech_name: str, version: str | None = None) -> list[dict]:
    cache_key = f"{tech_name}:{version or 'any'}"
    if cache_key in CVE_CACHE:
        return CVE_CACHE[cache_key]

    results = []
    query_parts = [tech_name]
    if version:
        query_parts.append(version)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            search = " ".join(query_parts)
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "keywordSearch": search,
                    "resultsPerPage": 10,
                },
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    description = ""
                    descriptions = cve.get("descriptions", [])
                    for d in descriptions:
                        if d.get("lang") == "en":
                            description = d.get("value", "")
                            break
                    metrics = cve.get("metrics", {})
                    cvss_score = None
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if key in metrics:
                            cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                            break
                    results.append({
                        "cve_id": cve_id,
                        "description": description[:200],
                        "cvss_score": cvss_score,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    })
    except Exception:
        pass

    CVE_CACHE[cache_key] = results
    return results


async def check_cves_for_assets(assets: list[dict], db=None) -> list[dict]:
    results = []
    for asset in assets:
        if asset.get("asset_type") != "technology":
            continue
        details = asset.get("details", "")
        value = asset.get("value", "")
        tech_name = ""
        if "detected:" in details:
            tech_name = details.split("detected:")[1].strip().split(",")[0].strip()
        else:
            tech_name = details.split(":")[0] if ":" in details else details

        version = extract_version(tech_name, details)
        cves = await fetch_cves(tech_name, version)

        if version:
            results.append({
                "asset_type": "technology",
                "value": value,
                "details": f"detected: {tech_name} {version}, cve_count: {len(cves)}",
                "cves": cves,
                "version": version,
            })

        for cve in cves[:3]:
            cvss = cve.get("cvss_score")
            severity = "critical" if cvss and cvss >= 9 else "high" if cvss and cvss >= 7 else "medium"
            results.append({
                "asset_type": "vulnerability",
                "value": f"{value} ({cve['cve_id']})",
                "details": f"CVE: {cve['cve_id']} - {cve['description'][:150]} "
                          f"(CVSS: {cvss or 'N/A'}) - {cve['url']}",
                "severity": severity,
                "cve_id": cve["cve_id"],
                "cvss_score": cvss,
            })
    return results
