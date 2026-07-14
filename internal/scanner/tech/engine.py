import httpx
import re
from datetime import datetime

TECH_SIGNATURES = {
    "nginx": re.compile(r"nginx", re.I),
    "apache": re.compile(r"apache", re.I),
    "iis": re.compile(r"iis|Microsoft-IIS", re.I),
    "cloudflare": re.compile(r"cloudflare", re.I),
    "wordpress": re.compile(r"wp-content|wp-includes|wordpress", re.I),
    "react": re.compile(r"react|__REACT", re.I),
    "angular": re.compile(r"angular|ng-", re.I),
    "vue": re.compile(r"vue|__VUE", re.I),
    "jquery": re.compile(r"jquery", re.I),
    "bootstrap": re.compile(r"bootstrap", re.I),
    "php": re.compile(r"php|PHPSESSID|X-Powered-By: PHP", re.I),
    "node.js": re.compile(r"node|express|connect", re.I),
    "django": re.compile(r"django|csrftoken", re.I),
    "ruby on rails": re.compile(r"rails|ruby|_rails", re.I),
    "laravel": re.compile(r"laravel|laravel_session", re.I),
    "tomcat": re.compile(r"tomcat", re.I),
    "docker": re.compile(r"docker", re.I),
    "kubernetes": re.compile(r"kubernetes", re.I),
    "elasticsearch": re.compile(r"elasticsearch", re.I),
    "redis": re.compile(r"redis", re.I),
}

HEADER_SIGNATURES = {
    "x-powered-by": "x-powered-by",
    "x-generator": "x-generator",
    "server": "server",
    "x-aspnet-version": "asp.net",
    "x-drupal-cache": "drupal",
    "x-litespeed-cache": "litespeed",
}


async def fingerprint_tech(host: str, port: int = 443) -> list[dict]:
    results = []
    schemes = ["https", "http"] if port != 80 else ["http"]
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}"
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(url, follow_redirects=True)
                body = resp.text
                headers = resp.headers
                detected = set()
                for name, pattern in TECH_SIGNATURES.items():
                    if pattern.search(body):
                        detected.add(name)
                for header, tech in HEADER_SIGNATURES.items():
                    if header in headers:
                        detected.add(f"{tech} ({headers[header]})")
                for d in detected:
                    results.append({
                        "asset_type": "technology",
                        "value": f"{host}:{port}",
                        "details": f"detected: {d}",
                    })
                if resp.status_code:
                    results.append({
                        "asset_type": "technology",
                        "value": f"{host}:{port}",
                        "details": f"status_code={resp.status_code}, content_type={resp.headers.get('content-type', 'unknown')}",
                    })
                break
        except Exception as e:
            continue
    return results
