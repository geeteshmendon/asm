import httpx
import ssl
from datetime import datetime

SSL_CHECKS = {
    "ssl_v2": ssl.OP_NO_SSLv2,
    "ssl_v3": ssl.OP_NO_SSLv3,
    "tls_v1_0": ssl.OP_NO_TLSv1,
    "tls_v1_1": ssl.OP_NO_TLSv1_1,
}

COMMON_VULN_PATHS = [
    "/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/",
    "/admin/", "/login", "/.htaccess", "/server-status",
    "/actuator/env", "/actuator/health", "/debug/pprof",
    "/api/swagger.json", "/graphql", "/.well-known/security.txt",
]


async def check_ssl_weakness(host: str, port: int = 443) -> list[dict]:
    results = []
    try:
        context = ssl.create_default_context()
        with httpx.Client(timeout=5, verify=False) as client:
            resp = client.get(f"https://{host}:{port}")
            server = resp.headers.get("Server", "")
            if "nginx" in server.lower() or "apache" in server.lower():
                pass
    except Exception:
        pass
    return results


async def check_exposed_paths(host: str, port: int = 443) -> list[dict]:
    results = []
    schemes = ["https"] if port == 443 else ["http"]
    for scheme in schemes:
        base = f"{scheme}://{host}:{port}"
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            for path in COMMON_VULN_PATHS:
                try:
                    resp = await client.get(f"{base}{path}", follow_redirects=False)
                    if resp.status_code == 200:
                        results.append({
                            "asset_type": "vulnerability",
                            "value": f"{base}{path}",
                            "details": f"exposed path (HTTP {resp.status_code})",
                        })
                    elif resp.status_code in (301, 302, 307, 308):
                        results.append({
                            "asset_type": "vulnerability",
                            "value": f"{base}{path}",
                            "details": f"redirect detected (HTTP {resp.status_code} -> {resp.headers.get('location', 'unknown')})",
                        })
                except Exception:
                    continue
    return results


async def check_security_headers(host: str, port: int = 443) -> list[dict]:
    results = []
    required_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
    ]
    schemes = ["https"] if port == 443 else ["http"]
    for scheme in schemes:
        try:
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                resp = await client.get(f"{scheme}://{host}:{port}")
                missing = [h for h in required_headers if h not in resp.headers]
                if missing:
                    results.append({
                        "asset_type": "vulnerability",
                        "value": f"{scheme}://{host}:{port}",
                        "details": f"missing security headers: {', '.join(missing)}",
                    })
        except Exception:
            continue
    return results


async def scan_vulnerabilities(host: str, port: int = 443) -> list[dict]:
    results = []
    results.extend(await check_exposed_paths(host, port))
    results.extend(await check_security_headers(host, port))
    return results
