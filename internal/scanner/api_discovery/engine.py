import httpx
import json

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/swagger.json", "/swagger/v1/swagger.json",
    "/api/swagger.json", "/api/docs", "/api/schema",
    "/openapi.json", "/api/openapi.json",
    "/graphql", "/api/graphql",
    "/.well-known/openid-configuration",
    "/api/health", "/api/status",
    "/api/users", "/api/login", "/api/auth",
    "/api/register", "/api/tokens",
    "/health", "/healthz", "/readyz",
    "/actuator", "/actuator/health",
    "/api/endpoints", "/api/services",
    "/docs", "/redoc", "/swagger",
]

COMMON_API_PORTS = [443, 80, 8080, 8443, 3000, 4000, 5000, 8000, 9000]


async def discover_api_endpoints(host: str, port: int = 443) -> list[dict]:
    results = []
    schemes = ["https", "http"]
    for scheme in schemes:
        base = f"{scheme}://{host}:{port}"
        async with httpx.AsyncClient(timeout=8, verify=False) as client:
            for path in API_PATHS:
                try:
                    resp = await client.get(f"{base}{path}", follow_redirects=False)
                    if resp.status_code in (200, 401, 403, 405):
                        content_type = resp.headers.get("content-type", "")
                        body_snippet = resp.text[:200] if resp.text else ""

                        api_type = "unknown"
                        if "swagger" in path.lower():
                            api_type = "swagger"
                        elif "openapi" in path.lower():
                            api_type = "openapi"
                        elif "graphql" in path.lower():
                            api_type = "graphql"
                        elif "actuator" in path.lower():
                            api_type = "spring_actuator"
                        elif "docs" in path.lower() or "redoc" in path.lower():
                            api_type = "api_docs"

                        details = f"api_endpoint={path}, status_code={resp.status_code}, content_type={content_type}"
                        if "json" in content_type:
                            try:
                                data = resp.json()
                                if isinstance(data, dict):
                                    keys = list(data.keys())[:5]
                                    details += f", response_keys={keys}"
                            except Exception:
                                pass

                        results.append({
                            "asset_type": "technology",
                            "value": f"{host}:{port}{path}",
                            "details": details,
                            "api_type": api_type,
                        })
                except Exception:
                    continue
    return results


async def scan_for_apis(host: str, ports: list[int] | None = None) -> list[dict]:
    results = []
    ports_to_scan = ports or [443, 80, 8080]
    for port in ports_to_scan:
        try:
            api_results = await discover_api_endpoints(host, port)
            results.extend(api_results)
        except Exception:
            continue
    return results
