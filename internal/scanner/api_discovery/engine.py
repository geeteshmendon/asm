import httpx

API_PATHS = [
    "/api", "/api/v1",
    "/swagger.json", "/api/swagger.json",
    "/openapi.json", "/api/openapi.json",
    "/graphql", "/api/graphql",
    "/health", "/api/health",
    "/.well-known/openid-configuration",
    "/actuator/health",
    "/docs", "/swagger",
]


async def check_path(client: httpx.AsyncClient, base: str, path: str) -> dict | None:
    try:
        resp = await client.get(f"{base}{path}", follow_redirects=False, timeout=3)
        if resp.status_code in (200, 401, 403, 405):
            content_type = resp.headers.get("content-type", "")
            api_type = "unknown"
            if "swagger" in path: api_type = "swagger"
            elif "openapi" in path: api_type = "openapi"
            elif "graphql" in path: api_type = "graphql"
            elif "actuator" in path: api_type = "spring_actuator"
            elif "docs" in path: api_type = "api_docs"
            return {
                "asset_type": "technology",
                "value": f"{base}{path}",
                "details": f"api_endpoint={path}, status={resp.status_code}, type={content_type[:30]}",
                "api_type": api_type,
            }
    except Exception:
        return None


async def discover_api_endpoints(host: str) -> list[dict]:
    results = []
    bases = [f"https://{host}:443", f"https://{host}:80", f"http://{host}:80"]

    async with httpx.AsyncClient(timeout=5, verify=False) as client:
        for base in bases[:1]:  # Only try HTTPS:443 first
            for path in API_PATHS:
                result = await check_path(client, base, path)
                if result:
                    results.append(result)
            if not results:
                for path in ["/api", "/swagger.json", "/graphql", "/health"]:
                    result = await check_path(client, base.replace(":443", ":80").replace("https://", "http://"), path)
                    if result:
                        results.append(result)
    return results


async def scan_for_apis(host: str) -> list[dict]:
    try:
        return await discover_api_endpoints(host)
    except Exception:
        return []
