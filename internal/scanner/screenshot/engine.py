import httpx
import os
from datetime import datetime


SCREENSHOT_DIR = "web/static/screenshots"


async def capture_screenshot(host: str, port: int = 443) -> dict | None:
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    schemes = ["https", "http"]
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}"
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(url, follow_redirects=True, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                body = resp.text

                title = ""
                if "<title>" in body and "</title>" in body:
                    title = body.split("<title>")[1].split("</title>")[0].strip()[:100]

                description = ""
                meta_desc = ""
                if '<meta name="description"' in body.lower():
                    import re
                    match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']', body, re.I)
                    if match:
                        meta_desc = match.group(1)[:200]

                favicon = ""
                fav_match = re.search(r'<link\s+[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']', body, re.I)
                if fav_match:
                    favicon = fav_match.group(1)

                content_type = resp.headers.get("content-type", "unknown")
                server = resp.headers.get("server", "")
                powered_by = resp.headers.get("x-powered-by", "")

                return {
                    "asset_type": "technology",
                    "value": f"{host}:{port}",
                    "details": (
                        f"title={title}, "
                        f"description={meta_desc}, "
                        f"content_type={content_type}, "
                        f"server={server}, "
                        f"x-powered-by={powered_by}, "
                        f"status_code={resp.status_code}, "
                        f"favicon={favicon}"
                    ),
                }
        except Exception:
            continue
    return None
