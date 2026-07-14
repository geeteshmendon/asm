import httpx
import dns.resolver

AWS_S3_BUCKETS = [
    "assets", "static", "media", "uploads", "files", "images",
    "backup", "data", "prod", "staging", "dev", "test",
    "public", "www", "cdn", "downloads", "docs", "config",
]

CLOUD_SERVICES = {
    "aws": {"domains": ["amazonaws.com", "s3.amazonaws.com", "cloudfront.net"]},
    "azure": {"domains": ["azurewebsites.net", "azureedge.net", "azurefd.net"]},
    "gcp": {"domains": ["appspot.com", "cloudfunctions.net", "storage.googleapis.com"]},
    "cloudflare": {"domains": ["cloudflare.com", "cloudflare.net"]},
    "digitalocean": {"domains": ["digitaloceanspaces.com"]},
    "fastly": {"domains": ["fastly.net"]},
}


async def check_s3_bucket(domain: str, bucket_name: str) -> dict | None:
    url = f"https://{bucket_name}.s3.amazonaws.com"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            if resp.status_code != 404:
                body = resp.text.lower()
                is_listable = "contents" in body or "key" in body
                details = f"s3_bucket={bucket_name}, status={resp.status_code}"
                if resp.status_code == 200:
                    details += ", publicly_accessible"
                if is_listable:
                    details += ", listable"

                return {
                    "asset_type": "technology",
                    "value": f"{domain} (s3://{bucket_name})",
                    "details": details,
                    "cloud_provider": "aws",
                }
    except Exception:
        pass
    return None


async def discover_cloud_assets(domain: str, subdomains: list[str] | None = None) -> list[dict]:
    results = []
    all_names = [domain]
    if subdomains:
        all_names.extend(subdomains)

    prefixes = [domain.replace(".", "-"), domain.split(".")[0]]
    for prefix in prefixes:
        for bucket in AWS_S3_BUCKETS:
            bucket_name = f"{prefix}-{bucket}"
            result = await check_s3_bucket(domain, bucket_name)
            if result:
                results.append(result)

    for name in all_names:
        try:
            answers = dns.resolver.resolve(name, "CNAME")
            for rdata in answers:
                cname = str(rdata.target).lower()
                for cloud, info in CLOUD_SERVICES.items():
                    for cd in info["domains"]:
                        if cd in cname:
                            results.append({
                                "asset_type": "technology",
                                "value": f"{name} → {cname}",
                                "details": f"cloud_service={cloud}, cname={cname}",
                                "cloud_provider": cloud,
                            })
        except Exception:
            continue

    return results
