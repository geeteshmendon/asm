import dns.resolver
import httpx
import json

FINGERPRINTS = {
    "amazonaws.com": {"aws", "s3", "cloudfront"},
    "s3.amazonaws.com": {"no such bucket", "the specified bucket does not exist"},
    "cloudfront.net": {"error: cloudfront"},
    "herokuapp.com": {"there's nothing here", "heroku"},
    "github.io": {"404", "there isn't a github pages site here"},
    "netlify.app": {"not found - request id", "netlify"},
    "vercel.app": {"the page could not be found", "vercel"},
    "firebaseapp.com": {"firebase hosting", "not found"},
    "azurewebsites.net": {"azure web apps service"},
    "trafficmanager.net": {"404 not found"},
    "myshopify.com": {"shopify"},
    "helpshift.com": {"helpshift"},
    "freshdesk.com": {"freshdesk"},
    "zendesk.com": {"help center closed"},
    "unbounce.com": {"unbounce"},
    "surge.sh": {"not found"},
    "bitbucket.io": {"repository not found"},
    "readme.io": {"page not found", "readme"},
    "statuspage.io": {"statuspage"},
    "atlassian.net": {"site not found"},
    "cargo.site": {"cargo"},
    "fly.io": {"not found"},
    "render.com": {"render"},
    "pantheonsite.io": {"pantheon"},
    "wpengine.com": {"wp engine"},
    "acquia.com": {"acquia"},
    "kinsta.com": {"kinsta"},
}

TAKEOVER_SERVICES = {
    "github.io": {"cname": "github.io", "service": "GitHub Pages"},
    "s3.amazonaws.com": {"cname": "amazonaws.com", "service": "AWS S3"},
    "cloudfront.net": {"cname": "cloudfront.net", "service": "CloudFront"},
    "herokuapp.com": {"cname": "herokuapp.com", "service": "Heroku"},
    "netlify.app": {"cname": "netlify.app", "service": "Netlify"},
    "vercel.app": {"cname": "vercel.app", "service": "Vercel"},
    "firebaseapp.com": {"cname": "firebaseapp.com", "service": "Firebase"},
    "azurewebsites.net": {"cname": "azurewebsites.net", "service": "Azure App Service"},
    "myshopify.com": {"cname": "myshopify.com", "service": "Shopify"},
    "zendesk.com": {"cname": "zendesk.com", "service": "Zendesk"},
    "atlassian.net": {"cname": "atlassian.net", "service": "Atlassian"},
    "render.com": {"cname": "render.com", "service": "Render"},
    "fly.io": {"cname": "fly.io", "service": "Fly.io"},
    "pantheonsite.io": {"cname": "pantheonsite.io", "service": "Pantheon"},
    "statuspage.io": {"cname": "statuspage.io", "service": "Statuspage"},
    "freshdesk.com": {"cname": "freshdesk.com", "service": "Freshdesk"},
    "helpshift.com": {"cname": "helpshift.com", "service": "Helpshift"},
    "unbounce.com": {"cname": "unbounce.com", "service": "Unbounce"},
    "bitbucket.io": {"cname": "bitbucket.io", "service": "Bitbucket"},
    "readme.io": {"cname": "readme.io", "service": "ReadMe"},
    "surge.sh": {"cname": "surge.sh", "service": "Surge"},
    "cargo.site": {"cname": "cargo.site", "service": "Cargo"},
    "wpengine.com": {"cname": "wpengine.com", "service": "WP Engine"},
    "trafficmanager.net": {"cname": "trafficmanager.net", "service": "Azure Traffic Manager"},
}


async def check_takeover(subdomain: str) -> dict | None:
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            target = str(rdata.target).rstrip(".")
            target_lower = target.lower()

            for domain_key, info in TAKEOVER_SERVICES.items():
                if domain_key in target_lower:
                    try:
                        async with httpx.AsyncClient(timeout=10, verify=False) as client:
                            for scheme in ("https", "http"):
                                try:
                                    resp = await client.get(f"{scheme}://{subdomain}", follow_redirects=True)
                                    body = resp.text.lower()
                                    fingerprints = FINGERPRINTS.get(domain_key, set())
                                    for fp in fingerprints:
                                        if fp in body:
                                            return {
                                                "asset_type": "vulnerability",
                                                "value": subdomain,
                                                "details": f"Subdomain takeover: {subdomain} CNAME → {target} (service: {info['service']}). "
                                                          f"The external service is unclaimed and can be hijacked.",
                                                "severity": "critical",
                                                "takeover_service": info["service"],
                                                "takeover_cname": target,
                                            }
                                except Exception:
                                    continue
                    except Exception:
                        return {
                            "asset_type": "vulnerability",
                            "value": subdomain,
                            "details": f"Potential subdomain takeover: {subdomain} points to {target} ({info['service']}) "
                                      f"but could not verify. Manual check recommended.",
                            "severity": "medium",
                            "takeover_service": info["service"],
                            "takeover_cname": target,
                        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        pass
    except Exception:
        pass
    return None


async def scan_takeovers(domain: str, subdomains: list[str]) -> list[dict]:
    results = []
    for sub in subdomains:
        result = await check_takeover(sub)
        if result:
            results.append(result)
    return results
