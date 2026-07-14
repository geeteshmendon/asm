import dns.resolver
import httpx
from datetime import datetime


async def discover_subdomains(domain: str) -> list[dict]:
    results = []
    common_prefixes = [
        "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
        "portal", "dashboard", "app", "cdn", "static", "blog", "docs",
        "support", "help", "login", "auth", "sso", "vpn", "remote",
        "cloud", "db", "smtp", "ns1", "ns2", "mx", "webmail",
        "git", "jenkins", "grafana", "monitor", "status", "beta",
    ]
    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, "A")
            for rdata in answers:
                results.append({
                    "asset_type": "subdomain",
                    "value": subdomain,
                    "details": f"resolves to {rdata.address}",
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            continue
    return results


async def discover_dns_records(domain: str) -> list[dict]:
    results = []
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                results.append({
                    "asset_type": "dns_record",
                    "value": f"{domain} {rtype}",
                    "details": str(rdata),
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            continue
    return results
