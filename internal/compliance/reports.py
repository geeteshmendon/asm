from datetime import datetime
from sqlalchemy.orm import Session
from internal.models.models import Asset, Target, ScanJob


def get_owasp_top10_mapping(asset_type: str, details: str) -> list[str]:
    owasp = []
    if asset_type == "vulnerability":
        if "exposed path" in details.lower():
            owasp.append("A01:2021 - Broken Access Control")
        if "missing security headers" in details.lower():
            owasp.append("A05:2021 - Security Misconfiguration")
        if "xss" in details.lower():
            owasp.append("A03:2021 - Injection")
        if "ssl" in details.lower() or "tls" in details.lower():
            owasp.append("A02:2021 - Cryptographic Failures")
        if "exposed" in details.lower() or "sensitive" in details.lower():
            owasp.append("A01:2021 - Broken Access Control")
        if "cve" in details.lower():
            owasp.append("A06:2021 - Vulnerable Components")
    return owasp if owasp else ["A05:2021 - Security Misconfiguration"]


def generate_owasp_report(db: Session) -> dict:
    assets = db.query(Asset).filter(Asset.asset_type == "vulnerability").all()
    owasp_categories = {}
    for asset in assets:
        categories = get_owasp_top10_mapping(asset.asset_type, asset.details or "")
        for cat in categories:
            if cat not in owasp_categories:
                owasp_categories[cat] = {"count": 0, "assets": [], "severity": "low"}
            owasp_categories[cat]["count"] += 1
            risk = asset.risk_score or 0
            if len(owasp_categories[cat]["assets"]) < 5:
                owasp_categories[cat]["assets"].append({
                    "value": asset.value,
                    "risk_score": risk,
                })
            if risk >= 7:
                owasp_categories[cat]["severity"] = "high"
            elif risk >= 4 and owasp_categories[cat]["severity"] != "high":
                owasp_categories[cat]["severity"] = "medium"

    return {
        "report_type": "OWASP Top 10 - 2021",
        "generated_at": datetime.utcnow().isoformat(),
        "total_vulnerabilities": len(assets),
        "categories": owasp_categories,
    }


def generate_pci_report(db: Session) -> dict:
    high_risk = db.query(Asset).filter(Asset.risk_score >= 7.0).count()
    vulns = db.query(Asset).filter(Asset.asset_type == "vulnerability").count()
    open_ports = db.query(Asset).filter(Asset.asset_type == "port").count()
    ssl_issues = db.query(Asset).filter(
        Asset.asset_type == "vulnerability",
        Asset.details.ilike("%ssl%"),
    ).count()
    exposed_paths = db.query(Asset).filter(
        Asset.asset_type == "vulnerability",
        Asset.details.ilike("%exposed%"),
    ).count()
    missing_headers = db.query(Asset).filter(
        Asset.asset_type == "vulnerability",
        Asset.details.ilike("%missing security headers%"),
    ).count()

    findings = []
    if ssl_issues:
        findings.append({"requirement": "4.1 - Encrypt transmission", "status": "FAIL", "details": f"{ssl_issues} SSL/TLS issues"})
    if exposed_paths:
        findings.append({"requirement": "6.3 - Secure coding", "status": "FAIL", "details": f"{exposed_paths} exposed paths"})
    if high_risk > 0:
        findings.append({"requirement": "6.5 - Address vulnerabilities", "status": "FAIL", "details": f"{high_risk} high-risk assets"})
    if missing_headers > 0:
        findings.append({"requirement": "6.6 - Security monitoring", "status": "FAIL", "details": "Missing security headers"})

    return {
        "report_type": "PCI DSS v4.0 Assessment",
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_vulnerabilities": vulns,
            "high_risk_findings": high_risk,
            "open_ports": open_ports,
            "ssl_tls_issues": ssl_issues,
            "exposed_paths": exposed_paths,
            "missing_headers": missing_headers,
        },
        "findings": findings,
        "overall_status": "FAIL" if findings else "PASS",
    }


def generate_hipaa_report(db: Session) -> dict:
    ssl_issues = db.query(Asset).filter(
        Asset.asset_type == "vulnerability",
        Asset.details.ilike("%ssl%"),
    ).count()
    exposed = db.query(Asset).filter(
        Asset.asset_type == "vulnerability",
        Asset.details.ilike("%exposed%"),
    ).count()
    open_ports = db.query(Asset).filter(Asset.asset_type == "port").count()

    findings = []
    if ssl_issues:
        findings.append({"standard": "164.312(a)(1) - Access Control", "status": "FAIL", "details": f"{ssl_issues} SSL/TLS weaknesses"})
    if exposed:
        findings.append({"standard": "164.312(c)(1) - Integrity Control", "status": "FAIL", "details": f"{exposed} exposed paths"})
    if open_ports > 20:
        findings.append({"standard": "164.312(e)(1) - Transmission Security", "status": "FAIL", "details": f"{open_ports} open ports"})

    return {
        "report_type": "HIPAA Security Rule Assessment",
        "generated_at": datetime.utcnow().isoformat(),
        "findings": findings,
        "overall_status": "FAIL" if findings else "PASS",
    }
