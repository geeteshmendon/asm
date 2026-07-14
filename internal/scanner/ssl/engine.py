import ssl
import socket
from datetime import datetime

CIPHER_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
]

WEAK_CIPHERS = {
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": "3DES is deprecated",
    "TLS_RSA_WITH_RC4_128_SHA": "RC4 is broken",
    "TLS_RSA_WITH_RC4_128_MD5": "RC4-MD5 is broken",
    "TLS_RSA_WITH_AES_128_CBC_SHA": "CBC mode without AEAD",
    "TLS_RSA_WITH_AES_256_CBC_SHA": "CBC mode without AEAD",
}

PROTOCOLS = {
    "SSLv2": ssl.OP_NO_SSLv2,
    "SSLv3": ssl.OP_NO_SSLv3,
    "TLSv1.0": ssl.OP_NO_TLSv1,
    "TLSv1.1": ssl.OP_NO_TLSv1_1,
    "TLSv1.2": 0,
    "TLSv1.3": 0,
}


def check_protocol_support(host: str, port: int = 443) -> list[str]:
    supported = []
    protocol_flags = {
        "SSLv2": ssl.OP_NO_SSLv2,
        "SSLv3": ssl.OP_NO_SSLv3,
        "TLSv1.0": ssl.OP_NO_TLSv1,
        "TLSv1.1": ssl.OP_NO_TLSv1_1,
    }
    for name, flag in protocol_flags.items():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.options |= flag
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    supported.append(name)
        except Exception:
            pass

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                supported.append("TLSv1.2")
    except Exception:
        pass

    if not supported:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    supported.append("TLSv1.3")
        except Exception:
            pass

    return supported


def check_cipher_suites(host: str, port: int = 443) -> list[dict]:
    results = []
    supported_ciphers = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    supported_ciphers.append(cipher[0])
    except Exception:
        pass

    for cipher_name, reason in WEAK_CIPHERS.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher_name)
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results.append({
                        "asset_type": "vulnerability",
                        "value": f"{host}:{port}",
                        "details": f"Weak cipher supported: {cipher_name} - {reason}",
                        "severity": "high",
                    })
        except Exception:
            pass

    return results


async def analyze_ssl(host: str, port: int = 443) -> list[dict]:
    results = []

    cert_result = await check_certificate_extended(host, port)
    if cert_result:
        results.append(cert_result)

    protocols = check_protocol_support(host, port)
    if protocols:
        results.append({
            "asset_type": "technology",
            "value": f"{host}:{port}",
            "details": f"supported SSL/TLS protocols: {', '.join(protocols)}",
        })
        weak_protos = [p for p in protocols if p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")]
        if weak_protos:
            results.append({
                "asset_type": "vulnerability",
                "value": f"{host}:{port}",
                "details": f"Deprecated protocols enabled: {', '.join(weak_protos)}",
                "severity": "medium",
            })
    else:
        results.append({
            "asset_type": "vulnerability",
            "value": f"{host}:{port}",
            "details": "Could not establish SSL/TLS connection",
            "severity": "high",
        })

    cipher_issues = check_cipher_suites(host, port)
    results.extend(cipher_issues)

    return results


async def check_certificate_extended(host: str, port: int = 443) -> dict | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                days_remaining = (not_after - datetime.utcnow()).days
                issuer = dict(x[0] for x in cert["issuer"])
                subject = dict(x[0] for x in cert["subject"])
                sans = cert.get("subjectAltName", [])
                san_list = [san[1] for san in sans] if sans else []

                details = (
                    f"issuer={issuer.get('organizationName', 'Unknown')}, "
                    f"subject={subject.get('commonName', host)}, "
                    f"valid_from={not_before.isoformat()}, "
                    f"valid_until={not_after.isoformat()}, "
                    f"days_remaining={days_remaining}, "
                    f"serial={cert.get('serialNumber', 'N/A')}, "
                    f"sans={','.join(san_list[:10])}"
                )

                result = {
                    "asset_type": "certificate",
                    "value": host,
                    "details": details,
                }

                if days_remaining < 0:
                    result["severity"] = "critical"
                elif days_remaining < 14:
                    result["severity"] = "high"
                elif days_remaining < 30:
                    result["severity"] = "medium"
                return result
    except Exception as e:
        return {
            "asset_type": "certificate",
            "value": host,
            "details": f"error: {str(e)}",
        }
