import ssl
import socket
from datetime import datetime


async def check_certificate(host: str, port: int = 443) -> dict | None:
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
                return {
                    "asset_type": "certificate",
                    "value": host,
                    "details": (
                        f"issuer={issuer.get('organizationName', 'Unknown')}, "
                        f"subject={subject.get('commonName', host)}, "
                        f"valid_from={not_before.isoformat()}, "
                        f"valid_until={not_after.isoformat()}, "
                        f"days_remaining={days_remaining}, "
                        f"serial={cert.get('serialNumber', 'N/A')}"
                    ),
                }
    except (ssl.SSLError, socket.timeout, socket.error, OSError, ValueError) as e:
        return {
            "asset_type": "certificate",
            "value": host,
            "details": f"error: {str(e)}",
        }
    return None
