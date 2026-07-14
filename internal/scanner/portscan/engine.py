import socket
import concurrent.futures
from datetime import datetime


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                return {
                    "asset_type": "port",
                    "value": f"{host}:{port}",
                    "details": f"port {port} ({COMMON_PORTS.get(port, 'unknown')}) is open",
                }
    except (socket.timeout, socket.error, OSError):
        pass
    return None


async def scan_ports(host: str, ports: list[int] | None = None) -> list[dict]:
    ports_to_scan = ports or list(COMMON_PORTS.keys())
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port, host, port): port
            for port in ports_to_scan
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return results
