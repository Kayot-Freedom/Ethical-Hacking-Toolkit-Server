import socket
import ssl
import asyncio
import dns.resolver
import httpx
from datetime import datetime
from urllib.parse import urlparse

# ⚠️ Только безопасные, "белые" проверки.
# Никакого брутфорса, эксплойтов, SQLi и т.п.

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


async def scan_ports(host: str, ports: list[int] | None = None, timeout: float = 0.8) -> list[dict]:
    """Асинхронное TCP-сканирование (без баннеров, только открыт/закрыт)."""
    ports = ports or COMMON_PORTS
    results = []

    async def check(port: int):
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "state": "open"}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {"port": port, "state": "closed"}

    tasks = [check(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda x: x["port"])


async def check_http_headers(url: str) -> dict:
    """Проверка HTTP-заголовков безопасности."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
        r = await client.get(url)
    present = {h: r.headers.get(h) for h in SECURITY_HEADERS if h in r.headers}
    missing = [h for h in SECURITY_HEADERS if h not in r.headers]
    return {
        "status_code": r.status_code,
        "server": r.headers.get("Server", "unknown"),
        "powered_by": r.headers.get("X-Powered-By", "unknown"),
        "present_headers": present,
        "missing_headers": missing,
    }


def check_ssl(host: str, port: int = 443) -> dict:
    """Информация о SSL-сертификате."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        return {
            "valid": True,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "version": cert.get("version"),
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def dns_lookup(host: str) -> dict:
    """DNS-разведка: A, MX, TXT, NS."""
    result = {}
    for rtype in ("A", "MX", "TXT", "NS"):
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5)
            result[rtype] = [str(a) for a in answers]
        except Exception:
            result[rtype] = []
    return result


def whois_lookup(host: str) -> dict:
    """WHOIS по домену (упрощённо)."""
    try:
        import whois
        w = whois.whois(host)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
        }
    except Exception as e:
        return {"error": str(e)}


def normalize_target(target: str) -> tuple[str, str]:
    """Возвращает (host, url)."""
    if "://" in target:
        p = urlparse(target)
        host = p.hostname or ""
        url = target
    else:
        host = target.split("/")[0]
        url = "https://" + target
    return host, url