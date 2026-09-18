import asyncio
from core.config import COMMON_PORTS, PORT_TIMEOUT

PORT_META = {
    21:   {"name": "FTP",        "risk": "warn"},
    22:   {"name": "SSH",        "risk": "ok"},
    23:   {"name": "Telnet",     "risk": "bad"},
    25:   {"name": "SMTP",       "risk": "warn"},
    53:   {"name": "DNS",        "risk": "warn"},
    80:   {"name": "HTTP",       "risk": "warn"},
    110:  {"name": "POP3",       "risk": "warn"},
    143:  {"name": "IMAP",       "risk": "warn"},
    443:  {"name": "HTTPS",      "risk": "ok"},
    445:  {"name": "SMB",        "risk": "bad"},
    3306: {"name": "MySQL",      "risk": "bad"},
    3389: {"name": "RDP",        "risk": "bad"},
    5432: {"name": "PostgreSQL", "risk": "bad"},
    8080: {"name": "HTTP-alt",   "risk": "warn"},
    8443: {"name": "HTTPS-alt",  "risk": "warn"},
}


async def scan_ports(host: str) -> list[dict]:
    async def check(port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=PORT_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {
                "port": port,
                "state": "open",
                "service": PORT_META.get(port, {}).get("name", "?"),
                "risk": PORT_META.get(port, {}).get("risk", "warn"),
            }
        except Exception:
            return {
                "port": port,
                "state": "closed",
                "service": PORT_META.get(port, {}).get("name", "?"),
                "risk": PORT_META.get(port, {}).get("risk", "warn"),
            }

    results = await asyncio.gather(*[check(p) for p in COMMON_PORTS])
    return sorted(results, key=lambda x: x["port"])