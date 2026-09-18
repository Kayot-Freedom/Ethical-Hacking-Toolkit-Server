import asyncio
import socket
import ssl


async def check_ssl(host: str, port: int = 443) -> dict:
    return await asyncio.to_thread(_sync_ssl, host, port)


def _sync_ssl(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
        return {
            "valid": True,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "version": cert.get("version"),
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}