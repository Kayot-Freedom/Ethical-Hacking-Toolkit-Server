import httpx
from core.config import SECURITY_HEADERS, HTTP_TIMEOUT
from modules.proxy_manager import make_httpx_client


async def check_http_headers(url: str, use_proxy: bool = False) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    async with make_httpx_client(
        enabled=use_proxy,
        timeout=HTTP_TIMEOUT,
        follow_redirects=True,
        verify=False,
    ) as c:
        r = await c.get(url)

    present = {h: r.headers.get(h) for h in SECURITY_HEADERS if h in r.headers}
    missing = [h for h in SECURITY_HEADERS if h not in r.headers]

    return {
        "status_code": r.status_code,
        "server": r.headers.get("Server", "unknown"),
        "powered_by": r.headers.get("X-Powered-By", "unknown"),
        "present_headers": present,
        "missing_headers": missing,
    }