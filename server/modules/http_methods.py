import asyncio
import httpx
from core.config import HTTP_TIMEOUT, HTTP_METHODS
from modules.proxy_manager import make_httpx_client


async def check_http_methods(url: str, use_proxy: bool = False) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    async with make_httpx_client(
        enabled=use_proxy,
        timeout=HTTP_TIMEOUT,
        verify=False,
        follow_redirects=True,
    ) as c:
        options_task = asyncio.create_task(_get_options(c, url))
        method_tasks = [
            asyncio.create_task(_check_method(c, url, m))
            for m in HTTP_METHODS
        ]
        allowed_by_options = await options_task
        checks = await asyncio.gather(*method_tasks)

    dangerous = [c for c in checks if c.get("dangerous")]
    return {
        "options_advertised": allowed_by_options,
        "checks": checks,
        "dangerous": dangerous,
    }


async def _get_options(client, url):
    try:
        r = await client.options(url)
        header = (
            r.headers.get("Allow")
            or r.headers.get("Access-Control-Allow-Methods", "")
        )
        return [m.strip().upper() for m in header.split(",") if m.strip()]
    except Exception:
        return []


async def _check_method(client, url, method):
    try:
        r = await client.request(method, url)
        active = r.status_code < 400
        if method == "TRACE" and r.status_code >= 400:
            active = False
        return {
            "method": method,
            "status": r.status_code,
            "allowed": active,
            "dangerous": _is_dangerous(method, active),
        }
    except Exception as e:
        return {
            "method": method,
            "error": str(e),
            "allowed": False,
            "dangerous": False,
        }


def _is_dangerous(method: str, active: bool) -> bool:
    if not active:
        return False
    return method in ("TRACE", "PUT", "DELETE", "CONNECT", "PATCH")