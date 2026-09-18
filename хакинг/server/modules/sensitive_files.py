import asyncio
import httpx
from core.config import HTTP_TIMEOUT, SENSITIVE_PATHS
from modules.proxy_manager import make_httpx_client


async def check_sensitive_files(url: str, use_proxy: bool = False) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    async with make_httpx_client(
        enabled=use_proxy,
        timeout=HTTP_TIMEOUT,
        verify=False,
        follow_redirects=False,
    ) as c:
        async def check(path: str):
            full = url + path
            try:
                r = await c.get(full)
                return {
                    "path": path,
                    "status": r.status_code,
                    "size": len(r.content),
                    "content_type": r.headers.get("content-type", ""),
                    "found": r.status_code == 200,
                    "redirect": r.status_code in (301, 302, 307, 308),
                }
            except Exception as e:
                return {"path": path, "error": str(e), "found": False}

        results = await asyncio.gather(*[check(p) for p in SENSITIVE_PATHS])

    found = [r for r in results if r.get("found")]
    return {
        "checked": len(SENSITIVE_PATHS),
        "found": found,
        "all": results,
    }