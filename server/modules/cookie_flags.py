import httpx
from core.config import HTTP_TIMEOUT
from modules.proxy_manager import make_httpx_client


async def check_cookie_flags(url: str, use_proxy: bool = False) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        async with make_httpx_client(
            enabled=use_proxy,
            timeout=HTTP_TIMEOUT,
            verify=False,
            follow_redirects=True,
        ) as c:
            r = await c.get(url)
    except Exception as e:
        return {"error": str(e), "cookies": []}

    cookies = []
    for ck in r.cookies.jar:
        set_cookie_raw = None
        for h, v in r.headers.multi_items():
            if h.lower() == "set-cookie" and ck.name in v:
                set_cookie_raw = v
                break

        flags = {
            "secure": ck.secure,
            "httponly": _has_flag(set_cookie_raw, "httponly"),
            "samesite": _extract_samesite(set_cookie_raw),
        }

        issues = []
        if not flags["secure"]:
            issues.append("Нет флага Secure — cookie уйдёт по HTTP")
        if not flags["httponly"]:
            issues.append("Нет HttpOnly — доступна из JavaScript (XSS)")
        if not flags["samesite"]:
            issues.append("Нет SameSite — уязвима для CSRF")
        elif flags["samesite"].lower() == "none" and not flags["secure"]:
            issues.append("SameSite=None без Secure — браузеры отклонят cookie")

        cookies.append({
            "name": ck.name,
            "domain": ck.domain,
            "path": ck.path,
            "flags": flags,
            "issues": issues,
            "safe": len(issues) == 0,
        })

    unsafe = [c for c in cookies if not c["safe"]]
    return {
        "total": len(cookies),
        "unsafe": len(unsafe),
        "cookies": cookies,
    }


def _has_flag(raw: str | None, flag: str) -> bool:
    if not raw:
        return False
    return flag in raw.lower()


def _extract_samesite(raw: str | None) -> str | None:
    if not raw:
        return None
    for part in raw.split(";"):
        part = part.strip()
        if part.lower().startswith("samesite="):
            return part.split("=", 1)[1].strip()
    return None