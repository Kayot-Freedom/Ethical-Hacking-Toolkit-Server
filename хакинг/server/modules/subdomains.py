import httpx
from core.config import HTTP_TIMEOUT


async def enumerate_subdomains(host: str) -> dict:
    """
    Поиск поддоменов через Certificate Transparency (crt.sh).
    Бесплатно, без API-ключей.
    """
    url = f"https://crt.sh/?q=%25.{host}&output=json"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT * 2) as c:
            r = await c.get(url)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        return {"error": str(e), "subdomains": []}

    subs = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name and name.endswith(host):
                subs.add(name)

    return {
        "count": len(subs),
        "subdomains": sorted(subs),
    }