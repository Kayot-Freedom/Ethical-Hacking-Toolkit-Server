import httpx
from core.config import HTTP_TIMEOUT


async def wayback_urls(host: str, limit: int = 200) -> dict:
    """
    Старые URL из Wayback Machine через CDX API.
    Показывает «забытые» страницы, которые уже не на сайте.
    """
    cdx_url = (
        f"http://web.archive.org/cdx/search/cdx?"
        f"url={host}/*&output=json&fl=timestamp,original,statuscode,mimetype"
        f"&collapse=urlkey&limit={limit}"
    )
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT * 3) as c:
            r = await c.get(cdx_url)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        return {"error": str(e), "urls": []}

    if not data or len(data) < 2:
        return {"total": 0, "urls": [], "interesting": []}

    headers_row = data[0]
    rows = data[1:]
    urls = []
    for row in rows:
        try:
            urls.append({
                "timestamp": row[0],
                "url": row[1],
                "status": row[2],
                "mimetype": row[3],
            })
        except IndexError:
            continue

    # Ищем интересные URL (админки, api, бэкапы)
    keywords = ["admin", "api", "backup", "test", "dev", "staging", "old",
                "private", "internal", "config", "db", "sql", "archive"]
    interesting = [
        u for u in urls
        if any(k in u["url"].lower() for k in keywords)
    ][:30]

    return {
        "total": len(urls),
        "urls": urls[:50],
        "interesting": interesting,
    }