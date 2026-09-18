import httpx
import socket
from core.config import HTTP_TIMEOUT


async def ip_geo(host: str) -> dict:
    """Геолокация и ASN по IP-адресу цели."""
    # Получаем IP
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"error": f"DNS-ошибка: {e}"}

    # ip-api.com — бесплатный, без ключа, 45 запросов/минуту
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            r = await c.get(url)
            data = r.json()
    except Exception as e:
        return {"error": str(e), "ip": ip}

    if data.get("status") != "success":
        return {"error": data.get("message", "unknown"), "ip": ip}

    return {
        "ip": ip,
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "zip": data.get("zip"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "asn_name": data.get("asname"),
        "reverse_dns": data.get("reverse"),
        "is_proxy": data.get("proxy"),
        "is_hosting": data.get("hosting"),
        "is_mobile": data.get("mobile"),
    }