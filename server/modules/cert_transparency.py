import httpx
from core.config import HTTP_TIMEOUT


async def cert_transparency(host: str) -> dict:
    """Все сертификаты домена через Certificate Transparency (crt.sh)."""
    url = f"https://crt.sh/?q={host}&output=json"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT * 2) as c:
            r = await c.get(url)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        return {"error": str(e), "certificates": []}

    # Группируем по сертификату
    by_id = {}
    for entry in data:
        cid = entry.get("id")
        if cid in by_id:
            continue
        by_id[cid] = {
            "id": cid,
            "issuer": entry.get("issuer_name", ""),
            "common_name": entry.get("common_name", ""),
            "not_before": entry.get("not_before"),
            "not_after": entry.get("not_after"),
            "names": entry.get("name_value", "").split("\n"),
            "entry_timestamp": entry.get("entry_timestamp"),
        }

    # Статистика по issuer'ам
    issuers = {}
    for cert in by_id.values():
        iss = cert["issuer"]
        # Вытаскиваем CN или O из issuer
        for part in iss.split(","):
            part = part.strip()
            if part.startswith("O=") or part.startswith("CN="):
                issuers[part] = issuers.get(part, 0) + 1
                break

    # Сортируем сертификаты по дате
    certs = sorted(
        by_id.values(),
        key=lambda x: x.get("entry_timestamp") or "",
        reverse=True,
    )

    # Уникальные доменные имена
    all_names = set()
    for c in certs:
        for n in c["names"]:
            n = n.strip().lower()
            if n and "*" not in n:
                all_names.add(n)

    return {
        "total_certificates": len(certs),
        "unique_domains": len(all_names),
        "issuers": issuers,
        "certificates": certs[:50],  # первые 50 для UI
        "all_domains": sorted(all_names),
    }