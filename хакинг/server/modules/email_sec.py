import asyncio
import dns.resolver


def _txt_sync(host: str) -> list[str]:
    try:
        records = dns.resolver.resolve(host, "TXT", lifetime=5)
        result = []
        for r in records:
            if hasattr(r, "strings"):
                result.append(b"".join(r.strings).decode("utf-8", "ignore"))
            else:
                result.append(str(r).strip('"'))
        return result
    except Exception:
        return []


def _dkim_exists(selector: str, host: str) -> bool:
    try:
        dns.resolver.resolve(f"{selector}._domainkey.{host}", "TXT", lifetime=3)
        return True
    except Exception:
        return False


async def check_email_security(host: str) -> dict:
    """Параллельная проверка SPF, DMARC, DKIM."""
    selectors = ("default", "google", "mail", "dkim", "k1", "s1", "s2", "selector1", "selector2")

    # Запускаем все DNS-запросы параллельно
    tasks = [
        asyncio.to_thread(_txt_sync, host),                 # SPF
        asyncio.to_thread(_txt_sync, f"_dmarc.{host}"),     # DMARC
    ] + [asyncio.to_thread(_dkim_exists, sel, host) for sel in selectors]

    results = await asyncio.gather(*tasks)

    txt_host = results[0]
    txt_dmarc = results[1]
    dkim_found = [sel for sel, exists in zip(selectors, results[2:]) if exists]

    spf = next((t for t in txt_host if t.startswith("v=spf1")), None)
    dmarc = next((t for t in txt_dmarc if t.startswith("v=DMARC1")), None)

    score = 0
    if spf:  score += 33
    if dmarc and "p=none" not in dmarc: score += 34
    if dmarc and "p=none" in dmarc:     score += 15
    if dkim_found: score += 33

    return {
        "spf": spf,
        "dmarc": dmarc,
        "dmarc_policy": _extract_policy(dmarc),
        "dkim_selectors": dkim_found,
        "score": score,
        "spoofable": score < 70,
    }


def _extract_policy(dmarc: str | None) -> str:
    if not dmarc:
        return "нет"
    for p in ("p=reject", "p=quarantine", "p=none"):
        if p in dmarc:
            return p.replace("p=", "")
    return "?"