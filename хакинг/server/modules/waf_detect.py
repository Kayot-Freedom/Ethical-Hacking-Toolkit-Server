import httpx
from core.config import HTTP_TIMEOUT
from modules.proxy_manager import make_httpx_client


WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "Akamai":      ["akamai", "ak-bmsc", "akamai-grn"],
    "Sucuri":      ["sucuri", "x-sucuri-id"],
    "AWS WAF":     ["awselb", "x-amz-cf-id", "x-amzn-requestid"],
    "Fastly":      ["fastly", "x-served-by", "x-fastly"],
    "Imperva":     ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP":   ["bigipserver", "ts01", "x-wa-info"],
    "Barracuda":   ["barra_counter_session"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Wordfence":   ["wordfence"],
    "DDoS-Guard":  ["ddos-guard"],
    "Qrator":      ["qrator"],
    "StackPath":   ["stackpath"],
}


async def detect_waf(url: str, use_proxy: bool = False) -> dict:
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
        return {"error": str(e), "detected": []}

    haystack = " ".join(f"{k}:{v}" for k, v in r.headers.items()).lower()
    for ck in r.cookies:
        haystack += " " + ck.lower()

    detected = []
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in haystack:
                detected.append({"name": waf, "matched": sig})
                break

    return {
        "detected": detected,
        "has_waf": len(detected) > 0,
    }