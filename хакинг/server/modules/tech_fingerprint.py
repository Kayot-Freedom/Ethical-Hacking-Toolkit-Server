import httpx
from bs4 import BeautifulSoup
from core.config import HTTP_TIMEOUT
from modules.proxy_manager import make_httpx_client


TECH_SIGS = {
    "WordPress":     {"html": ["wp-content", "wp-includes"], "cookies": ["wordpress_"]},
    "Joomla":        {"html": ["/components/com_", "joomla"], "cookies": ["joomla_"]},
    "Drupal":        {"html": ["drupal-settings-json", "sites/default/files"], "headers": ["x-generator:drupal"]},
    "Bitrix":        {"html": ["bitrix/", "bx-"], "cookies": ["bitrix_"]},
    "MODX":          {"html": ["/assets/components/", "modx"], "headers": ["x-powered-by:modx"]},
    "OpenCart":      {"html": ["index.php?route=", "catalog/view"]},
    "Magento":       {"html": ["mage/", "Magento"], "cookies": ["frontend="]},
    "Shopify":       {"html": ["cdn.shopify.com"], "headers": ["x-shopify-stage"]},
    "Tilda":         {"html": ["tilda-", "static.tildacdn.com"]},
    "Wix":           {"html": ["static.wixstatic.com", "wix.com"], "headers": ["x-wix-"]},
    "Squarespace":   {"html": ["static1.squarespace.com"], "headers": ["x-squarespace-"]},
    "React":         {"html": ["data-reactroot", "_reactListening", "react-dom"]},
    "Next.js":       {"html": ["__NEXT_DATA__", "/_next/"], "headers": ["x-powered-by:next.js"]},
    "Vue.js":        {"html": ["data-v-", "vue.js", "__vue__"]},
    "Angular":       {"html": ["ng-version=", "ng-app="]},
    "Svelte":        {"html": ["__svelte"]},
    "Nginx":         {"headers": ["server:nginx"]},
    "Apache":        {"headers": ["server:apache"]},
    "IIS":           {"headers": ["server:microsoft-iis"]},
    "Caddy":         {"headers": ["server:caddy"]},
    "LiteSpeed":     {"headers": ["server:litespeed"]},
    "PHP":           {"headers": ["x-powered-by:php"]},
    "ASP.NET":       {"headers": ["x-powered-by:asp.net", "x-aspnet-version"]},
    "Express":       {"headers": ["x-powered-by:express"]},
    "Django":        {"cookies": ["csrftoken"], "html": ["csrfmiddlewaretoken"]},
    "Rails":         {"cookies": ["_rails", "_session_id"], "headers": ["x-powered-by:phusion"]},
    "Laravel":       {"cookies": ["laravel_session", "xsrf-token"]},
    "Google Analytics": {"html": ["gtag(", "googletagmanager.com", "google-analytics.com", "ga('create"]},
    "Yandex Metrica":   {"html": ["mc.yandex.ru", "ym("]},
    "Facebook Pixel":   {"html": ["connect.facebook.net", "fbq("]},
    "Hotjar":        {"html": ["static.hotjar.com"]},
    "jQuery":        {"html": ["jquery.min.js", "jquery-"]},
    "Bootstrap":     {"html": ["bootstrap.min.css", "bootstrap.bundle"]},
}


async def fingerprint_tech(url: str, use_proxy: bool = False) -> dict:
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
        return {"error": str(e), "technologies": []}

    headers_blob = " ".join(f"{k}:{v}" for k, v in r.headers.items()).lower()
    cookies_blob = " ".join(ck for ck in r.cookies).lower()
    html_blob = r.text.lower()

    generator = None
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        meta = soup.find("meta", attrs={"name": "generator"})
        if meta:
            generator = meta.get("content")
    except Exception:
        pass

    found = []
    for tech, sigs in TECH_SIGS.items():
        matched = None
        for h in sigs.get("headers", []):
            if h in headers_blob:
                matched = f"header: {h}"; break
        if not matched:
            for ck in sigs.get("cookies", []):
                if ck in cookies_blob:
                    matched = f"cookie: {ck}"; break
        if not matched:
            for h in sigs.get("html", []):
                if h.lower() in html_blob:
                    matched = f"html: {h}"; break
        if matched:
            found.append({"name": tech, "matched": matched})

    return {
        "generator": generator,
        "technologies": found,
        "server": r.headers.get("Server", "unknown"),
        "powered_by": r.headers.get("X-Powered-By", "unknown"),
    }