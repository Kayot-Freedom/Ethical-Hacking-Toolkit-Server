import asyncio
import httpx
import dns.resolver
from core.config import HTTP_TIMEOUT, TAKEOVER_SIGNATURES
from modules.proxy_manager import make_httpx_client


MAX_CONCURRENCY = 20
MAX_SUBDOMAINS = 150
PER_SUB_TIMEOUT = 8.0


CNAME_SIGNATURES = {
    "herokuapp.com":         "heroku",
    "herokudns.com":         "heroku",
    "github.io":             "github",
    "s3.amazonaws.com":      "s3",
    "s3-website":            "s3",
    "cloudfront.net":        "cloudfront",
    "azurewebsites.net":     "azure",
    "cloudapp.azure.com":    "azure",
    "trafficmanager.net":    "azure",
    "blob.core.windows.net": "azure",
    "shopify.com":           "shopify",
    "myshopify.com":         "shopify",
    "surge.sh":              "surge",
    "bitbucket.io":          "bitbucket",
    "pantheonsite.io":       "pantheon",
    "ghost.io":              "ghost",
    "readme.io":             "readme",
    "zendesk.com":           "zendesk",
    "statuspage.io":         "statuspage",
    "fastly.net":            "fastly",
    "netlify.app":           "netlify",
    "netlify.com":           "netlify",
    "vercel.app":            "vercel",
    "vercel-dns.com":        "vercel",
    "fly.dev":               "fly",
    "fly.io":                "fly",
    "render.com":            "render",
    "onrender.com":          "render",
    "wordpress.com":         "wordpress",
    "wpengine.com":          "wpengine",
    "unbouncepages.com":     "unbounce",
    "webflow.io":            "webflow",
    "firebaseapp.com":       "firebase",
    "cloudfunctions.net":    "gcp",
    "appspot.com":           "gcp",
    "storage.googleapis.com":"gcp",
    "elasticbeanstalk.com":  "aws",
    "disqus.com":            "disqus",
}


async def subdomain_takeover(
    subdomains: list[str],
    use_proxy: bool = False,
) -> dict:
    if not subdomains:
        return {"checked": 0, "vulnerable": [], "clean": 0, "errors": 0}

    subdomains = [s.strip().lower() for s in subdomains if s and "*" not in s][:MAX_SUBDOMAINS]
    subdomains = list(dict.fromkeys(subdomains))

    if not subdomains:
        return {"checked": 0, "vulnerable": [], "clean": 0, "errors": 0}

    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    cname_cache: dict[str, str | None] = {}

    async with make_httpx_client(
        enabled=use_proxy,
        timeout=HTTP_TIMEOUT,
        verify=False,
        follow_redirects=True,
    ) as client:

        async def check(sub: str) -> dict:
            async with sem:
                try:
                    return await asyncio.wait_for(
                        _check_one(client, sub, cname_cache),
                        timeout=PER_SUB_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    return {"subdomain": sub, "vulnerable": False, "error": "timeout"}
                except Exception as e:
                    return {"subdomain": sub, "vulnerable": False, "error": str(e)}

        tasks = [check(s) for s in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    clean = 0
    vulnerable = []
    errors = 0

    for r in results:
        if isinstance(r, Exception):
            errors += 1
            continue
        if r.get("error") and not r.get("vulnerable"):
            errors += 1
            continue
        if r.get("vulnerable"):
            vulnerable.append(r)
        else:
            clean += 1

    return {
        "checked": len(subdomains),
        "vulnerable": vulnerable,
        "clean": clean,
        "errors": errors,
    }


async def _check_one(client: httpx.AsyncClient, sub: str, cache: dict) -> dict:
    cname_task = asyncio.create_task(_get_cname_cached(sub, cache))
    https_task = asyncio.create_task(_try_http(client, f"https://{sub}"))
    http_task = asyncio.create_task(_try_http(client, f"http://{sub}"))

    cname = await cname_task
    https_result = await https_task
    http_result = await http_task

    for http_res in (https_result, http_result):
        if not http_res:
            continue
        matched = _match_body_signature(http_res["body"])
        if matched:
            return {
                "subdomain": sub,
                "cname": cname,
                "service": matched,
                "vulnerable": True,
                "status": http_res["status"],
                "reason": "Сигнатура в теле ответа",
            }

    if cname:
        service = _match_cname_signature(cname)
        if service:
            for http_res in (https_result, http_result):
                if not http_res:
                    continue
                if http_res["status"] in (404, 410, 502, 503):
                    return {
                        "subdomain": sub,
                        "cname": cname,
                        "service": service,
                        "vulnerable": True,
                        "status": http_res["status"],
                        "reason": f"CNAME на {service} + HTTP {http_res['status']}",
                    }

    if cname and not (https_result or http_result):
        service = _match_cname_signature(cname)
        if service:
            return {
                "subdomain": sub,
                "cname": cname,
                "service": service,
                "vulnerable": True,
                "status": None,
                "reason": f"CNAME на {service}, соединение не устанавливается",
            }

    return {"subdomain": sub, "cname": cname, "vulnerable": False}


async def _try_http(client: httpx.AsyncClient, url: str) -> dict | None:
    try:
        r = await client.get(url)
        body = r.text[:10000]
        return {"status": r.status_code, "body": body}
    except Exception:
        return None


async def _get_cname_cached(host: str, cache: dict) -> str | None:
    if host in cache:
        return cache[host]

    def _resolve():
        try:
            answers = dns.resolver.resolve(host, "CNAME", lifetime=3)
            return str(answers[0]).rstrip(".").lower()
        except Exception:
            return None

    cname = await asyncio.to_thread(_resolve)
    cache[host] = cname
    return cname


def _match_body_signature(body: str) -> str | None:
    if not body:
        return None
    body_lower = body.lower()
    for service, sigs in TAKEOVER_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in body_lower:
                return service
    return None


def _match_cname_signature(cname: str) -> str | None:
    cname_lower = cname.lower()
    for signature, service in CNAME_SIGNATURES.items():
        if signature in cname_lower:
            return service
    return None