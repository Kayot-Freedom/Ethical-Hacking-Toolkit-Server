import asyncio
import httpx
from core.config import HTTP_TIMEOUT
from modules.proxy_manager import make_httpx_client


EVIL_ORIGINS = [
    "https://evil.com",
    "null",
]

CORS_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Vary",
]


async def check_cors(url: str, use_proxy: bool = False) -> dict:
    """
    Проверка CORS-конфигурации.
    Все запросы — параллельно через asyncio.gather.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    host = url.split("//", 1)[1].split("/")[0]

    origins_to_test = list(EVIL_ORIGINS)
    origins_to_test.append(f"https://{host}.evil.com")
    if url.startswith("https://"):
        origins_to_test.append(f"http://{host}")

    async with make_httpx_client(
        enabled=use_proxy,
        timeout=HTTP_TIMEOUT,
        verify=False,
        follow_redirects=False,
    ) as client:
        get_tasks = [
            asyncio.create_task(_test_origin(client, url, "GET", origin))
            for origin in origins_to_test
        ]
        options_tasks = [
            asyncio.create_task(_test_origin(client, url, "OPTIONS", origin))
            for origin in origins_to_test
        ]

        get_results = await asyncio.gather(*get_tasks, return_exceptions=True)
        options_results = await asyncio.gather(*options_tasks, return_exceptions=True)

    checks = []
    for r in get_results + options_results:
        if isinstance(r, Exception):
            checks.append({"error": str(r)})
        else:
            checks.append(r)

    vulnerable = [c for c in checks if c.get("verdict") == "vulnerable"]
    null_allowed = [c for c in checks if c.get("verdict") == "null_allowed"]
    reflect_no_creds = [c for c in checks if c.get("verdict") == "reflect_no_creds"]
    wildcard = [c for c in checks if c.get("verdict") == "wildcard"]

    is_vulnerable = bool(vulnerable)
    is_suspicious = is_vulnerable or bool(null_allowed)

    return {
        "vulnerable": is_vulnerable,
        "suspicious": is_suspicious,
        "summary": _build_summary(vulnerable, null_allowed, reflect_no_creds, wildcard),
        "checks": checks,
        "stats": {
            "vulnerable": len(vulnerable),
            "null_allowed": len(null_allowed),
            "reflect_no_creds": len(reflect_no_creds),
            "wildcard": len(wildcard),
            "total": len(checks),
        },
    }


async def _test_origin(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    origin: str,
) -> dict:
    headers = {
        "Origin": origin,
        "User-Agent": "EthicalHackingToolkit/3.3 (+authorized-scan)",
    }
    if method == "OPTIONS":
        headers["Access-Control-Request-Method"] = "GET"
        headers["Access-Control-Request-Headers"] = "authorization,content-type"

    try:
        r = await client.request(method, url, headers=headers)
    except Exception as e:
        return {
            "method": method,
            "origin_sent": origin,
            "error": str(e),
            "verdict": "error",
        }

    cors = {h: r.headers.get(h) for h in CORS_HEADERS if h in r.headers}
    acao = cors.get("Access-Control-Allow-Origin", "")
    acac = (cors.get("Access-Control-Allow-Credentials", "") or "").lower()

    verdict = _classify(origin, acao, acac, r.status_code)

    return {
        "method": method,
        "origin_sent": origin,
        "status": r.status_code,
        "acao": acao or None,
        "acac": acac or None,
        "cors_headers": cors,
        "verdict": verdict,
        "reflects_origin": acao == origin,
        "wildcard": acao == "*",
        "null_allowed": acao == "null",
        "with_credentials": acac == "true",
    }


def _classify(origin: str, acao: str, acac: str, status: int) -> str:
    if not acao:
        return "ok"
    reflects = acao == origin
    wildcard = acao == "*"
    null_val = acao == "null"
    creds = acac == "true"

    if reflects and creds:
        return "vulnerable"
    if null_val and creds:
        return "vulnerable"
    if null_val:
        return "null_allowed"
    if reflects:
        return "reflect_no_creds"
    if wildcard:
        return "wildcard"
    return "ok"


def _build_summary(vulnerable, null_allowed, reflect_no_creds, wildcard) -> str:
    if vulnerable:
        origins = ", ".join(sorted({c["origin_sent"] for c in vulnerable}))
        return (
            f"🔴 КРИТИЧНО: CORS отражает произвольный Origin с "
            f"Access-Control-Allow-Credentials: true. "
            f"Проверенные Origin'ы: {origins}."
        )
    if null_allowed:
        return (
            "🟠 Подозрительно: сервер разрешает Origin: null. "
            "Обходится через <iframe sandbox>."
        )
    if reflect_no_creds:
        origins = ", ".join(sorted({c["origin_sent"] for c in reflect_no_creds}))
        return f"🟡 Отражает Origin ({origins}), но без credentials. Риск средний."
    if wildcard:
        return "🟡 Access-Control-Allow-Origin: *. Обычно безопасно без credentials."
    return "✅ CORS настроен корректно."