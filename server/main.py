import asyncio
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from core.config import CLIENT_DIR, PROXIES
from core.security import validate_target, normalize_target, check_consent

# ── Модули ─────────────────────────────────────
from modules.ports import scan_ports
from modules.headers import check_http_headers
from modules.ssl import check_ssl
from modules.dns import dns_lookup
from modules.whois import whois_lookup
from modules.subdomains import enumerate_subdomains
from modules.email_sec import check_email_security
from modules.waf_detect import detect_waf
from modules.tech_fingerprint import fingerprint_tech
from modules.sensitive_files import check_sensitive_files

from modules.cors_check import check_cors
from modules.cookie_flags import check_cookie_flags
from modules.http_methods import check_http_methods
from modules.tls_deep import tls_deep_analysis
from modules.cert_transparency import cert_transparency
from modules.wayback import wayback_urls
from modules.ip_geo import ip_geo
from modules.subdomain_takeover import subdomain_takeover
from modules.directory_scan import scan_directories

# ── Proxy ──────────────────────────────────────
from modules.proxy_manager import get_proxy_manager

# ── Scoring & storage ──────────────────────────
from scoring.risk_score import compute_score
from storage.db import init_db, save_scan, get_scans, get_last_scan
from storage.diff import diff_scans

app = FastAPI(title="Ethical Hacking Toolkit API", version="3.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FULL_SCAN_TIMEOUT = 300


@app.on_event("startup")
async def startup():
    await init_db()


class TargetRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=253)
    consent: bool
    use_proxy: bool = False


def _prep(req: TargetRequest):
    check_consent(req.consent)
    validate_target(req.target)
    return normalize_target(req.target)


# ═══════════════════════════════════════════════
#  ПРОКСИ
# ═══════════════════════════════════════════════

@app.get("/api/proxies/status")
async def api_proxies_status(force: bool = False):
    """Проверка всех прокси из config.py."""
    manager = get_proxy_manager()
    if not manager.is_enabled():
        return {
            "enabled_globally": False,
            "total": 0,
            "alive": 0,
            "proxies": [],
            "message": "Прокси не настроены в core/config.py",
        }
    await manager.verify_all(force=force)
    return {
        "enabled_globally": True,
        "total": manager.total_count(),
        "alive": manager.alive_count(),
        "proxies": manager._snapshot(),
    }


async def _ensure_proxies_ready() -> None:
    """Проверяет прокси перед сканом. Бросает 400, если ни один не работает."""
    manager = get_proxy_manager()
    if not manager.is_enabled():
        raise HTTPException(
            400,
            "Прокси не настроены. Добавьте их в core/config.py → PROXIES",
        )
    if not manager.has_alive():
        await manager.verify_all()
    if not manager.has_alive():
        raise HTTPException(
            400,
            "Ни один прокси не работает. Отключите прокси или проверьте список.",
        )


# ═══════════════════════════════════════════════
#  Одиночные модули
# ═══════════════════════════════════════════════

@app.post("/api/scan/ports")
async def api_ports(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await scan_ports(host)}


@app.post("/api/scan/headers")
async def api_headers(req: TargetRequest):
    _, url = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    try:
        return {"target": url, "result": await check_http_headers(url, req.use_proxy)}
    except Exception as e:
        raise HTTPException(400, f"Ошибка запроса: {e}")


@app.post("/api/scan/ssl")
async def api_ssl(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await check_ssl(host)}


@app.post("/api/scan/dns")
async def api_dns(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await dns_lookup(host)}


@app.post("/api/scan/whois")
async def api_whois(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await asyncio.to_thread(whois_lookup, host)}


@app.post("/api/scan/subdomains")
async def api_subdomains(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await enumerate_subdomains(host)}


@app.post("/api/scan/email")
async def api_email(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await check_email_security(host)}


@app.post("/api/scan/waf")
async def api_waf(req: TargetRequest):
    _, url = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    return {"target": url, "result": await detect_waf(url, req.use_proxy)}


@app.post("/api/scan/tech")
async def api_tech(req: TargetRequest):
    _, url = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    return {"target": url, "result": await fingerprint_tech(url, req.use_proxy)}


@app.post("/api/scan/sensitive")
async def api_sensitive(req: TargetRequest):
    _, url = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    return {"target": url, "result": await check_sensitive_files(url, req.use_proxy)}


@app.post("/api/scan/cors")
async def api_cors(req: TargetRequest):
    _, url = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    return {"target": url, "result": await check_cors(url, req.use_proxy)}


@app.post("/api/scan/cookies")
async def api_cookies(req: TargetRequest):
    _, url = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    return {"target": url, "result": await check_cookie_flags(url, req.use_proxy)}


@app.post("/api/scan/methods")
async def api_methods(req: TargetRequest):
    _, url = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    return {"target": url, "result": await check_http_methods(url, req.use_proxy)}


@app.post("/api/scan/tls_deep")
async def api_tls_deep(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await tls_deep_analysis(host)}


@app.post("/api/scan/ct")
async def api_ct(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await cert_transparency(host)}


@app.post("/api/scan/wayback")
async def api_wayback(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await wayback_urls(host)}


@app.post("/api/scan/geo")
async def api_geo(req: TargetRequest):
    host, _ = _prep(req)
    return {"target": host, "result": await ip_geo(host)}


@app.post("/api/scan/takeover")
async def api_takeover(req: TargetRequest):
    host, _ = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    subs_data = await enumerate_subdomains(host)
    subs = subs_data.get("subdomains", []) if not subs_data.get("error") else []
    return {"target": host, "result": await subdomain_takeover(subs, req.use_proxy)}


@app.post("/api/scan/directories")
async def api_directories(req: TargetRequest):
    _, url = _prep(req)
    if req.use_proxy:
        await _ensure_proxies_ready()
    return {"target": url, "result": await scan_directories(url, use_proxy=req.use_proxy)}


# ═══════════════════════════════════════════════
#  Полный скан
# ═══════════════════════════════════════════════

async def _takeover_pipeline(host: str, use_proxy: bool = False):
    subs_data = await enumerate_subdomains(host)
    subs = subs_data.get("subdomains", []) if not subs_data.get("error") else []
    if not subs:
        return subs_data, {"vulnerable": [], "checked": 0, "clean": 0}
    takeover = await subdomain_takeover(subs, use_proxy)
    return subs_data, takeover


async def _full_scan_logic(host: str, url: str, use_proxy: bool = False) -> dict:
    results = await asyncio.gather(
        scan_ports(host),                          # 0
        check_http_headers(url, use_proxy),        # 1
        _takeover_pipeline(host, use_proxy),       # 2
        detect_waf(url, use_proxy),                # 3
        fingerprint_tech(url, use_proxy),          # 4
        check_sensitive_files(url, use_proxy),     # 5
        check_cors(url, use_proxy),                # 6
        check_cookie_flags(url, use_proxy),        # 7
        check_http_methods(url, use_proxy),        # 8
        tls_deep_analysis(host),                   # 9
        cert_transparency(host),                   # 10
        wayback_urls(host, limit=100),             # 11
        ip_geo(host),                              # 12
        check_ssl(host),                           # 13
        dns_lookup(host),                          # 14
        check_email_security(host),                # 15
        scan_directories(url, use_proxy=use_proxy),# 16
        return_exceptions=True,
    )

    def safe(i, default):
        r = results[i]
        return default if isinstance(r, Exception) else r

    ports = safe(0, [])
    headers = safe(1, {"error": "failed"})

    subs_takeover = safe(2, ({"subdomains": []}, {"vulnerable": [], "checked": 0, "clean": 0}))
    if isinstance(subs_takeover, tuple) and len(subs_takeover) == 2:
        subdomains, takeover = subs_takeover
    else:
        subdomains, takeover = {"subdomains": []}, {"vulnerable": [], "checked": 0, "clean": 0}

    waf = safe(3, {"detected": [], "error": "failed"})
    tech = safe(4, {"technologies": [], "error": "failed"})
    sensitive = safe(5, {"found": [], "error": "failed"})
    cors = safe(6, {"vulnerable": False})
    cookies = safe(7, {"cookies": []})
    methods = safe(8, {"dangerous": []})
    tls_deep = safe(9, {"error": "failed"})
    ct = safe(10, {"certificates": []})
    wayback = safe(11, {"urls": []})
    geo = safe(12, {"error": "failed"})
    ssl_info = safe(13, {"valid": False})
    dns_info = safe(14, {})
    email_info = safe(15, {"error": "failed"})
    directory_scan = safe(16, {"found": [], "critical": [], "by_category": {}})

    scan = {
        "target": host,
        "url": url,
        "ports": ports,
        "headers": headers,
        "ssl": ssl_info,
        "dns": dns_info,
        "email_sec": email_info,
        "subdomains": subdomains,
        "waf": waf,
        "tech": tech,
        "sensitive_files": sensitive,
        "cors": cors,
        "cookies": cookies,
        "http_methods": methods,
        "tls_deep": tls_deep,
        "cert_transparency": ct,
        "wayback": wayback,
        "ip_geo": geo,
        "subdomain_takeover": takeover,
        "directory_scan": directory_scan,
    }

    scan["risk_score"] = compute_score(scan)
    return scan


@app.post("/api/scan/full")
async def api_full(req: TargetRequest):
    host, url = _prep(req)

    # Проверяем прокси, если включены
    if req.use_proxy:
        await _ensure_proxies_ready()

    try:
        scan = await asyncio.wait_for(
            _full_scan_logic(host, url, use_proxy=req.use_proxy),
            timeout=FULL_SCAN_TIMEOUT,
        )
    except asyncio.TimeoutError:
        raise HTTPException(504, f"Скан превысил {FULL_SCAN_TIMEOUT} секунд")

    scan["proxy_used"] = req.use_proxy
    if req.use_proxy:
        manager = get_proxy_manager()
        scan["proxy_stats"] = {
            "alive": manager.alive_count(),
            "total": manager.total_count(),
        }

    scan_id = await save_scan(host, scan)
    prev = await get_last_scan(host, exclude_id=scan_id)
    scan["scan_id"] = scan_id

    diff = None
    if prev:
        diff = diff_scans(prev["data"], scan)
        diff["previous_scan_at"] = prev["created_at"]
    scan["diff"] = diff

    return scan


# ═══════════════════════════════════════════════
#  История
# ═══════════════════════════════════════════════

@app.get("/api/history/{target}")
async def api_history(target: str, limit: int = 10):
    validate_target(target)
    host, _ = normalize_target(target)
    scans = await get_scans(host, limit=limit)
    return {
        "target": host,
        "scans": [
            {
                "id": s["id"],
                "created_at": s["created_at"],
                "score": (s["data"].get("risk_score") or {}).get("score"),
                "rating": (s["data"].get("risk_score") or {}).get("rating"),
            }
            for s in scans
        ],
    }


@app.get("/api/history/{target}/diff/{scan_id}")
async def api_diff(target: str, scan_id: int):
    validate_target(target)
    host, _ = normalize_target(target)
    scans = await get_scans(host, limit=50)
    current = next((s for s in scans if s["id"] == scan_id), None)
    if not current:
        raise HTTPException(404, "Скан не найден")
    prev = next((s for s in scans if s["id"] < scan_id), None)
    if not prev:
        return {"changes": [], "message": "Предыдущих сканов нет"}
    return diff_scans(prev["data"], current["data"])


# ═══════════════════════════════════════════════
#  Главная страница
# ═══════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def root():
    f = CLIENT_DIR / "index.html"
    if f.exists():
        return f.read_text(encoding="utf-8")
    return "<h1>Ethical Hacking API v3.3</h1>"



