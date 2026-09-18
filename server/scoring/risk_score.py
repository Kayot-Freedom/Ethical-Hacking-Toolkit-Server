"""
Оценка безопасности 0–100 с весами по категориям.
"""


def compute_score(scan: dict) -> dict:
    score = 100
    penalties: list[str] = []
    critical_issues: list[str] = []
    categories: dict[str, int] = {
        "network": 0, "web": 0, "crypto": 0,
        "email": 0, "leak": 0, "takeover": 0,
    }

    def add(points: int, message: str, category: str, critical: bool = False):
        nonlocal score
        score -= points
        penalties.append(f"{message}  −{points}")
        categories[category] = categories.get(category, 0) + points
        if critical:
            critical_issues.append(message)

    # ── Порты (network) ─────────────────────────
    for p in (scan.get("ports") or []):
        if p.get("state") != "open":
            continue
        if p.get("risk") == "bad":
            add(10, f"Опасный порт открыт: {p['port']} ({p.get('service', '?')})",
                "network", critical=True)
        elif p.get("risk") == "warn":
            add(4, f"Потенциально рискованный порт: {p['port']} ({p.get('service', '?')})",
                "network")

    # ── Заголовки (web) ─────────────────────────
    headers = scan.get("headers") or {}
    if headers and not headers.get("error"):
        for h in headers.get("missing_headers", []):
            add(4, f"Отсутствует заголовок {h}", "web")

    # ── SSL (crypto) ────────────────────────────
    ssl = scan.get("ssl") or {}
    if ssl and not ssl.get("error") and not ssl.get("valid"):
        add(20, "SSL-сертификат невалиден или отсутствует", "crypto", critical=True)
    elif ssl.get("valid") and ssl.get("not_after"):
        days = _days_until(ssl["not_after"])
        if days is not None:
            if days < 0:
                add(25, f"SSL-сертификат просрочен на {-days} дн.", "crypto", critical=True)
            elif days < 14:
                add(10, f"SSL-сертификат истекает через {days} дн.", "crypto")

    # ── TLS Deep (crypto) ───────────────────────
    tls = scan.get("tls_deep") or {}
    if tls and not tls.get("error"):
        for proto in tls.get("weak_protocols", []):
            add(5, f"Устаревший TLS-протокол: {proto}", "crypto")
        if tls.get("heartbleed_vulnerable") is True:
            add(30, "КРИТИЧНО: Heartbleed", "crypto", critical=True)
        robot = tls.get("robot")
        if robot and "VULNERABLE" in str(robot).upper():
            add(15, "Уязвим к ROBOT attack", "crypto", critical=True)

    # ── Email (email) ───────────────────────────
    email = scan.get("email_sec") or {}
    if email and not email.get("error"):
        if not email.get("spf"):
            add(5, "SPF не настроен", "email")
        if not email.get("dmarc"):
            add(5, "DMARC не настроен", "email")
        elif "p=none" in (email.get("dmarc") or ""):
            add(3, "DMARC в режиме p=none (мониторинг)", "email")

    # ── Sensitive Files (leak) ──────────────────
    sensitive = scan.get("sensitive_files") or {}
    harmless = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
    for f in (sensitive.get("found") or []):
        path = f.get("path")
        if path in harmless:
            continue
        if path in ("/.env", "/.git/config", "/.git/HEAD"):
            add(12, f"КРИТИЧНО: публично доступен {path}", "leak", critical=True)
        else:
            add(8, f"Публично доступен {path}", "leak")

    # ── Directory Scan (leak / web) ─────────────
    dirs = scan.get("directory_scan") or {}
    seen_paths = set()

    # Критичные находки — отдельным приоритетом
    for f in (dirs.get("critical") or []):
        path = f.get("path")
        if path in seen_paths:
            continue
        seen_paths.add(path)
        add(15, f"КРИТИЧНО: публично доступен {path}", "leak", critical=True)

    # Остальные по категориям
    for f in (dirs.get("found") or []):
        path = f.get("path")
        if path in seen_paths:
            continue
        if f.get("critical"):
            continue
        category = f.get("category")
        status = f.get("status")

        # 401/403 на админку — это хорошо (защищено)
        if status in (401, 403):
            seen_paths.add(path)
            continue

        if category == "admin" and status in (200, 302):
            add(8, f"Публичная админка: {path}", "web")
        elif category == "api" and status == 200:
            add(4, f"Открытый API endpoint: {path}", "web")
        elif category == "backup" and status == 200:
            add(12, f"Публичный бэкап: {path}", "leak", critical=True)
        elif category == "debug" and status == 200:
            add(6, f"Debug endpoint открыт: {path}", "web")
        elif category == "config" and status == 200:
            add(10, f"Файл конфигурации доступен: {path}", "leak")
        elif category == "old" and status == 200:
            add(5, f"Старый файл доступен: {path}", "leak")

        seen_paths.add(path)

    # ── CORS (web) ──────────────────────────────
    cors = scan.get("cors") or {}
    if cors.get("vulnerable"):
        add(25, "КРИТИЧНО: CORS с credentials misconfig", "web", critical=True)

    # ── Cookie Flags (web) ──────────────────────
    cookies = scan.get("cookies") or {}
    for ck in (cookies.get("cookies") or []):
        if ck.get("safe"):
            continue
        add(3, f"Cookie «{ck.get('name', '?')}» без флагов безопасности", "web")

    # ── HTTP Methods (web) ──────────────────────
    methods = scan.get("http_methods") or {}
    for m in (methods.get("dangerous") or []):
        method = m.get("method")
        if method in ("PUT", "DELETE"):
            add(8, f"Опасный HTTP-метод: {method}", "web", critical=True)
        else:
            add(6, f"Опасный HTTP-метод: {method}", "web")

    # ── Subdomain Takeover (takeover) ───────────
    takeover = scan.get("subdomain_takeover") or {}
    for v in (takeover.get("vulnerable") or []):
        add(
            20,
            f"Subdomain takeover: {v.get('subdomain')} ({v.get('service', '?')})",
            "takeover",
            critical=True,
        )

    # ── Финализация ─────────────────────────────
    score = max(0, min(100, score))

    if score >= 90:
        rating, color, label = "A", "green",  "Отличная защита"
    elif score >= 75:
        rating, color, label = "B", "green",  "Хорошая защита"
    elif score >= 60:
        rating, color, label = "C", "yellow", "Средняя защита"
    elif score >= 40:
        rating, color, label = "D", "orange", "Слабая защита"
    else:
        rating, color, label = "F", "red",    "Критично"

    return {
        "score": score,
        "rating": rating,
        "color": color,
        "label": label,
        "penalties": penalties,
        "critical_issues": critical_issues,
        "categories": categories,
        "critical_count": len(critical_issues),
    }


def _days_until(date_str: str):
    try:
        from datetime import datetime, timezone
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return None