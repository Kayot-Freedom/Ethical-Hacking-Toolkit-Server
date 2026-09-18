import asyncio
from pathlib import Path
import httpx
from core.config import HTTP_TIMEOUT
from modules.proxy_manager import make_httpx_client


# ═══════════════════════════════════════════════
#  Словари путей
# ═══════════════════════════════════════════════

WORDLIST_DIR = Path(__file__).parent.parent / "wordlist"

WORDLIST_FILES = {
    "common": WORDLIST_DIR / "common.txt",
    "dicc": WORDLIST_DIR / "dicc.txt",
    "raft-medium": WORDLIST_DIR / "raft-medium-words.txt",
    "raft-large": WORDLIST_DIR / "raft-large-words.txt",
}

DEFAULT_WORDLIST = "raft-large"
MAX_PATHS = 5000


def _load_wordlist(name: str = DEFAULT_WORDLIST) -> list[str]:
    path = WORDLIST_FILES.get(name)
    if not path or not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    result = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            line = "/" + line
        result.append(line)
    return list(dict.fromkeys(result))


FALLBACK_PATHS = {
    "admin": [
        "/admin", "/admin/", "/admin/login", "/administrator", "/wp-admin",
        "/wp-login.php", "/phpmyadmin", "/cpanel", "/dashboard", "/panel",
        "/manage", "/management", "/controlpanel", "/backend",
    ],
    "auth": [
        "/login", "/signin", "/sign-in", "/auth", "/authenticate",
        "/logout", "/register", "/signup", "/password-reset", "/2fa",
    ],
    "api": [
        "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
        "/swagger.json", "/openapi.json", "/api-docs", "/docs",
        "/graphql", "/graphiql", "/health", "/status", "/metrics",
        "/actuator", "/actuator/health", "/actuator/env",
    ],
    "config": [
        "/.env", "/.env.local", "/.env.bak",
        "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/.htaccess", "/.htpasswd", "/.DS_Store",
        "/config.php", "/config.json", "/config.yaml",
        "/wp-config.php", "/wp-config.php.bak",
        "/docker-compose.yml", "/package.json", "/composer.json",
        "/.aws/credentials", "/credentials.json", "/id_rsa",
    ],
    "backup": [
        "/backup", "/backups/", "/backup.zip", "/backup.tar.gz",
        "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
        "/site.zip", "/www.zip", "/old", "/archive/",
    ],
    "debug": [
        "/phpinfo.php", "/info.php", "/test.php", "/debug",
        "/server-status", "/server-info", "/nginx_status",
        "/trace", "/elmah.axd", "/console", "/_debug",
        "/version", "/changelog", "/readme.txt", "/README.md",
    ],
    "monitoring": [
        "/health", "/healthz", "/ready", "/live", "/metrics",
        "/prometheus", "/ping", "/status",
    ],
    "cms": [
        "/wp-content", "/wp-includes", "/wp-json",
        "/xmlrpc.php", "/uploads", "/files", "/images",
        "/static", "/assets", "/logs", "/error.log",
    ],
    "common": [
        "/index.php", "/index.html", "/home",
        "/robots.txt", "/sitemap.xml", "/favicon.ico",
        "/crossdomain.xml", "/manifest.json",
        "/.well-known/security.txt",
    ],
    "old": [
        "/index.php.bak", "/index.php.old", "/index.php~",
        "/index.html.bak", "/backup.php", "/test.php.bak",
        "/.index.php.swp", "/config.php.old",
    ],
}


CATEGORY_PREFIXES = {
    "admin":     ["/admin", "/wp-admin", "/phpmyadmin", "/cpanel", "/panel",
                  "/dashboard", "/manage", "/control", "/backend", "/moderator"],
    "auth":      ["/login", "/signin", "/sign-in", "/auth", "/register",
                  "/signup", "/logout", "/password", "/reset", "/2fa", "/mfa"],
    "api":       ["/api", "/swagger", "/openapi", "/graphql", "/graphiql",
                  "/rest", "/docs", "/redoc", "/actuator", "/services"],
    "config":    ["/.env", "/config", "/.git", "/.svn", "/.hg", "/.aws",
                  "/.htaccess", "/.htpasswd", "/docker", "/package.json",
                  "/composer.json", "/credentials", "/secrets", "/.npmrc",
                  "/id_rsa", "/.ssh"],
    "backup":    ["/backup", "/bak", "/old", "/archive", "/dump",
                  "/db.sql", "/database", "/export", "/import", "/www.zip",
                  "/site.zip", "/1.zip", "/2.zip"],
    "debug":     ["/phpinfo", "/info.php", "/test", "/debug", "/trace",
                  "/server-status", "/server-info", "/nginx_status",
                  "/elmah", "/console", "/_debug", "/_profiler", "/version",
                  "/changelog", "/readme", "/license"],
    "monitoring":["/health", "/healthz", "/ready", "/live", "/metrics",
                  "/prometheus", "/status", "/ping", "/pong", "/actuator"],
    "cms":       ["/wp-content", "/wp-includes", "/wp-json", "/xmlrpc",
                  "/sites", "/typo3", "/uploads", "/upload", "/files",
                  "/images", "/img", "/assets", "/static", "/media",
                  "/includes", "/vendor", "/logs"],
    "common":    ["/index", "/home", "/main", "/default", "/about",
                  "/contact", "/help", "/terms", "/privacy",
                  "/robots.txt", "/sitemap", "/favicon",
                  "/crossdomain", "/clientaccesspolicy",
                  "/manifest", "/.well-known"],
    "old":       [".bak", ".old", ".save", ".swp", ".orig", ".tmp", "~",
                  ".backup", ".zip", ".txt"],
}


def _guess_category(path: str) -> str:
    lower = path.lower()
    for cat, prefixes in CATEGORY_PREFIXES.items():
        for p in prefixes:
            if p in lower:
                return cat
    return "common"


CRITICAL_PATHS = {
    "/.env", "/.env.local", "/.env.prod", "/.env.production",
    "/.git/config", "/.git/HEAD", "/.git/index",
    "/.aws/credentials", "/.aws/config",
    "/id_rsa", "/.ssh/id_rsa",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/backup.sql", "/backup.zip", "/db.sql", "/dump.sql",
    "/phpinfo.php", "/server-status", "/nginx_status",
    "/actuator/env", "/credentials.json", "/secrets.json",
    "/.htpasswd", "/.htaccess",
}

INTERESTING_CODES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}


# ═══════════════════════════════════════════════
#  Главная функция
# ═══════════════════════════════════════════════

async def scan_directories(
    url: str,
    wordlist: str = DEFAULT_WORDLIST,
    max_concurrency: int = 30,
    timeout_per_request: float = 5.0,
    use_proxy: bool = False,
) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    loaded = _load_wordlist(wordlist)
    source = f"SecLists ({wordlist})"

    if not loaded:
        loaded = []
        for paths in FALLBACK_PATHS.values():
            loaded.extend(paths)
        loaded = list(dict.fromkeys(loaded))
        source = "встроенный fallback"

    loaded = loaded[:MAX_PATHS]

    if not loaded:
        return {
            "error": "Не удалось загрузить словарь путей",
            "checked": 0, "found": [], "critical": [], "by_category": {},
            "source": source,
        }

    all_paths = [(p, _guess_category(p)) for p in loaded]

    sem = asyncio.Semaphore(max_concurrency)

    async with make_httpx_client(
        enabled=use_proxy,
        timeout=HTTP_TIMEOUT,
        verify=False,
        follow_redirects=False,
        headers={"User-Agent": "EthicalHackingToolkit/3.2 (+authorized-scan)"},
    ) as client:

        async def check_path(path: str, category: str) -> dict:
            async with sem:
                full_url = url + path
                try:
                    r = await asyncio.wait_for(
                        client.get(full_url),
                        timeout=timeout_per_request,
                    )
                    size = len(r.content) if r.content else 0
                    return {
                        "path": path,
                        "category": category,
                        "status": r.status_code,
                        "size": size,
                        "content_type": r.headers.get("content-type", "")[:80],
                        "server": r.headers.get("server", "")[:40],
                        "location": r.headers.get("location", "")[:120],
                        "found": r.status_code in INTERESTING_CODES,
                        "critical": path in CRITICAL_PATHS and r.status_code == 200,
                    }
                except asyncio.TimeoutError:
                    return {"path": path, "category": category, "error": "timeout"}
                except Exception as e:
                    return {"path": path, "category": category, "error": str(e)[:100]}

        tasks = [check_path(p, c) for p, c in all_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    found = []
    errors = 0
    for r in results:
        if isinstance(r, Exception):
            errors += 1
            continue
        if r.get("error"):
            errors += 1
            continue
        if r.get("found"):
            found.append(r)

    found.sort(key=lambda x: (x["category"], x["status"]))

    by_category: dict[str, list] = {}
    for f in found:
        by_category.setdefault(f["category"], []).append(f)

    critical = [f for f in found if f.get("critical")]

    return {
        "source": source,
        "wordlist": wordlist,
        "checked": len(all_paths),
        "found_count": len(found),
        "critical_count": len(critical),
        "errors": errors,
        "found": found,
        "critical": critical,
        "by_category": by_category,
    }