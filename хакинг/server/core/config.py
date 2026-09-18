from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CLIENT_DIR = BASE_DIR / "client"
DB_PATH = BASE_DIR / "scans.db"

# ⚠️ Белый список — если не пустой, сканировать можно только эти домены
ALLOWED_TARGETS: set[str] = set()

# Таймауты
HTTP_TIMEOUT = 10.0
PORT_TIMEOUT = 0.8

# Порты для сканирования
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]

# Security-заголовки
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ── Sensitive paths ─────────────────────────────
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/backup.zip", "/backup.sql", "/db.sql", "/.DS_Store",
    "/config.php.bak", "/wp-config.php.bak", "/phpinfo.php",
    "/.htaccess", "/crossdomain.xml", "/server-status",
]

# ── HTTP методы для проверки ────────────────────
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"]

# ── Сабдомен takeover — сигнатуры облаков ───────
TAKEOVER_SIGNATURES = {
    "heroku":         ["No such app", "herokucdn.com/error-pages/no-such-app"],
    "github":         ["There isn't a GitHub Pages site here", "For root URLs"],
    "s3":             ["NoSuchBucket", "The specified bucket does not exist"],
    "azure":          ["404 Web Site not found", "The resource you are looking for has been removed"],
    "shopify":        ["Sorry, this shop is currently unavailable"],
    "tumblr":         ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
    "wordpress":      ["Do you want to register"],
    "surge.sh":       ["project not found"],
    "bitbucket":      ["Repository not found"],
    "fastly":         ["Fastly error: unknown domain"],
    "pantheon":       ["The gods are wise", "404 error unknown site"],
    "ghost":          ["The thing you were looking for is no longer here"],
    "zendesk":        ["Help Center Closed"],
    "readme":         ["Project doesnt exist"],
    "cargo":          ["<title>404 &mdash; File not found"],
    "unbounce":       ["The requested URL was not found on this server"],
    "statuspage":     ["You are being redirected"],
}

PROXIES: list[str] = [
    # Раскомментируй и добавь свои:
    "http://5.188.23.147:5555",
    "http://176.99.134.183:8090",
    "http://80.246.16.2:3128",
    "http://195.19.217.200:3128",
    # "http://user:pass@proxy1.example.com:3128",
    # "socks5://91.197.79.59:1080",
    # "socks5://185.49.110.155:1080",
    # "socks5://213.27.29.153:51000",
    # "socks5://94.228.240.23:1080",
    # "socks5://195.133.83.147:1080",
    # "socks5://77.41.170.50:1080",
    # "socks5://195.211.124.50:1080"
]

# URL для проверки работоспособности прокси.
# Должен отдавать 200 и быть быстрым. Можно свой.
PROXY_CHECK_URL = "https://api.ipify.org?format=json"

# Таймаут проверки одного прокси (сек)
PROXY_CHECK_TIMEOUT = 8.0

# Проверять прокси при каждом скане (True) или кэшировать (False)
PROXY_VERIFY_EACH_TIME = True