import re
from fastapi import HTTPException
from core.config import ALLOWED_TARGETS

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                    "169.254.", "127.", "0.")


def normalize_target(target: str) -> tuple[str, str]:
    """Возвращает (host, url)."""
    target = target.strip().lower()
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0]
    host = target
    url = "https://" + target
    return host, url


def validate_target(target: str) -> str:
    host, _ = normalize_target(target)
    if host in ("localhost", "127.0.0.1"):
        return host
    if not DOMAIN_RE.match(host):
        raise HTTPException(400, "Некорректный домен")
    for p in PRIVATE_PREFIXES:
        if host.startswith(p):
            raise HTTPException(403, "Приватные сети запрещены")
    if ALLOWED_TARGETS and host not in ALLOWED_TARGETS:
        raise HTTPException(403, "Цель отсутствует в белом списке")
    return host


def check_consent(consent: bool):
    if not consent:
        raise HTTPException(403, "Необходимо подтвердить разрешение на тестирование.")