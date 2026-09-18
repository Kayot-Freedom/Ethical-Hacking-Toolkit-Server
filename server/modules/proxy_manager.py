import asyncio
import itertools
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from core.config import (
    PROXIES,
    PROXY_CHECK_URL,
    PROXY_CHECK_TIMEOUT,
    PROXY_VERIFY_EACH_TIME,
)


@dataclass
class ProxyState:
    url: str
    alive: bool = False
    latency_ms: Optional[float] = None
    exit_ip: Optional[str] = None
    error: Optional[str] = None
    checked_at: Optional[float] = None


class ProxyManager:
    """
    Пул прокси с проверкой и последовательной ротацией.

    - verify_all(): проверяет все прокси параллельно.
    - get_next(): возвращает следующий рабочий прокси (круговой обход).
    - has_alive(): есть ли рабочие прокси.
    """

    def __init__(self):
        self._states: list[ProxyState] = [ProxyState(url=u) for u in PROXIES]
        self._rotation = itertools.cycle([])
        self._alive_urls: list[str] = []
        self._lock = asyncio.Lock()
        self._verified = False
        self._last_check: float = 0.0

    # ────────────────────────────────────────────
    #  Проверка
    # ────────────────────────────────────────────

    async def verify_all(self, force: bool = False) -> list[dict]:
        async with self._lock:
            if (
                self._verified
                and not force
                and not PROXY_VERIFY_EACH_TIME
            ):
                return self._snapshot()

            if not self._states:
                self._verified = True
                return self._snapshot()

            results = await asyncio.gather(
                *[_check_proxy(s) for s in self._states],
                return_exceptions=False,
            )
            self._states = results

            self._alive_urls = [s.url for s in self._states if s.alive]
            self._rotation = (
                itertools.cycle(self._alive_urls)
                if self._alive_urls
                else itertools.cycle([])
            )
            self._verified = True
            self._last_check = time.time()
            return self._snapshot()

    def _snapshot(self) -> list[dict]:
        return [
            {
                "url": s.url,
                "alive": s.alive,
                "latency_ms": round(s.latency_ms, 1)
                if s.latency_ms is not None
                else None,
                "exit_ip": s.exit_ip,
                "error": s.error,
            }
            for s in self._states
        ]

    # ────────────────────────────────────────────
    #  Ротация
    # ────────────────────────────────────────────

    def has_alive(self) -> bool:
        return len(self._alive_urls) > 0

    def get_next(self) -> Optional[str]:
        if not self._alive_urls:
            return None
        return next(self._rotation)

    def alive_count(self) -> int:
        return len(self._alive_urls)

    def total_count(self) -> int:
        return len(self._states)

    def is_enabled(self) -> bool:
        """Прокси вообще настроены в config? (не пустой список)"""
        return len(PROXIES) > 0


# ─── Глобальный singleton ─────────────────────
_manager: Optional[ProxyManager] = None


def get_proxy_manager() -> ProxyManager:
    global _manager
    if _manager is None:
        _manager = ProxyManager()
    return _manager


# ─── Проверка одного прокси ───────────────────
async def _check_proxy(state: ProxyState) -> ProxyState:
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            proxy=state.url,
            timeout=PROXY_CHECK_TIMEOUT,
            verify=False,
            follow_redirects=True,
        ) as client:
            r = await client.get(PROXY_CHECK_URL)
            r.raise_for_status()

            exit_ip = None
            try:
                data = r.json()
                if isinstance(data, dict):
                    exit_ip = (
                        data.get("ip")
                        or data.get("origin")
                        or data.get("query")
                    )
            except Exception:
                exit_ip = r.text.strip()[:64] if r.text else None

            state.alive = True
            state.latency_ms = (time.perf_counter() - start) * 1000
            state.exit_ip = exit_ip
            state.error = None
            state.checked_at = time.time()
    except Exception as e:
        state.alive = False
        state.latency_ms = None
        state.exit_ip = None
        state.error = _short_error(e)
        state.checked_at = time.time()
    return state


def _short_error(e: Exception) -> str:
    msg = str(e)
    if not msg:
        msg = e.__class__.__name__
    return msg[:160]


# ─── Хелпер для httpx-клиентов ────────────────
def make_httpx_client(enabled: bool = False, **kwargs) -> httpx.AsyncClient:
    """
    Возвращает готовый AsyncClient с прокси, если пользователь включил прокси.

    Пример:
        async with make_httpx_client(enabled=use_proxy, timeout=10) as client:
            ...
    """
    if enabled:
        manager = get_proxy_manager()
        proxy_url = manager.get_next()
        if proxy_url:
            kwargs["proxy"] = proxy_url
    return httpx.AsyncClient(**kwargs)