import asyncio
import dns.resolver
from concurrent.futures import ThreadPoolExecutor


async def dns_lookup(host: str) -> dict:
    """Параллельный DNS-lookup всех типов записей."""
    rtypes = ("A", "AAAA", "MX", "TXT", "NS", "CAA")

    def _resolve(rtype):
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5)
            return rtype, [str(a) for a in answers]
        except Exception:
            return rtype, []

    # Все 6 запросов идут параллельно в пуле потоков
    results = await asyncio.gather(
        *[asyncio.to_thread(_resolve, rt) for rt in rtypes]
    )
    return dict(results)