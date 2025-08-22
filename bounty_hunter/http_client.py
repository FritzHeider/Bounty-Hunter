from __future__ import annotations
import asyncio, random
from collections import defaultdict
import httpx
from yarl import URL
from typing import Dict

# A small pool of common user-agent strings
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

class BHClient(httpx.AsyncClient):
    """Async HTTP client with per-domain pacing and random user agents."""

    def __init__(self, *, settings, **kwargs):
        super().__init__(**kwargs)
        self.settings = settings
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def request(self, method: str, url: str, headers: dict | None = None, **kwargs):  # type: ignore[override]
        headers = headers.copy() if headers else {}
        if self.settings.RANDOM_UA:
            headers.setdefault("User-Agent", random.choice(USER_AGENTS))
        host = URL(url).host or ""
        lock = self._locks[host]
        async with lock:
            jitter = random.uniform(0, self.settings.REQUEST_JITTER_MS) / 1000
            if jitter > 0:
                await asyncio.sleep(jitter)
            return await super().request(method, url, headers=headers, **kwargs)
