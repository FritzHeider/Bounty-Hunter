from __future__ import annotations
import asyncio, secrets, httpx
from yarl import URL
SSRF_KEYS=["url","dest","domain","host","image","feed","callback","target","path"]
class OOBSSRF:
    def __init__(self, client: httpx.AsyncClient, reporter, settings):
        self.client=client; self.reporter=reporter; self.settings=settings; self.sem=asyncio.Semaphore(settings.MAX_CONCURRENCY)
        self.domain=(settings.CANARY_DOMAIN or "").strip()
    async def run(self, endpoints: list[str]):
        if not self.domain: return
        await asyncio.gather(*(self._probe(u) for u in endpoints if URL(u).scheme in ("http","https")))
    async def _probe(self, url: str):
        base=URL(url); token=secrets.token_hex(6)
        canary=f"{self.settings.CANARY_LABEL_PREFIX}-{token}.{self.domain}"; canary_url=f"http://{canary}/ping"
        for k in SSRF_KEYS:
            q=dict(base.query); q[k]=canary_url; test=str(base.with_query(q))
            try:
                async with self.sem: r=await self.client.get(test)
                curl=f"curl -i '{test}'"; note=f"Injected `{canary_url}` via `{k}`. Watch canary for hits."
                await self.reporter.generic_finding("SSRF (OOB probe queued)", test, note, curl)
            except Exception: continue
