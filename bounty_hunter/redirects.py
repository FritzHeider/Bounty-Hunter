from __future__ import annotations
import asyncio, httpx
from dataclasses import dataclass
from yarl import URL

@dataclass
class RedirectFinding: url: str; location: str; curl: str
class RedirectChecker:
    def __init__(self, client: httpx.AsyncClient, reporter, settings):
        self.client=client; self.reporter=reporter; self.settings=settings; self.sem=asyncio.Semaphore(settings.MAX_CONCURRENCY)
        self.keys=["next","url","redirect","return","r","dest","to"]
    async def run(self, endpoints: list[str]): await asyncio.gather(*(self.check(u) for u in endpoints))
    async def check(self, url: str):
        base=URL(url); 
        if base.scheme not in ("http","https"): return
        payloads=["https://evil.example/","//evil.example/","\\evil.example/"]
        for k in self.keys:
            q=dict(base.query)
            for p in payloads:
                q[k]=p; test=str(base.with_query(q))
                try:
                    async with self.sem: r=await self.client.get(test)
                except Exception: continue
                loc=r.headers.get("Location","")
                if loc.startswith("http") and ("evil.example" in loc or loc.startswith("//evil.example")):
                    curl=f"curl -i '{test}'"; md=f"Open redirect via `{k}` → `{loc}`"
                    await self.reporter.generic_finding("Open Redirect", test, md, curl)
