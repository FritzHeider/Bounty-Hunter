from __future__ import annotations
import asyncio, httpx
from yarl import URL
COMMON_ADMIN_PATHS=["/admin","/admin/","/dashboard","/manage","/settings","/account","/wp-admin/","/cms/"]
class AuthChecker:
    def __init__(self, client: httpx.AsyncClient, reporter, settings):
        self.client=client; self.reporter=reporter; self.settings=settings; self.sem=asyncio.Semaphore(settings.MAX_CONCURRENCY)
    async def run(self, endpoints: list[str]):
        roots=sorted({str(URL(u).with_path("/")) for u in endpoints if URL(u).scheme in ("http","https")})
        await asyncio.gather(*(self.check_root(r) for r in roots))
    async def check_root(self, root: str):
        for p in COMMON_ADMIN_PATHS:
            url=str(URL(root).with_path(p))
            try:
                async with self.sem: r=await self.client.get(url)
                body=(r.text or "")[:4000]
                if r.status_code in (200,302,301):
                    if r.status_code==200 and ("login" not in body.lower() and "sign in" not in body.lower()):
                        curl=f"curl -i '{url}'"; ev=f"HTTP {r.status_code} to admin path without login markers"
                        await self.reporter.generic_finding("Auth Bypass (heuristic)", url, ev, curl)
                aco=r.headers.get("Access-Control-Allow-Origin",""); acc=r.headers.get("Access-Control-Allow-Credentials","")
                if acc.lower()=="true" and (aco=="*" or aco.endswith(".example.com")):
                    curl=f"curl -i '{url}'"; ev=f"CORS misconfig: ACO='{aco}', ACC='{acc}'"; await self.reporter.generic_finding("CORS Misconfiguration", url, ev, curl)
            except Exception: continue
