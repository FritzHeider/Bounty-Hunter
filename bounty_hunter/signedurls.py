from __future__ import annotations
import re, httpx
from yarl import URL
PRESIGN_PATTERNS=[re.compile(r"X-Amz-Signature=",re.I),re.compile(r"X-Goog-Signature=",re.I),re.compile(r"se=\d{10,}",re.I),re.compile(r"sig=",re.I)]
class SignedURLChecker:
    def __init__(self, client: httpx.AsyncClient, reporter, settings):
        self.client=client; self.reporter=reporter; self.settings=settings
    async def run(self,endpoints:list[str]):
        for url in [u for u in endpoints if any(p.search(u) for p in PRESIGN_PATTERNS)]:
            await self._check(url)
    async def _check(self,url:str):
        u=URL(url); q=dict(u.query)
        stripped={k:v for k,v in q.items() if k.lower() not in {"x-amz-signature","x-goog-signature","sig"}}
        naked=str(u.with_query(stripped))
        try:
            r=await self.client.get(naked)
            if r.status_code==200:
                await self.reporter.generic_finding("Signed URL Misuse — Signature Not Enforced", naked, f"Removing signature still returns 200. Original: {url}", f"curl -i '{naked}'")
        except Exception: pass
        if "se" in q:
            try:
                ex=dict(q); ex["se"]=str(int(q["se"]) + 864000)
                test=str(u.with_query(ex)); r2=await self.client.get(test)
                if r2.status_code==200 and test!=url:
                    await self.reporter.generic_finding("Signed URL Misuse — Expiry Tampering", test, f"Increasing `se` maintained access. Original: {url}", f"curl -i '{test}'")
            except Exception: pass
