from __future__ import annotations
import asyncio, re, httpx
from bs4 import BeautifulSoup
from yarl import URL
from sourcemap import load as sm_load
ENDPOINT_RE=re.compile(r"https?://[\w.-]+(?:\:[0-9]+)?(?:/[\w\-./%?#=&+]*)?", re.I)
API_KEY_RE=re.compile(r"(?i)(api[_-]?key|token|secret)[\s:=\"]{0,3}([A-Za-z0-9_\-]{16,})")
class JSMiner:
    def __init__(self, client: httpx.AsyncClient, settings):
        self.client=client; self.settings=settings; self.sem=asyncio.Semaphore(settings.MAX_CONCURRENCY)
    async def mine(self, endpoints: list[str])->list[str]:
        js=[u for u in endpoints if u.lower().endswith('.js')]
        html=[u for u in endpoints if any(u.lower().endswith(x) for x in ("/",".html",".htm"))]
        extra = await asyncio.gather(*[self._from_html(u) for u in html])
        for ex in extra: js.extend(ex)
        js=sorted(set(js)); out=[]
        for res in await asyncio.gather(*[self._scan_js(u) for u in js]): out.extend(res)
        return sorted(set(out))
    async def _from_html(self,url:str)->list[str]:
        try:
            async with self.sem: r=await self.client.get(url)
            if r.status_code>=400: return []
            soup=BeautifulSoup(r.text,"lxml"); out=[]
            for s in soup.find_all("script"):
                src=s.get("src");
                if src: out.append(str(URL(url)/src))
            return out
        except Exception: return []
    async def _scan_js(self,url:str)->list[str]:
        disc=[]
        try:
            async with self.sem: r=await self.client.get(url)
            body=r.text or ""
        except Exception: return []
        disc+=ENDPOINT_RE.findall(body)
        for m in API_KEY_RE.findall(body):
            token=m[1]
            if len(token)>=20: disc.append(f"secret://{token}")
        sm_url=None
        for line in body.splitlines()[-5:]:
            if "sourceMappingURL=" in line:
                part=line.split("sourceMappingURL=")[-1].strip().strip('*/# '); sm_url=str(URL(url)/part)
        if sm_url:
            try:
                async with self.sem: r2=await self.client.get(sm_url)
                if r2.status_code<400:
                    sm=sm_load(r2.text)
                    disc+=ENDPOINT_RE.findall(r2.text)
            except Exception: pass
        return disc
