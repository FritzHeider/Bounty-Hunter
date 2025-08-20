from __future__ import annotations
import asyncio, httpx
from bs4 import BeautifulSoup
from yarl import URL
from .utils import URL_RE, uniq

async def harvest_from_targets(client: httpx.AsyncClient, targets: list[str], settings) -> list[str]:
    sem = asyncio.Semaphore(settings.MAX_CONCURRENCY)
    async def fetch(url: str) -> str|None:
        try:
            async with sem:
                r = await client.get(url)
                ct = r.headers.get("content-type","")
                if r.status_code < 400 and ("text/" in ct or "javascript" in ct or "json" in ct):
                    return r.text
        except Exception: return None
        return None
    async def one(target: str) -> list[str]:
        urls=[]; base=str(URL(target))
        robots=str(URL(base).with_path("/robots.txt")); html=await fetch(robots)
        if html: urls.extend(URL_RE.findall(html))
        html=await fetch(base)
        if html:
            urls.extend(URL_RE.findall(html))
            soup=BeautifulSoup(html,"lxml")
            for tag in soup.find_all(["a","script","link","img"]):
                for attr in ("href","src"):
                    v=tag.get(attr)
                    if v and isinstance(v,str):
                        try:
                            u=str(URL(v)) if v.startswith("http") else str(URL(base)/v)
                            urls.append(u)
                        except Exception: pass
        for p in ["/login","/signin","/admin","/api/","/api/v1/","/.well-known/security.txt","/.well-known/change-password"]:
            urls.append(str(URL(base).with_path(p)))
        return uniq(urls)
    res = await asyncio.gather(*(one(t) for t in targets))
    return [u for sub in res for u in sub]
