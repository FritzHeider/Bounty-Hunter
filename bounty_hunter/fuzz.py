from __future__ import annotations
import asyncio, httpx, random
from dataclasses import dataclass
from urllib.parse import urljoin
from yarl import URL
from .payloads import XSS_PROBES, SQLI_PROBES, SSTI_PROBES, SSRF_PROBES, COMMON_KEYS, HEADERS_MUTATIONS
from .signatures import XSS_REFLECTION, SQLI_ERRORS, SSTI_REFLECTION
from .report import ReportWriter
from .llm import LLM

@dataclass
class Finding:
    url: str; method: str; category: str; evidence: str; curl: str

class FuzzCoordinator:
    def __init__(self, client: httpx.AsyncClient, llm: LLM, reporter: ReportWriter, settings):
        self.client=client; self.llm=llm; self.reporter=reporter; self.settings=settings
        self.sem=asyncio.Semaphore(settings.MAX_CONCURRENCY)

    async def _fetch(self, method: str, url: str, *, headers=None, body: str|None=None):
        await asyncio.sleep(random.uniform(0, self.settings.JITTER_S))
        current=url; depth=0
        while True:
            if self.settings.ALLOWED_HOSTS and URL(current).host not in self.settings.ALLOWED_HOSTS:
                return None
            async with self.sem:
                try:
                    async with self.client.stream(method, current, headers=headers, content=body, follow_redirects=False) as r:
                        if r.is_redirect:
                            depth+=1
                            if depth>self.settings.MAX_REDIRECT_DEPTH:
                                return None
                            loc=r.headers.get("Location")
                            if not loc:
                                return None
                            nxt=urljoin(current, loc)
                            current=nxt
                            continue
                        if int(r.headers.get("Content-Length","0"))>self.settings.MAX_RESPONSE_SIZE:
                            return None
                        buf=b""
                        async for chunk in r.aiter_bytes():
                            buf+=chunk
                            if len(buf)>self.settings.MAX_RESPONSE_SIZE:
                                return None
                        text=buf.decode(errors="ignore")
                        return text
                except Exception:
                    return None
    async def run(self, endpoints: list[str]):
        await asyncio.gather(*(self.scan_endpoint(u) for u in endpoints))
    async def scan_endpoint(self, url: str):
        await self._fuzz_get(url); await self._mutate_headers(url)
    async def _fuzz_get(self, url: str):
        base=URL(url); 
        if base.scheme not in ("http","https"): return
        async def try_payloads(category, probes):
            for key in COMMON_KEYS:
                for p in probes:
                    q=dict(base.query); q[key]=p; u=str(base.with_query(q))
                    await self._request_and_check(u, "GET", category, None)
        await try_payloads("XSS", XSS_PROBES)
        await try_payloads("SQLi", SQLI_PROBES)
        await try_payloads("SSTI", SSTI_PROBES)
        await try_payloads("SSRF", SSRF_PROBES)
        ctx=f"URL: {url}\nHeaders: minimal\nObservations: n/a"
        for p in await self.llm.advise_payloads(ctx):
            for key in COMMON_KEYS:
                q=dict(base.query); q[key]=p; u=str(base.with_query(q))
                await self._request_and_check(u, "GET", "LLM-variant", None)
    async def _mutate_headers(self, url: str):
        body = await self._fetch("GET", url, headers=HEADERS_MUTATIONS)
        if not body:
            return
        snippet = body[:4000]
        if any(sig.search(snippet) for sig in [XSS_REFLECTION, SSTI_REFLECTION]):
            f = Finding(
                url=url,
                method="GET",
                category="Header-reflection",
                evidence=snippet[:800],
                curl=f"curl -i -H 'X-Forwarded-Host: evil.example' '{url}'",
            )
            await self.reporter.write_finding(f, self.llm)
    async def _request_and_check(self, url: str, method: str, category: str, body: str|None):
        text = await self._fetch(method, url, body=body)
        if not text:
            return
        text = text[:8000]
        if category.startswith("XSS") or category=="LLM-variant":
            if XSS_REFLECTION.search(text):
                await self._record(url, method, "Reflected XSS (indicator)", text)
        if category.startswith("SQLi") or category=="LLM-variant":
            if any(sig.search(text) for sig in SQLI_ERRORS):
                await self._record(url, method, "Potential SQLi (error-based)", text)
        if category.startswith("SSTI") or category=="LLM-variant":
            if SSTI_REFLECTION.search(text):
                await self._record(url, method, "Template Injection indicator", text)
        if category.startswith("SSRF") or category=="LLM-variant":
            if "169.254.169.254" in text or "127.0.0.1" in text:
                await self._record(url, method, "SSRF indicator reflected", text)
    async def _record(self, url: str, method: str, label: str, evidence_body: str):
        curl=f"curl -i '{url}'"; f=Finding(url=url, method=method, category=label, evidence=evidence_body[:2000], curl=curl)
        await self.reporter.write_finding(f, self.llm)
