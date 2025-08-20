from __future__ import annotations
import asyncio, httpx
from dataclasses import dataclass
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
        try:
            async with self.sem:
                r=await self.client.get(url, headers=HEADERS_MUTATIONS)
                body=(r.text or "")[:4000]
                if any(sig.search(body) for sig in [XSS_REFLECTION, SSTI_REFLECTION]):
                    f=Finding(url=url, method="GET", category="Header-reflection", evidence=body[:800], curl=f"curl -i -H 'X-Forwarded-Host: evil.example' '{url}'")
                    await self.reporter.write_finding(f, self.llm)
        except Exception: return
    async def _request_and_check(self, url: str, method: str, category: str, body: str|None):
        try:
            async with self.sem:
                r=await self.client.request(method, url, content=body)
                text=(r.text or "")[:8000]
        except Exception: return
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
