from __future__ import annotations
import asyncio, httpx
from dataclasses import dataclass
from yarl import URL
from .payloads import XSS_PROBES, SQLI_PROBES, SSTI_PROBES, SSRF_PROBES, COMMON_KEYS, HEADERS_MUTATIONS
from .signatures import XSS_PATTERNS, SQLI_ERRORS, SSTI_PATTERNS, RESPONSE_TIME_THRESHOLD
from .report import ReportWriter
from .llm import LLM

@dataclass
class Finding:
    url: str; method: str; category: str; evidence: str; curl: str; confidence: float

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
                if any(sig.search(body) for sig in (XSS_PATTERNS+SSTI_PATTERNS)):
                    await self._record(url, "GET", "Header-reflection", body[:800], 0.9)
        except Exception:
            return
    async def _request_and_check(self, url: str, method: str, category: str, body: str|None):
        try:
            async with self.sem:
                start=asyncio.get_event_loop().time()
                r=await self.client.request(method, url, content=body)
                elapsed=asyncio.get_event_loop().time()-start
                text=(r.text or "")[:8000]
        except Exception:
            return

        async def confirm()->tuple[str,float]:
            async with self.sem:
                s=asyncio.get_event_loop().time()
                r2=await self.client.request(method, url, content=body)
                return (r2.text or "")[:8000], asyncio.get_event_loop().time()-s

        if category.startswith("XSS") or category=="LLM-variant":
            if any(sig.search(text) for sig in XSS_PATTERNS):
                ctext,_=await confirm()
                conf=0.9 if any(sig.search(ctext) for sig in XSS_PATTERNS) else 0.4
                await self._record(url, method, "Reflected XSS (indicator)", text, conf)
        if category.startswith("SQLi") or category=="LLM-variant":
            hit=any(sig.search(text) for sig in SQLI_ERRORS)
            delay=elapsed>RESPONSE_TIME_THRESHOLD
            if hit or delay:
                ctext,celapsed=await confirm()
                confirm_hit=any(sig.search(ctext) for sig in SQLI_ERRORS)
                confirm_delay=celapsed>RESPONSE_TIME_THRESHOLD
                conf=0.9 if (hit and confirm_hit) or (delay and confirm_delay) else 0.4
                label="Potential SQLi (error-based)" if hit else "Potential SQLi (time-based)"
                await self._record(url, method, label, text, conf)
        if category.startswith("SSTI") or category=="LLM-variant":
            if any(sig.search(text) for sig in SSTI_PATTERNS):
                ctext,_=await confirm()
                conf=0.9 if any(sig.search(ctext) for sig in SSTI_PATTERNS) else 0.4
                await self._record(url, method, "Template Injection indicator", text, conf)
        if category.startswith("SSRF") or category=="LLM-variant":
            hit="169.254.169.254" in text or "127.0.0.1" in text
            if hit:
                ctext,_=await confirm()
                confirm_hit="169.254.169.254" in ctext or "127.0.0.1" in ctext
                conf=0.9 if confirm_hit else 0.4
                await self._record(url, method, "SSRF indicator reflected", text, conf)

    async def _record(self, url: str, method: str, label: str, evidence_body: str, confidence: float):
        print(f"[{confidence:.2f}] {label} at {url}")
        if confidence < getattr(self.settings, "CONFIDENCE_THRESHOLD", 0.0):
            return
        curl=f"curl -i '{url}'"
        f=Finding(url=url, method=method, category=label, evidence=evidence_body[:2000], curl=curl, confidence=confidence)
        await self.reporter.write_finding(f, self.llm)
