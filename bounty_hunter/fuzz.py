from __future__ import annotations

import asyncio, random
from dataclasses import dataclass
from typing import Optional, Sequence, Iterable, Mapping

import httpx
from yarl import URL

from .payloads import (
    XSS_PROBES,
    SQLI_PROBES,
    SSTI_PROBES,
    SSRF_PROBES,
    COMMON_KEYS,
    HEADERS_MUTATIONS,
)
from . import mutate  # needed by both branches
from .report import ReportWriter
from .llm import LLM

# --- signatures import (backward-compat across branches) ----------------------
try:
    from .signatures import XSS_PATTERNS, SQLI_ERRORS, SSTI_PATTERNS
except Exception:
    # Older/main branch names
    from .signatures import XSS_REFLECTION as XSS_PATTERNS  # type: ignore
    from .signatures import SQLI_ERRORS  # type: ignore
    from .signatures import SSTI_REFLECTION as SSTI_PATTERNS  # type: ignore

try:
    from .signatures import RESPONSE_TIME_THRESHOLD as DEFAULT_RTT_THRESHOLD  # type: ignore
except Exception:
    DEFAULT_RTT_THRESHOLD = 2.5  # seconds (sane default)


@dataclass
class Finding:
    url: str
    method: str
    category: str
    evidence: str
    curl: str
    confidence: float


class FuzzCoordinator:
    def __init__(self, client: httpx.AsyncClient, llm: LLM, reporter: ReportWriter, settings):
        self.client = client
        self.llm = llm
        self.reporter = reporter
        self.settings = settings
        self.sem = asyncio.Semaphore(getattr(settings, "MAX_CONCURRENCY", 10))
        self._rtt_threshold = float(getattr(settings, "RESPONSE_TIME_THRESHOLD", DEFAULT_RTT_THRESHOLD))
        self._confidence_threshold = float(getattr(settings, "CONFIDENCE_THRESHOLD", 0.0))
        self._jitter = float(getattr(settings, "JITTER_MAX_S", 0.5))
        self._max_body = int(getattr(settings, "MAX_RESPONSE_SIZE", 1_000_000))
        self._max_redirects = int(getattr(settings, "MAX_REDIRECT_DEPTH", 5))
        self._allowed_hosts = set(getattr(settings, "ALLOWED_HOSTS", []))

    async def run(self, endpoints: Sequence[str]) -> None:
        async def _launch(u: str) -> None:
            if self._jitter:
                await asyncio.sleep(random.uniform(0, self._jitter))
            await self.scan_endpoint(u)

        await asyncio.gather(*(_launch(u) for u in endpoints))

    async def scan_endpoint(self, url: str) -> None:
        await self._fuzz_get(url)
        await self._mutate_headers(url)

    async def _fuzz_get(self, url: str) -> None:
        base = URL(url)
        if base.scheme not in ("http", "https"):
            return

        async def try_payloads(category: str, probes: Sequence[str]) -> None:
            for key in COMMON_KEYS:
                for p in probes:
                    for variant in mutate.generate_variants(p):
                        q = dict(base.query)
                        q[key] = variant
                        u = str(base.with_query(q))
                        status = await self._request_and_check(u, "GET", category, None)
                        if status in (403, 406):  # WAF? try alternates
                            for alt in mutate.alternate_encodings(variant):
                                q[key] = alt
                                u2 = str(base.with_query(q))
                                await self._request_and_check(u2, "GET", category, None)

        # Deterministic probe passes
        await try_payloads("XSS", XSS_PROBES)
        await try_payloads("SQLi", SQLI_PROBES)
        await try_payloads("SSTI", SSTI_PROBES)
        await try_payloads("SSRF", SSRF_PROBES)

        # LLM-guided pass
        ctx = f"URL: {url}\nHeaders: minimal\nObservations: n/a"
        try:
            llm_payloads = await self.llm.advise_payloads(ctx)
        except Exception:
            llm_payloads = []

        for p in llm_payloads:
            for key in COMMON_KEYS:
                for variant in mutate.generate_variants(p):
                    q = dict(base.query)
                    q[key] = variant
                    u = str(base.with_query(q))
                    status = await self._request_and_check(u, "GET", "LLM-variant", None)
                    if status in (403, 406):
                        for alt in mutate.alternate_encodings(variant):
                            q[key] = alt
                            u2 = str(base.with_query(q))
                            await self._request_and_check(u2, "GET", "LLM-variant", None)

    async def _mutate_headers(self, url: str) -> None:
        # Support either a single mapping or a sequence of header mutations.
        try:
            from collections.abc import Mapping as _Mapping
        except Exception:
            _Mapping = dict  # fallback

        try:
            if isinstance(HEADERS_MUTATIONS, _Mapping):
                mutations: Iterable[Mapping[str, str]] = [HEADERS_MUTATIONS]  # type: ignore[assignment]
            else:
                mutations = HEADERS_MUTATIONS  # type: ignore[assignment]
        except Exception:
            return

        for headers in mutations:
            try:
                async with self.sem:
                    r = await self.client.get(url, headers=headers)
                    body = (r.text or "")[:4000]
            except Exception:
                continue

            # Header reflection checks
            if any(sig.search(body) for sig in XSS_PATTERNS) or any(sig.search(body) for sig in SSTI_PATTERNS):
                await self._record(url, "GET", "Header-reflection", body[:800], 0.9)

    async def _request_and_check(self, url: str, method: str, category: str, body: Optional[str]) -> Optional[int]:
        depth = 0
        current_url = url
        text = ""
        status: Optional[int] = None
        elapsed = 0.0
        headers = {}

        while True:
            try:
                async with self.sem:
                    start = asyncio.get_event_loop().time()
                    async with self.client.stream(method, current_url, content=body, follow_redirects=False) as r:
                        status = r.status_code
                        headers = r.headers
                        cl = headers.get("Content-Length")
                        if cl and int(cl) > self._max_body:
                            return status
                        content = await r.aread(self._max_body + 1)
                    elapsed = asyncio.get_event_loop().time() - start
            except Exception:
                return None

            if len(content) > self._max_body:
                return status
            text = content.decode(errors="ignore")

            if status in {301, 302, 303, 307, 308} and headers.get("Location"):
                depth += 1
                if depth > self._max_redirects:
                    return status
                nxt = headers.get("Location")
                next_url = str(URL(nxt)) if "://" in nxt else str(URL(current_url).join(URL(nxt)))
                if self._allowed_hosts and not any(URL(next_url).host.endswith(h) for h in self._allowed_hosts):
                    return status
                current_url = next_url
                continue
            break

        async def confirm() -> tuple[str, float]:
            try:
                async with self.sem:
                    s = asyncio.get_event_loop().time()
                    async with self.client.stream(method, current_url, content=body, follow_redirects=False) as r2:
                        cl = r2.headers.get("Content-Length")
                        if cl and int(cl) > self._max_body:
                            return "", 0.0
                        data = await r2.aread(self._max_body + 1)
                    celapsed = asyncio.get_event_loop().time() - s
            except Exception:
                return "", 0.0
            if len(data) > self._max_body:
                return "", 0.0
            return data.decode(errors="ignore"), celapsed

        # XSS
        if category.startswith("XSS") or category == "LLM-variant":
            if any(sig.search(text) for sig in XSS_PATTERNS):
                ctext, _ = await confirm()
                conf = 0.9 if any(sig.search(ctext) for sig in XSS_PATTERNS) else 0.4
                await self._record(current_url, method, "Reflected XSS (indicator)", text, conf)

        # SQLi (error-based / time-based)
        if category.startswith("SQLi") or category == "LLM-variant":
            hit = any(sig.search(text) for sig in SQLI_ERRORS)
            delay = elapsed > self._rtt_threshold
            if hit or delay:
                ctext, celapsed = await confirm()
                confirm_hit = any(sig.search(ctext) for sig in SQLI_ERRORS)
                confirm_delay = celapsed > self._rtt_threshold
                conf = 0.9 if (hit and confirm_hit) or (delay and confirm_delay) else 0.4
                label = "Potential SQLi (error-based)" if hit else "Potential SQLi (time-based)"
                await self._record(current_url, method, label, text, conf)

        # SSTI
        if category.startswith("SSTI") or category == "LLM-variant":
            if any(sig.search(text) for sig in SSTI_PATTERNS):
                ctext, _ = await confirm()
                conf = 0.9 if any(sig.search(ctext) for sig in SSTI_PATTERNS) else 0.4
                await self._record(current_url, method, "Template Injection indicator", text, conf)

        # SSRF (basic reflection heuristic)
        if category.startswith("SSRF") or category == "LLM-variant":
            hit = ("169.254.169.254" in text) or ("127.0.0.1" in text) or ("localhost" in text)
            if hit:
                ctext, _ = await confirm()
                confirm_hit = ("169.254.169.254" in ctext) or ("127.0.0.1" in ctext) or ("localhost" in ctext)
                conf = 0.9 if confirm_hit else 0.4
                await self._record(current_url, method, "SSRF indicator reflected", text, conf)

        return status

    async def _record(self, url: str, method: str, label: str, evidence_body: str, confidence: float) -> None:
        if confidence >= self._confidence_threshold:
            curl = f"curl -i -X {method} '{url}'"
            f = Finding(
                url=url,
                method=method,
                category=label,
                evidence=evidence_body[:2000],
                curl=curl,
                confidence=confidence,
            )
            await self.reporter.write_finding(f, self.llm)
        else:
            # Low-confidence telemetry; keep noisy findings out of the formal report
            print(f"[{confidence:.2f}] {label} at {url}")
