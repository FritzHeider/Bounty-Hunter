from __future__ import annotations

import asyncio
from typing import Dict, List

import httpx
from yarl import URL


COMMON_ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/dashboard",
    "/manage",
    "/settings",
    "/account",
    "/wp-admin/",
    "/cms/",
]

DESKTOP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    )
}

MOBILE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
        "Mobile/15E148 Safari/604.1"
    )
}

HEADER_PROFILES = {"desktop": DESKTOP_HEADERS, "mobile": MOBILE_HEADERS}


class AuthChecker:
    def __init__(self, client: httpx.AsyncClient, reporter, settings):
        self.client = client
        self.reporter = reporter
        self.settings = settings
        self.sem = asyncio.Semaphore(settings.MAX_CONCURRENCY)
        self.sessions = self._build_sessions()

    def _build_sessions(self) -> List[Dict]:
        roles = {"anon": {}}
        roles.update(self.settings.USER_ROLES or {})
        sessions = []
        for role, data in roles.items():
            r_headers = data.get("headers", {})
            cookies = data.get("cookies", {})
            for prof_name, prof_headers in HEADER_PROFILES.items():
                headers = {**prof_headers, **r_headers}
                sessions.append(
                    {
                        "name": f"{role}-{prof_name}",
                        "headers": headers,
                        "cookies": cookies,
                    }
                )
        return sessions

    async def run(self, endpoints: List[str]):
        roots = sorted(
            {
                str(URL(u).with_path("/"))
                for u in endpoints
                if URL(u).scheme in ("http", "https")
            }
        )
        await asyncio.gather(*(self.check_root(r) for r in roots))

    async def check_root(self, root: str):
        for p in COMMON_ADMIN_PATHS:
            url = str(URL(root).with_path(p))
            results = []
            for sess in self.sessions:
                try:
                    async with self.sem:
                        r = await self.client.get(
                            url, headers=sess["headers"], cookies=sess["cookies"]
                        )
                    body = (r.text or "")[:4000]
                    results.append((sess["name"], r.status_code, body))

                    if r.status_code in (200, 302, 301):
                        if r.status_code == 200 and (
                            "login" not in body.lower()
                            and "sign in" not in body.lower()
                        ):
                            curl = (
                                f"curl -i '{url}' -H 'User-Agent: {sess['headers'].get('User-Agent','')}'"
                            )
                            ev = (
                                f"HTTP {r.status_code} to admin path without login markers for {sess['name']}"
                            )
                            await self.reporter.generic_finding(
                                "Auth Bypass (heuristic)", url, ev, curl
                            )

                    aco = r.headers.get("Access-Control-Allow-Origin", "")
                    acc = r.headers.get("Access-Control-Allow-Credentials", "")
                    if acc.lower() == "true" and (
                        aco == "*" or aco.endswith(".example.com")
                    ):
                        curl = (
                            f"curl -i '{url}' -H 'User-Agent: {sess['headers'].get('User-Agent','')}'"
                        )
                        ev = f"CORS misconfig: ACO='{aco}', ACC='{acc}'"
                        await self.reporter.generic_finding(
                            "CORS Misconfiguration", url, ev, curl
                        )
                except Exception:
                    continue

            if len(results) > 1:
                status_pairs = {(code, len(body)) for _, code, body in results}
                if len(status_pairs) > 1:
                    evidence = " | ".join(
                        f"{name}:{code}:{len(body)}B" for name, code, body in results
                    )
                    await self.reporter.generic_finding(
                        "Authorization discrepancy", url, evidence, f"curl -i '{url}'"
                    )

