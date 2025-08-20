from __future__ import annotations
import base64, json, httpx, jwt
from dataclasses import dataclass
from yarl import URL
PROTECTED_GUESSES=["/api/me","/api/user","/api/account","/admin","/dashboard"]
@dataclass
class JWTFinding: endpoint: str; vuln: str; curl: str; evidence: str
class JWTChecker:
    def __init__(self, client: httpx.AsyncClient, reporter, settings):
        self.client=client; self.reporter=reporter; self.settings=settings
    async def run(self,endpoints:list[str]):
        roots=sorted({str(URL(u).with_path("/")) for u in endpoints if URL(u).scheme in ("http","https")})
        for root in roots:
            target=None
            for guess in PROTECTED_GUESSES:
                url=str(URL(root).with_path(guess))
                try:
                    r=await self.client.get(url)
                    if r.status_code in (401,403): target=url; break
                except Exception: continue
            if not target: continue
            none=self._make_alg_none({"sub":"test","role":"admin","iat":0})
            try:
                r=await self.client.get(target, headers={"Authorization": f"Bearer {none}"})
                if r.status_code not in (401,403):
                    await self.reporter.generic_finding("JWT alg=none acceptance", target, f"Accepted unsigned JWT (status {r.status_code}).", f"curl -i -H 'Authorization: Bearer {none}' '{target}'")
            except Exception: pass
            try:
                hs=jwt.encode({"sub":"test","role":"admin"}, key="none", algorithm="HS256")
                r2=await self.client.get(target, headers={"Authorization": f"Bearer {hs}"})
                if r2.status_code not in (401,403):
                    await self.reporter.generic_finding("JWT key confusion (heuristic)", target, "Accepted HS256 token with trivial key.", f"curl -i -H 'Authorization: Bearer {hs}' '{target}'")
            except Exception: pass
    def _make_alg_none(self,payload:dict)->str:
        header={"alg":"none","typ":"JWT"}
        b64=lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        return f"{b64(json.dumps(header,separators=(',',':')).encode())}.{b64(json.dumps(payload,separators=(',',':')).encode())}."
