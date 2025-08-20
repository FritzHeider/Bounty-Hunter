from __future__ import annotations
import json, httpx, mmh3
from dataclasses import dataclass
from yarl import URL
FAVICON_DB_BUILTIN={"116323821":{"product":"Jenkins","notes":"Default favicon"},"-203227154":{"product":"Apache Tomcat","notes":"Default favicon"},"-1581907337":{"product":"SonarQube","notes":"Default favicon"}}
@dataclass
class FingerprintFinding: endpoint: str; product: str; hash: str; headers: dict; notes: str
class Fingerprinter:
    def __init__(self, client: httpx.AsyncClient, settings):
        self.client=client; self.settings=settings
    async def run(self,endpoints:list[str])->list[FingerprintFinding]:
        roots=sorted({str(URL(u).with_path("/")) for u in endpoints if URL(u).scheme in ("http","https")}); out=[]
        db=dict(FAVICON_DB_BUILTIN)
        if self.settings.CVE_FAVICON_DB:
            try:
                with open(self.settings.CVE_FAVICON_DB,"r") as f: db.update(json.load(f))
            except Exception: pass
        for root in roots:
            try:
                r=await self.client.get(root); headers={k.lower():v for k,v in r.headers.items()}
            except Exception:
                headers={}
            fav=str(URL(root).with_path("/favicon.ico"))
            try:
                fr=await self.client.get(fav)
                if fr.status_code<400 and fr.content:
                    h=mmh3.hash(fr.content); entry=db.get(str(h))
                    if entry:
                        out.append(FingerprintFinding(endpoint=root, product=entry.get("product","Unknown"), hash=str(h), headers=headers, notes=entry.get("notes","")))
            except Exception: pass
        return out
