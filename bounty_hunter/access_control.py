from __future__ import annotations
import asyncio, httpx, jwt
from yarl import URL

ADMIN_GUESSES=["/admin","/dashboard","/manage","/settings","/api/admin"]
USER_TEMPLATES=["/api/users/{id}","/users/{id}","/api/user/{id}","/user/{id}","/account/{id}","/profile/{id}"]

class AccessControl:
    def __init__(self, client: httpx.AsyncClient, reporter, settings):
        self.client=client; self.reporter=reporter; self.settings=settings
        self.sem=asyncio.Semaphore(getattr(settings,"MAX_CONCURRENCY",40))
    async def run(self,endpoints:list[str]):
        tokens=getattr(self.settings,"ROLE_TOKENS",{}) or {}
        if not tokens: return
        roots=sorted({str(URL(u).with_path("/")) for u in endpoints if URL(u).scheme in ("http","https")})
        for root in roots:
            await self._vertical(root,tokens)
            await self._horizontal(root,tokens)
    async def _vertical(self,root:str,tokens:dict[str,str]):
        for guess in ADMIN_GUESSES:
            url=str(URL(root).with_path(guess))
            for role,token in tokens.items():
                try:
                    async with self.sem:
                        r=await self.client.get(url,headers={"Authorization":f"Bearer {token}"})
                    if r.status_code<400 and "admin" not in role.lower():
                        ev=f"Role '{role}' accessed admin path (status {r.status_code})"
                        curl=f"curl -i -H 'Authorization: Bearer {token}' '{url}'"
                        await self.reporter.generic_finding("Potential Vertical Privilege Escalation",url,ev,curl)
                except Exception:
                    continue
    async def _horizontal(self,root:str,tokens:dict[str,str]):
        ids:dict[str,str]={}
        for role,token in tokens.items():
            try:
                payload=jwt.decode(token,options={"verify_signature":False})
                uid=payload.get("sub") or payload.get("id") or payload.get("user_id")
                if uid: ids[role]=str(uid)
            except Exception:
                continue
        if len(ids)<2: return
        for tmpl in USER_TEMPLATES:
            for role,token in tokens.items():
                for other,oid in ids.items():
                    if other==role: continue
                    url=str(URL(root).with_path(tmpl.format(id=oid)))
                    try:
                        async with self.sem:
                            r=await self.client.get(url,headers={"Authorization":f"Bearer {token}"})
                        if r.status_code<400:
                            ev=f"Role '{role}' accessed resource of '{other}' (status {r.status_code})"
                            curl=f"curl -i -H 'Authorization: Bearer {token}' '{url}'"
                            await self.reporter.generic_finding("Potential Horizontal Privilege Escalation",url,ev,curl)
                    except Exception:
                        continue
