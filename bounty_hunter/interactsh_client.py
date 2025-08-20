from __future__ import annotations
import httpx
from dataclasses import dataclass
@dataclass
class InteractshClient:
    base: str; token: str|None=None; poll_seconds: int=8
    async def register(self, client: httpx.AsyncClient)->dict:
        r=await client.post(f"{self.base.rstrip('/')}\/register", json={}); r.raise_for_status(); return r.json()
    async def poll(self, client: httpx.AsyncClient, correlation_id: str, secret: str)->list[dict]:
        params={"id":correlation_id, "secret":secret};
        if self.token: params["token"]=self.token
        r=await client.get(f"{self.base.rstrip('/')}\/poll", params=params); r.raise_for_status(); data=r.json();
        return data.get("data", []) if isinstance(data, dict) else []
