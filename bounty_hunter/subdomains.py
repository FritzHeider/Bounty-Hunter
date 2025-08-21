from __future__ import annotations
import asyncio, httpx
from yarl import URL

async def enumerate_subdomains(client: httpx.AsyncClient, targets: list[str]) -> list[str]:
    """Enumerate subdomains for the given targets using open data sources.

    Currently queries crt.sh and the bufferover DNS database (used by Amass).
    Returns a list of base URLs (https) for discovered subdomains.
    """
    sem = asyncio.Semaphore(20)
    found: set[str] = set()

    async def crt(domain: str) -> None:
        url = "https://crt.sh/"
        params = {"q": f"%.{domain}", "output": "json"}
        try:
            async with sem:
                r = await client.get(url, params=params, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    for entry in data:
                        for name in entry.get("name_value", "").split("\n"):
                            n = name.strip().lower()
                            if n and "*" not in n and n.endswith(domain):
                                found.add(n)
        except Exception:
            pass

    async def bufferover(domain: str) -> None:
        url = "https://dns.bufferover.run/dns"
        params = {"q": domain}
        try:
            async with sem:
                r = await client.get(url, params=params, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    for rec in data.get("FDNS_A", []) + data.get("RDNS", []):
                        host = rec.split(",")[-1].strip().lower()
                        if host and host.endswith(domain):
                            found.add(host)
        except Exception:
            pass

    domains = {URL(t).host for t in targets if URL(t).host}
    await asyncio.gather(*(crt(d) for d in domains), *(bufferover(d) for d in domains))
    return [str(URL.build(scheme="https", host=d)) for d in sorted(found)]
