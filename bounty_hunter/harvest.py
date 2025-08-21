from __future__ import annotations
import asyncio, httpx
from bs4 import BeautifulSoup
from yarl import URL
from .utils import URL_RE, uniq
from .workflow import Form, Navigation, HarvestResult

async def harvest_from_targets(client: httpx.AsyncClient, targets: list[str], settings) -> HarvestResult:
    sem = asyncio.Semaphore(settings.MAX_CONCURRENCY)

    async def fetch(url: str) -> str | None:
        try:
            async with sem:
                r = await client.get(url)
                ct = r.headers.get("content-type", "")
                if r.status_code < 400 and (
                    "text/" in ct or "javascript" in ct or "json" in ct
                ):
                    return r.text
        except Exception:
            return None
        return None

    async def one(target: str) -> tuple[list[str], list[Form], list[Navigation]]:
        urls: list[str] = []
        forms: list[Form] = []
        navs: list[Navigation] = []
        base = str(URL(target))
        robots = str(URL(base).with_path("/robots.txt"))
        html = await fetch(robots)
        if html:
            urls.extend(URL_RE.findall(html))
        html = await fetch(base)
        if html:
            urls.extend(URL_RE.findall(html))
            soup = BeautifulSoup(html, "lxml")
            # navigation links
            for tag in soup.find_all("a"):
                v = tag.get("href")
                if v and isinstance(v, str):
                    try:
                        u = str(URL(v)) if v.startswith("http") else str(URL(base) / v)
                        urls.append(u)
                        navs.append(
                            Navigation(source=base, target=u, text=tag.get_text(strip=True) or None)
                        )
                    except Exception:
                        pass
            # other resources
            for tag in soup.find_all(["script", "link", "img"]):
                for attr in ("href", "src"):
                    v = tag.get(attr)
                    if v and isinstance(v, str):
                        try:
                            u = str(URL(v)) if v.startswith("http") else str(URL(base) / v)
                            urls.append(u)
                        except Exception:
                            pass
            # forms
            for form in soup.find_all("form"):
                action = form.get("action") or base
                method = (form.get("method") or "get").lower()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name and isinstance(name, str):
                        inputs.append(name)
                try:
                    action_url = (
                        str(URL(action)) if action.startswith("http") else str(URL(base) / action)
                    )
                except Exception:
                    action_url = action
                urls.append(action_url)
                forms.append(Form(url=base, action=action_url, method=method, inputs=inputs))
        for p in [
            "/login",
            "/signin",
            "/admin",
            "/api/",
            "/api/v1/",
            "/.well-known/security.txt",
            "/.well-known/change-password",
        ]:
            urls.append(str(URL(base).with_path(p)))
        return uniq(urls), forms, navs

    res = await asyncio.gather(*(one(t) for t in targets))
    all_urls: list[str] = []
    all_forms: list[Form] = []
    all_navs: list[Navigation] = []
    for u, f, n in res:
        all_urls.extend(u)
        all_forms.extend(f)
        all_navs.extend(n)
    return HarvestResult(endpoints=all_urls, forms=all_forms, navigations=all_navs)
