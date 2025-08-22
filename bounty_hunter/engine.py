from __future__ import annotations
import anyio, httpx, json
import redis.asyncio as redis
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from .config import Settings
from .harvest import harvest_from_targets
from .workflow import WorkflowAnalyzer
from .fuzz import FuzzCoordinator
from .report import ReportWriter
from .llm import LLM
from .redirects import RedirectChecker
from .authchecks import AuthChecker
from .jsminer import JSMiner
from .oob import OOBSSRF
from .signedurls import SignedURLChecker
from .jwtcheck import JWTChecker
from .fingerprinter import Fingerprinter
from .subdomains import enumerate_subdomains
from scripts.diff_scope import diff_scope

console = Console()

async def run_scan(targets_path: Path, outdir: Path, program: str, settings: Settings, template: str = "index"):
    targets = [t.strip() for t in targets_path.read_text().splitlines() if t.strip() and not t.strip().startswith('#')]
    if not targets:
        console.print("[bold red]No targets provided."); return
    outdir = outdir / f"{int(anyio.current_time())}"; outdir.mkdir(parents=True, exist_ok=True)
    limits = httpx.Limits(max_connections=settings.MAX_CONCURRENCY, max_keepalive_connections=settings.MAX_CONCURRENCY)
    timeout = httpx.Timeout(settings.TIMEOUT_S)
    transport = httpx.HTTPTransport(retries=settings.RETRIES)
    async with httpx.AsyncClient(http2=True, limits=limits, timeout=timeout, transport=transport, follow_redirects=False) as client:
        rc = redis.from_url(settings.REDIS_URL, decode_responses=True)

        subs = await enumerate_subdomains(client, targets)
        if subs:
            console.print(f"[cyan]＋[/] Subdomain enumerator discovered [bold]{len(subs)}[/] hosts")
            targets.extend(subs)
        llm = LLM.from_settings(settings)
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as p:
            p.add_task(description="Harvesting endpoints…", total=None)
            harvest_res = await harvest_from_targets(client, targets, settings)
        endpoints = sorted(set(harvest_res.endpoints))

        console.print(f"[green]\u2714[/] Harvested [bold]{len(endpoints)}[/] candidate endpoints")

        analyzer = WorkflowAnalyzer(harvest_res.forms, harvest_res.navigations, llm)
        for wf, issues, llm_notes in await analyzer.analyze():
            if issues or llm_notes:
                console.print("[yellow]Workflow issues detected:[/]")
                for issue in issues:
                    console.print(f" - {issue}")
                if llm_notes:
                    console.print(f" [LLM] {llm_notes}")
        reporter = ReportWriter(base=outdir, program=program, template=template)
        mined = await JSMiner(client, settings).mine(endpoints)
        if mined:
            console.print(f"[cyan]＋[/] JS miner discovered [bold]{len(mined)}[/] extra candidates"); endpoints.extend(mined)
        endpoints = sorted(set(endpoints))

        # Persist endpoints for this scan and compare with previous scope
        ep_file = outdir / "endpoints.json"
        ep_file.write_text(json.dumps(endpoints, indent=2))
        scope_note = ""
        parent = outdir.parent
        prev_dirs = sorted(
            [d for d in parent.iterdir() if d.is_dir() and d.name.isdigit() and d.name != outdir.name],
            key=lambda p: int(p.name),
        )
        if prev_dirs:
            prev_ep = prev_dirs[-1] / "endpoints.json"
            if prev_ep.exists():
                added, removed = diff_scope(prev_ep, ep_file)
                if added or removed:
                    scope_note = f"+{len(added)}/-{len(removed)} endpoints since last scan"

        await rc.delete(settings.REDIS_QUEUE)
        for i in range(0, len(endpoints), settings.CHUNK_SIZE):
            chunk = endpoints[i:i + settings.CHUNK_SIZE]
            await rc.rpush(settings.REDIS_QUEUE, json.dumps(chunk))

        async def worker():
            while True:
                item = await rc.blpop(settings.REDIS_QUEUE, timeout=1)
                if not item:
                    break
                _, payload = item
                chunk = json.loads(payload)
                await FuzzCoordinator(client=client, llm=llm, reporter=reporter, settings=settings).run(chunk)
                await RedirectChecker(client, reporter, settings).run(chunk)
                await AuthChecker(client, reporter, settings).run(chunk)
                await SignedURLChecker(client, reporter, settings).run(chunk)
                await JWTChecker(client, reporter, settings).run(chunk)
                for fp in await Fingerprinter(client, settings).run(chunk):
                    await reporter.generic_finding(
                        category=f"Fingerprint: {fp.product}",
                        endpoint=fp.endpoint,
                        evidence=f"mmh3={fp.hash} headers={dict(list(fp.headers.items())[:10])}\\n{fp.notes}",
                        curl=f"curl -i '{fp.endpoint}'",
                    )
                if settings.OOB_ENABLED:
                    await OOBSSRF(client, reporter, settings).run(chunk)

        async with anyio.create_task_group() as tg:
            for _ in range(settings.WORKERS):
                tg.start_soon(worker)
        await rc.aclose()
        (outdir/"INDEX.md").write_text(reporter.finish_index(scope_note))
        console.rule("[bold green]Done"); console.print(f"Reports: [bold]{outdir}[/]")
