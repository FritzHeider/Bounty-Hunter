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

console = Console()

async def run_scan(
    targets_path: Path,
    outdir: Path,
    program: str,
    settings: Settings,
    template: str = "index",
    resume: bool = False,
    modules: dict[str, bool] | None = None,
):
    modules = modules or {}
    state_file = outdir / "state.json"

    targets = [t.strip() for t in targets_path.read_text().splitlines() if t.strip() and not t.strip().startswith('#')]
    if not targets:
        console.print("[bold red]No targets provided."); return

    if not resume:
        outdir = outdir / f"{int(anyio.current_time())}"
        outdir.mkdir(parents=True, exist_ok=True)
    else:
        if not outdir.exists() or not state_file.exists():
            console.print("[bold red]State file not found for resume.")
            return

    limits = httpx.Limits(max_connections=settings.MAX_CONCURRENCY, max_keepalive_connections=settings.MAX_CONCURRENCY)
    timeout = httpx.Timeout(settings.TIMEOUT_S)
    transport = httpx.HTTPTransport(retries=settings.RETRIES)
    async with httpx.AsyncClient(http2=True, limits=limits, timeout=timeout, transport=transport, follow_redirects=False) as client:
        rc = redis.from_url(settings.REDIS_URL, decode_responses=True)

        if resume:
            state = json.loads(state_file.read_text())
            endpoints = state.get("endpoints", [])
            progress = state.get("progress", 0)
            llm = LLM.from_settings(settings)
            reporter = ReportWriter(base=outdir, program=program, template=template)
        else:
            subs = []
            if modules.get("subdomains", True):
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

            if modules.get("workflow", True):
                analyzer = WorkflowAnalyzer(harvest_res.forms, harvest_res.navigations, llm)
                for wf, issues, llm_notes in await analyzer.analyze():
                    if issues or llm_notes:
                        console.print("[yellow]Workflow issues detected:[/]")
                        for issue in issues:
                            console.print(f" - {issue}")
                        if llm_notes:
                            console.print(f" [LLM] {llm_notes}")
            reporter = ReportWriter(base=outdir, program=program, template=template)
            mined = []
            if modules.get("jsminer", True):
                mined = await JSMiner(client, settings).mine(endpoints)
            if mined:
                console.print(f"[cyan]＋[/] JS miner discovered [bold]{len(mined)}[/] extra candidates"); endpoints.extend(mined)
            endpoints = sorted(set(endpoints))
            state = {"endpoints": endpoints, "progress": 0}
            state_file.write_text(json.dumps(state, indent=2))
            progress = 0

        await rc.delete(settings.REDIS_QUEUE)
        for i in range(progress, len(endpoints), settings.CHUNK_SIZE):
            chunk = endpoints[i:i + settings.CHUNK_SIZE]
            await rc.rpush(settings.REDIS_QUEUE, json.dumps(chunk))

        progress_lock = anyio.Lock()

        async def worker():
            nonlocal progress
            while True:
                item = await rc.blpop(settings.REDIS_QUEUE, timeout=1)
                if not item:
                    break
                _, payload = item
                chunk = json.loads(payload)
                if modules.get("fuzz", True):
                    await FuzzCoordinator(client=client, llm=llm, reporter=reporter, settings=settings).run(chunk)
                if modules.get("redirects", True):
                    await RedirectChecker(client, reporter, settings).run(chunk)
                if modules.get("auth", True):
                    await AuthChecker(client, reporter, settings).run(chunk)
                if modules.get("signedurls", True):
                    await SignedURLChecker(client, reporter, settings).run(chunk)
                if modules.get("jwt", True):
                    await JWTChecker(client, reporter, settings).run(chunk)
                if modules.get("fingerprint", True):
                    for fp in await Fingerprinter(client, settings).run(chunk):
                        await reporter.generic_finding(
                            category=f"Fingerprint: {fp.product}",
                            endpoint=fp.endpoint,
                            evidence=f"mmh3={fp.hash} headers={dict(list(fp.headers.items())[:10])}\n{fp.notes}",
                            curl=f"curl -i '{fp.endpoint}'",
                        )
                if modules.get("oob", settings.OOB_ENABLED):
                    await OOBSSRF(client, reporter, settings).run(chunk)

                async with progress_lock:
                    progress += len(chunk)
                    state["progress"] = progress
                    state_file.write_text(json.dumps(state, indent=2))

        async with anyio.create_task_group() as tg:
            for _ in range(settings.WORKERS):
                tg.start_soon(worker)
        await rc.aclose()
        (outdir/"INDEX.md").write_text(reporter.finish_index())
        console.rule("[bold green]Done"); console.print(f"Reports: [bold]{outdir}[/]")
