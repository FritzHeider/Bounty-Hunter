from __future__ import annotations
import anyio, httpx
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from .config import Settings
from .harvest import harvest_from_targets
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
        llm = LLM.from_settings(settings)
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as p:
            p.add_task(description="Harvesting endpoints…", total=None)
            endpoints = await harvest_from_targets(client, targets, settings)
        endpoints = sorted(set(endpoints))
        console.print(f"[green]\u2714[/] Harvested [bold]{len(endpoints)}[/] candidate endpoints")
        reporter = ReportWriter(base=outdir, program=program, template=template)
        # JS miner expands scope
        mined = await JSMiner(client, settings).mine(endpoints)
        if mined:
            console.print(f"[cyan]＋[/] JS miner discovered [bold]{len(mined)}[/] extra candidates"); endpoints.extend(mined)
        # Core fuzz
        await FuzzCoordinator(client=client, llm=llm, reporter=reporter, settings=settings).run(endpoints)
        # Targeted checks
        await RedirectChecker(client, reporter, settings).run(endpoints)
        await AuthChecker(client, reporter, settings).run(endpoints)
        await SignedURLChecker(client, reporter, settings).run(endpoints)
        await JWTChecker(client, reporter, settings).run(endpoints)
        # Fingerprints
        for fp in await Fingerprinter(client, settings).run(endpoints):
            await reporter.generic_finding(
                category=f"Fingerprint: {fp.product}",
                endpoint=fp.endpoint,
                evidence=f"mmh3={fp.hash} headers={dict(list(fp.headers.items())[:10])}\\n{fp.notes}",
                curl=f"curl -i '{fp.endpoint}'",
            )
        # OOB SSRF
        if settings.OOB_ENABLED:
            await OOBSSRF(client, reporter, settings).run(endpoints)
        (outdir/"INDEX.md").write_text(reporter.finish_index())
        console.rule("[bold green]Done"); console.print(f"Reports: [bold]{outdir}[/]")
