from __future__ import annotations
import json, anyio, httpx
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

async def run_scan(targets_path: Path, outdir: Path, program: str, settings: Settings, template: str = "index", resume: bool = False):
    targets = [t.strip() for t in targets_path.read_text().splitlines() if t.strip() and not t.strip().startswith('#')]
    if not targets:
        console.print("[bold red]No targets provided."); return

    if resume:
        state_path = outdir / "state.json"
        if not state_path.exists():
            console.print("[bold yellow]No cached state found; starting a new scan[/]")
            resume = False
    if not resume:
        outdir = outdir / f"{int(anyio.current_time())}"
        outdir.mkdir(parents=True, exist_ok=True)
        state_path = outdir / "state.json"
    else:
        outdir.mkdir(parents=True, exist_ok=True)

    progress = {
        "harvest": False,
        "jsminer": False,
        "fuzz": False,
        "redirect": False,
        "auth": False,
        "signedurl": False,
        "jwt": False,
        "fingerprint": False,
        "oob": False,
    }
    endpoints: list[str] = []
    if resume:
        data = json.loads(state_path.read_text())
        endpoints = data.get("endpoints", [])
        progress.update(data.get("progress", {}))

    def save_state() -> None:
        state = {"endpoints": endpoints, "progress": progress}
        state_path.write_text(json.dumps(state, indent=2))

    limits = httpx.Limits(max_connections=settings.MAX_CONCURRENCY, max_keepalive_connections=settings.MAX_CONCURRENCY)
    timeout = httpx.Timeout(settings.TIMEOUT_S)
    transport = httpx.HTTPTransport(retries=settings.RETRIES)
    async with httpx.AsyncClient(http2=True, limits=limits, timeout=timeout, transport=transport, follow_redirects=False) as client:
        llm = LLM.from_settings(settings)
        if not progress["harvest"]:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as p:
                p.add_task(description="Harvesting endpoints…", total=None)
                endpoints = await harvest_from_targets(client, targets, settings)
            endpoints = sorted(set(endpoints))
            progress["harvest"] = True
            save_state()
            console.print(f"[green]\u2714[/] Harvested [bold]{len(endpoints)}[/] candidate endpoints")
        else:
            console.print(f"[green]\u2714[/] Loaded [bold]{len(endpoints)}[/] cached endpoints")

        reporter = ReportWriter(base=outdir, program=program, template=template)

        if not progress["jsminer"] and settings.JS_MINER_ENABLED:
            mined = await JSMiner(client, settings).mine(endpoints)
            if mined:
                console.print(f"[cyan]＋[/] JS miner discovered [bold]{len(mined)}[/] extra candidates")
                endpoints.extend(mined)
                endpoints = sorted(set(endpoints))
            progress["jsminer"] = True
            save_state()
        else:
            progress["jsminer"] = True

        if not progress["fuzz"] and settings.FUZZ_ENABLED:
            await FuzzCoordinator(client=client, llm=llm, reporter=reporter, settings=settings).run(endpoints)
        progress["fuzz"] = True
        save_state()

        if not progress["redirect"] and settings.REDIRECTS_ENABLED:
            await RedirectChecker(client, reporter, settings).run(endpoints)
        progress["redirect"] = True
        save_state()

        if not progress["auth"] and settings.AUTHCHECK_ENABLED:
            await AuthChecker(client, reporter, settings).run(endpoints)
        progress["auth"] = True
        save_state()

        if not progress["signedurl"] and settings.SIGNEDURL_ENABLED:
            await SignedURLChecker(client, reporter, settings).run(endpoints)
        progress["signedurl"] = True
        save_state()

        if not progress["jwt"] and settings.JWTCHECK_ENABLED:
            await JWTChecker(client, reporter, settings).run(endpoints)
        progress["jwt"] = True
        save_state()

        if not progress["fingerprint"] and settings.FINGERPRINTER_ENABLED:
            for fp in await Fingerprinter(client, settings).run(endpoints):
                await reporter.generic_finding(
                    category=f"Fingerprint: {fp.product}",
                    endpoint=fp.endpoint,
                    evidence=f"mmh3={fp.hash} headers={dict(list(fp.headers.items())[:10])}\n{fp.notes}",
                    curl=f"curl -i '{fp.endpoint}'",
                )
        progress["fingerprint"] = True
        save_state()

        if settings.OOB_ENABLED and not progress["oob"]:
            await OOBSSRF(client, reporter, settings).run(endpoints)
        progress["oob"] = True
        save_state()

        (outdir / "INDEX.md").write_text(reporter.finish_index())
        console.rule("[bold green]Done"); console.print(f"Reports: [bold]{outdir}[/]")

