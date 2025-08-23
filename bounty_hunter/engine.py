from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

import anyio
import httpx
import redis.asyncio as redis
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
from .access_control import AccessControl
from .fingerprinter import Fingerprinter
from .subdomains import enumerate_subdomains
from scripts.diff_scope import diff_scope

console = Console()


async def run_scan(
    targets_path: Path,
    outdir: Path,
    program: str,
    settings: Settings,
    template: str = "index",
    resume: bool = False,
    modules: Optional[Dict[str, bool]] = None,
) -> None:
    """
    Orchestrates a scan:
      - (optional) subdomain enum
      - harvest endpoints
      - (optional) workflow analysis
      - (optional) JS mining for more endpoints
      - queue endpoints in Redis and process with enabled modules
      - persist state for resume and record scope diff

    `modules` keys you can toggle (default True):
      subdomains, workflow, jsminer, fuzz, redirects, auth, signedurls,
      jwt, access_control, fingerprint, oob
    """
    modules = {
        "subdomains": True,
        "workflow": True,
        "jsminer": True,
        "fuzz": True,
        "redirects": True,
        "auth": True,
        "signedurls": True,
        "jwt": True,
        "access_control": True,
        "fingerprint": True,
        "oob": settings.OOB_ENABLED,  # honor global default
        **(modules or {}),
    }

    state_file = outdir / "state.json"

    # Read targets
    targets = [
        t.strip()
        for t in targets_path.read_text().splitlines()
        if t.strip() and not t.strip().startswith("#")
    ]
    if not targets:
        console.print("[bold red]No targets provided.")
        return

    # Prepare output directory (fresh vs resume)
    if not resume:
        outdir = outdir / f"{int(anyio.current_time())}"
        outdir.mkdir(parents=True, exist_ok=True)
    else:
        if not outdir.exists() or not state_file.exists():
            console.print("[bold red]State file not found for resume.")
            return

    limits = httpx.Limits(
        max_connections=settings.MAX_CONCURRENCY,
        max_keepalive_connections=settings.MAX_CONCURRENCY,
    )
    timeout = httpx.Timeout(settings.TIMEOUT_S)
    transport = httpx.HTTPTransport(retries=settings.RETRIES)
    proxies = settings.PROXY_URL or None

    async with httpx.AsyncClient(
        http2=True,
        limits=limits,
        timeout=timeout,
        transport=transport,
        follow_redirects=False,
        proxies=proxies,
    ) as client:
        # Redis
        rc = redis.from_url(settings.REDIS_URL, decode_responses=True)

        # Create LLM + reporter
        llm = LLM.from_settings(settings)
        reporter = ReportWriter(base=outdir, program=program, template=template)

        # Two entry paths: resume (load state) vs fresh (discover endpoints)
        if resume:
            state = json.loads(state_file.read_text())
            endpoints = state.get("endpoints", [])
            progress = int(state.get("progress", 0))
            if not isinstance(endpoints, list):
                console.print("[bold red]Corrupt state: endpoints not a list.")
                return
            console.print(
                f"[yellow]Resuming:[/] {len(endpoints)} endpoints, progress={progress}"
            )
        else:
            # (optional) Subdomain enumeration
            subs: list[str] = []
            if modules["subdomains"]:
                subs = await enumerate_subdomains(client, targets)
                if subs:
                    console.print(
                        f"[cyan]＋[/] Subdomain enumerator discovered "
                        f"[bold]{len(subs)}[/] hosts"
                    )
                # Extend scan targets with discovered subs
                all_targets = targets + subs
            else:
                all_targets = targets

            # Harvest endpoints (forms, navigations, URLs)
            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}")
            ) as p:
                p.add_task(description="Harvesting endpoints…", total=None)
                harvest_res = await harvest_from_targets(client, all_targets, settings)

            endpoints = sorted(set(harvest_res.endpoints + subs))

            console.print(
                f"[green]\u2714[/] Harvested [bold]{len(endpoints)}[/] candidate endpoints"
            )

            # (optional) Workflow analyzer
            if modules["workflow"]:
                analyzer = WorkflowAnalyzer(
                    harvest_res.forms, harvest_res.navigations, llm
                )
                for wf, issues, llm_notes in await analyzer.analyze():
                    if issues or llm_notes:
                        console.print("[yellow]Workflow issues detected:[/]")
                        for issue in issues:
                            console.print(f" - {issue}")
                        if llm_notes:
                            console.print(f" [LLM] {llm_notes}")

            # (optional) JS miner
            if modules["jsminer"]:
                mined = await JSMiner(client, settings).mine(endpoints)
                if mined:
                    console.print(
                        f"[cyan]＋[/] JS miner discovered [bold]{len(mined)}[/] extra candidates"
                    )
                    endpoints.extend(mined)

            endpoints = sorted(set(endpoints))

            # Persist initial state
            state = {"endpoints": endpoints, "progress": 0}
            state_file.write_text(json.dumps(state, indent=2))
            progress = 0

        # Persist endpoints.json and compute scope diff versus previous scan dir
        ep_file = outdir / "endpoints.json"
        ep_file.write_text(json.dumps(endpoints, indent=2))
        scope_note = ""
        parent = outdir.parent
        prev_dirs = sorted(
            [
                d
                for d in parent.iterdir()
                if d.is_dir() and d.name.isdigit() and d.name != outdir.name
            ],
            key=lambda p: int(p.name),
        )
        if prev_dirs:
            prev_ep = prev_dirs[-1] / "endpoints.json"
            if prev_ep.exists():
                added, removed = diff_scope(prev_ep, ep_file)
                if added or removed:
                    scope_note = f"+{len(added)}/-{len(removed)} endpoints since last scan"

        # Reset queue for this run
        await rc.delete(settings.REDIS_QUEUE)

        # Chunk endpoints into Redis list
        for i in range(progress, len(endpoints), settings.CHUNK_SIZE):
            chunk = endpoints[i : i + settings.CHUNK_SIZE]
            await rc.rpush(settings.REDIS_QUEUE, json.dumps(chunk))

        progress_lock = anyio.Lock()

        async def worker() -> None:
            nonlocal progress
            # Module runners (respect toggles)
            while True:
                item = await rc.blpop(settings.REDIS_QUEUE, timeout=1)
                if not item:
                    break
                _, payload = item
                chunk = json.loads(payload)

                # Fuzzing
                if modules["fuzz"]:
                    await FuzzCoordinator(
                        client=client, llm=llm, reporter=reporter, settings=settings
                    ).run(chunk)

                # Redirects
                if modules["redirects"]:
                    await RedirectChecker(client, reporter, settings).run(chunk)

                # Auth checks
                if modules["auth"]:
                    await AuthChecker(client, reporter, settings).run(chunk)

                # Signed URLs
                if modules["signedurls"]:
                    await SignedURLChecker(client, reporter, settings).run(chunk)

                # JWT checks
                if modules["jwt"]:
                    await JWTChecker(client, reporter, settings).run(chunk)

                # Access control
                if modules["access_control"]:
                    await AccessControl(client, reporter, settings).run(chunk)

                # Fingerprinter
                if modules["fingerprint"]:
                    for fp in await Fingerprinter(client, settings).run(chunk):
                        await reporter.generic_finding(
                            category=f"Fingerprint: {fp.product}",
                            endpoint=fp.endpoint,
                            evidence=(
                                f"mmh3={fp.hash} headers="
                                f"{dict(list(fp.headers.items())[:10])}\n{fp.notes}"
                            ),
                            curl=f"curl -i '{fp.endpoint}'",
                        )

                # OOB SSRF
                if modules["oob"]:
                    await OOBSSRF(client, reporter, settings).run(chunk)

                # Progress/state update
                async with progress_lock:
                    progress += len(chunk)
                    state["progress"] = progress
                    state_file.write_text(json.dumps(state, indent=2))

        # Fan out workers
        async with anyio.create_task_group() as tg:
            for _ in range(settings.WORKERS):
                tg.start_soon(worker)

        await rc.aclose()

        # Finish index markdown and print final location
        (outdir / "INDEX.md").write_text(reporter.finish_index(scope_note))
        console.rule("[bold green]Done")
        console.print(f"Reports: [bold]{outdir}[/]")
