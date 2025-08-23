from __future__ import annotations
import asyncio
from pathlib import Path
import json
import typer
from rich.console import Console
from .config import Settings
from .engine import run_scan

app = typer.Typer(no_args_is_help=True)
console = Console()

@app.command()
def scan(
    targets: Path = typer.Option(..., exists=True, readable=True),
    outdir: Path = typer.Option(Path("reports")),
    program: str = typer.Option("Unnamed Program"),
    llm: str = typer.Option("none"),
    max_concurrency: int = typer.Option(None),
    per_host: int = typer.Option(None),
    template: str = typer.Option("index"),
    oob: bool = typer.Option(False),
    resume: bool = typer.Option(False, help="Resume from saved state"),
    modules: str = typer.Option("modules.json", help="Module configuration file"),
):
    s = Settings()
    if max_concurrency:
        s.MAX_CONCURRENCY = max_concurrency
    if per_host:
        s.PER_HOST = per_host
    module_flags = {}
    modules_path = Path(modules)
    if modules_path.exists():
        module_flags = json.loads(modules_path.read_text())
    s.LLM_PROVIDER = llm.lower()
    s.OOB_ENABLED = oob or module_flags.get("oob", False)
    console.rule("[bold cyan]AI Bug Bounty Hunter")
    console.print(f"Program: [bold]{program}[/] | LLM: [bold]{s.LLM_PROVIDER}[/] | OOB: [bold]{s.OOB_ENABLED}[/]")
    console.print(f"Concurrency: {s.MAX_CONCURRENCY} (per-host {s.PER_HOST})\n")
    asyncio.run(run_scan(targets, outdir, program, s, template=template, resume=resume, modules=module_flags))
