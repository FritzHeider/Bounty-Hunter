from __future__ import annotations
import asyncio
from pathlib import Path
import typer
from rich.console import Console
from .config import Settings
from .engine import run_scan
from .llm import LLM
from .report import ReportWriter

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
):
    s = Settings()
    if max_concurrency: s.MAX_CONCURRENCY = max_concurrency
    if per_host: s.PER_HOST = per_host
    s.LLM_PROVIDER = llm.lower(); s.OOB_ENABLED = oob
    console.rule("[bold cyan]AI Bug Bounty Hunter")
    console.print(f"Program: [bold]{program}[/] | LLM: [bold]{s.LLM_PROVIDER}[/] | OOB: [bold]{s.OOB_ENABLED}[/]")
    console.print(f"Concurrency: {s.MAX_CONCURRENCY} (per-host {s.PER_HOST})\n")
    asyncio.run(run_scan(targets, outdir, program, s, template=template))

@app.command()
def triage(
    reports: Path = typer.Option(Path("reports"), exists=True, file_okay=False),
    llm: str = typer.Option("none"),
):
    s = Settings(); s.LLM_PROVIDER = llm.lower()
    asyncio.run(_triage(reports, s))

async def _triage(reports: Path, settings: Settings):
    llm = LLM.from_settings(settings)
    path = reports
    if path.is_dir() and not (path/"INDEX.md").exists():
        dirs=[d for d in path.iterdir() if d.is_dir()]
        if dirs:
            path=max(dirs, key=lambda d:d.stat().st_mtime)
    console.rule("[bold cyan]Triage")
    console.print(f"Directory: {path}")
    for f in sorted(path.glob("*.md")):
        if f.name=="INDEX.md":
            continue
        txt=f.read_text()
        if "Pending" not in txt:
            continue
        evidence=ReportWriter._extract_block(txt, "Evidence")
        summary=await llm.summarize_risk(evidence) if llm else ""
        severity=await llm.rank_findings(evidence) if llm else 0
        console.rule(f.name)
        console.print(summary or "[dim]No summary[/]")
        console.print(f"Severity: {severity}/10")
        if typer.confirm("Write summary to file?", default=False):
            new_txt=txt.replace("Pending triage.", summary).replace("Pending triage", summary)
            f.write_text(new_txt)
