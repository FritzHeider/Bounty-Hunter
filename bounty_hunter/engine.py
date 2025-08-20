"""Placeholder engine.
Implement run_scan(targets_path, outdir, program, settings, template='index').
"""
from pathlib import Path

def run_scan(targets_path: Path, outdir: Path, program: str, settings, template: str = "index"):
    print("[placeholder] run_scan called:")
    print("  targets:", targets_path)
    print("  outdir:", outdir)
    print("  program:", program)
    print("  template:", template)
    # Create outdir/INDEX.md as a proof the pipeline writes something
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "INDEX.md").write_text("# Findings Index — " + program + "\n\n_No findings (placeholder).\n")
