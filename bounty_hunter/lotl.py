from __future__ import annotations
from pathlib import Path
import subprocess
from typing import List


def run_chain(commands: List[str]) -> List[subprocess.CompletedProcess[str]]:
    """Execute a sequence of shell commands.

    Each command is executed using the system shell allowing the
    process to leverage existing tooling like ``curl`` or ``wget``.
    The function collects ``CompletedProcess`` results for further
    inspection by callers.
    """
    results: List[subprocess.CompletedProcess[str]] = []
    for cmd in commands:
        if not cmd.strip():
            continue
        results.append(
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
        )
    return results


def run_attack_chain(name: str) -> List[subprocess.CompletedProcess[str]]:
    """Run a predefined attack chain stored under ``scripts/attack_flows``.

    Parameters
    ----------
    name:
        Filename of the chain script relative to the ``scripts/attack_flows``
        directory. Each non-empty, non-comment line in the file is executed
        sequentially via :func:`run_chain`.
    """
    base = Path(__file__).resolve().parent.parent / "scripts" / "attack_flows"
    script = base / name
    if not script.exists():
        raise FileNotFoundError(f"Attack chain '{name}' not found in {base}")
    cmds = [
        line.strip() for line in script.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return run_chain(cmds)
