"""Placeholder CLI using Typer-like structure.
Swap with the full Typer CLI when ready.
"""
import sys

def app():
    if len(sys.argv) < 2:
        print("Usage: python -m bounty_hunter scan --targets scope.txt --program 'Program'")
        return
    print("[placeholder] CLI invoked:", sys.argv[1:])
