#!/usr/bin/env python3
"""Compare endpoint scopes between scans."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import List, Tuple


def diff_scope(prev: Path, curr: Path) -> Tuple[List[str], List[str]]:
    """Return (added, removed) endpoints comparing prev to curr."""
    prev_set = set(json.loads(prev.read_text())) if prev.exists() else set()
    curr_set = set(json.loads(curr.read_text())) if curr.exists() else set()
    added = sorted(curr_set - prev_set)
    removed = sorted(prev_set - curr_set)
    return added, removed


def main() -> None:
    p = argparse.ArgumentParser(description="Diff two endpoints.json files")
    p.add_argument("previous", type=Path)
    p.add_argument("current", type=Path)
    args = p.parse_args()
    added, removed = diff_scope(args.previous, args.current)
    print(json.dumps({"added": added, "removed": removed}, indent=2))


if __name__ == "__main__":
    main()
