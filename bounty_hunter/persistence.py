"""Utilities for optional persistence checks.

This module exposes helper functions that allow other parts of the
project to non-destructively check whether configuration files or
directories are writable and to store a minimal nonce file for verifying
persistence across runs.

All helpers are safe by default: they do not modify existing files
unless explicitly asked to create a nonce file.  The nonce helpers write
very small files containing a random token that can be removed after the
check has completed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Tuple
import os
import uuid


def is_writable(path: str | Path) -> bool:
    """Return True if ``path`` is writable without modifying it.

    The check is non-destructive and will fall back to the parent
    directory when ``path`` does not yet exist.
    """
    p = Path(path)
    target = p if p.exists() else p.parent
    try:
        return os.access(target, os.W_OK)
    except OSError:
        return False


def check_writable(paths: Iterable[str | Path]) -> dict[str, bool]:
    """Check a collection of paths for writability.

    Parameters
    ----------
    paths:
        Paths to examine.  Each entry may point to a file or directory.

    Returns
    -------
    Mapping of the original path (string representation) to a boolean
    indicating writability.
    """
    return {str(p): is_writable(p) for p in paths}


def write_nonce(directory: str | Path, name: str = "bh.nonce", nonce: str | None = None) -> Tuple[Path, str]:
    """Write a minimal nonce file into ``directory``.

    ``directory`` will be created if it does not already exist.  A newly
    generated UUID4 string is used when ``nonce`` is not supplied.

    Returns the path to the nonce file along with the value written.
    """
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    if nonce is None:
        nonce = uuid.uuid4().hex
    nonce_path = d / name
    nonce_path.write_text(nonce)
    return nonce_path, nonce


def read_nonce(path: str | Path) -> str | None:
    """Read a nonce file and return its contents or ``None`` if missing."""
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def verify_nonce(path: str | Path, expected: str) -> bool:
    """Verify that ``path`` contains ``expected`` nonce value."""
    return read_nonce(path) == expected

__all__ = [
    "is_writable",
    "check_writable",
    "write_nonce",
    "read_nonce",
    "verify_nonce",
]
