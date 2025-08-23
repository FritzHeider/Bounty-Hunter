"""Payload mutation helpers.

This module centralises routines used to fuzz payloads sent during
vulnerability discovery.  Variants help bypass naive filters by tweaking
case, encoding and by inserting special characters.
"""

from __future__ import annotations

import base64
import random
import urllib.parse
from typing import List

# Characters occasionally useful to sneak past unsanitised concatenation.
SPECIAL_CHARS = ['"', "'", ';', '|', '&']


def random_case(text: str) -> str:
    """Return ``text`` with randomised character casing."""

    return "".join(
        ch.upper() if random.random() > 0.5 else ch.lower() for ch in text
    )


def percent_encode_random(text: str) -> str:
    """Percent–encode a random selection of characters from ``text``."""

    out: List[str] = []
    for ch in text:
        if ch.isalnum() or random.random() > 0.5:
            out.append(ch)
        else:
            out.append(f"%{ord(ch):02x}")
    return "".join(out)


def insert_special(text: str) -> str:
    """Insert a random special character at a random position in ``text``."""

    char = random.choice(SPECIAL_CHARS)
    pos = random.randint(0, len(text))
    return text[:pos] + char + text[pos:]


def _encode_alt(text: str) -> list[str]:
    """Generate alternative encodings for ``text``."""

    quoted = urllib.parse.quote(text, safe="")
    double_quoted = urllib.parse.quote(quoted, safe="")
    b64 = base64.b64encode(text.encode()).decode()
    return [quoted, double_quoted, b64]


def generate_variants(probe: str) -> list[str]:
    """Return a collection of mutated forms of ``probe``.

    Variants include random casing, percent-encoding of random characters,
    insertion of special characters and a set of alternate encodings.
    """

    variants = {
        probe,
        random_case(probe),
        percent_encode_random(probe),
        insert_special(probe),
    }
    variants.update(_encode_alt(probe))
    return list(variants)


def alternate_encodings(probe: str) -> list[str]:
    """Return encodings used when a probe appears to be blocked."""

    return _encode_alt(probe)


__all__ = [
    "generate_variants",
    "alternate_encodings",
    "random_case",
    "percent_encode_random",
    "insert_special",
]

