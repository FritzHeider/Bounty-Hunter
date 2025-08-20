from __future__ import annotations
import re
from typing import Iterable
URL_RE = re.compile(r"https?://[\w.-]+(?:\:[0-9]+)?(?:/[\w\-./%?#=&+]*)?", re.I)

def uniq(seq: Iterable[str]) -> list[str]:
    seen=set(); out=[]
    for s in seq:
        if s not in seen:
            seen.add(s); out.append(s)
    return out
