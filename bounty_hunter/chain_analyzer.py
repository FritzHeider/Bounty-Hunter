from __future__ import annotations

from typing import Dict, Set, List


class ChainAnalyzer:
    """Suggest exploit chains based on finding relationships."""

    def __init__(self, graph: Dict[str, Set[str]], items: List[Dict[str, str]]):
        self.graph = graph
        self.items = items
        self.categories = {i["name"]: i.get("category", "").lower() for i in items}

    def suggest(self) -> List[str]:
        """Return simple chain recommendations."""
        suggestions: Set[str] = set()
        for src, targets in self.graph.items():
            src_cat = self.categories.get(src, "")
            for dst in targets:
                dst_cat = self.categories.get(dst, "")
                if self._is_redirect_ssrf(src_cat, dst_cat):
                    suggestions.add(f"{src} → {dst} (redirect → SSRF)")
                elif self._is_redirect_ssrf(dst_cat, src_cat):
                    suggestions.add(f"{dst} → {src} (redirect → SSRF)")
        return sorted(suggestions)

    @staticmethod
    def _is_redirect_ssrf(a: str, b: str) -> bool:
        return "redirect" in a and "ssrf" in b
