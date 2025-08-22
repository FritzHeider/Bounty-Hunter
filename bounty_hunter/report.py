from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple, Dict, Any, List, Set
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

from slugify import slugify
from jinja2 import Environment, DictLoader, select_autoescape

try:
    from cvss import CVSS3  # pip install cvss
except Exception:  # soft-dep fallback
    CVSS3 = None  # type: ignore

from .llm import LLM
from .chain_analyzer import ChainAnalyzer


def calculate_cvss(vector: str) -> Tuple[float, str]:
    """
    Parse a CVSS v3 vector and return (score, severity).
    Returns (0.0, "") on parse errors or if cvss lib is missing.
    """
    try:
        if not vector or CVSS3 is None:
            return 0.0, ""
        c = CVSS3(vector)
        score = float(c.scores()[0])  # base score
        severity = str(c.severities()[0])
        return score, severity
    except Exception:
        return 0.0, ""


TEMPLATES: Dict[str, str] = {
    "index": (
        "# {{ title }}\n\n"
        "{% for item in items %}- [{{ item.name }}]({{ item.filename }}) — "
        "{{ item.category }} ({{ item.severity or 'TBD' }})\n{% endfor %}\n"
        "{% if chains %}## Chained Recommendations\n"
        "{% for c in chains %}- {{ c }}\n{% endfor %}\n{% endif %}"
    ),
    "h1": (
        "# {{ title }} (HackerOne)\n\n"
        "**Program:** {{ program }}\n\n"
        "{% for item in items %}---\n"
        "## {{ loop.index }}. {{ item.category }} — {{ item.name }}\n"
        "**Endpoint:** `{{ item.endpoint }}`\n"
        "**Severity:** {{ item.severity or 'TBD' }}{% if item.score %} (CVSS {{ item.score }}){% endif %}\n\n"
        "**Steps to Reproduce**\n```bash\n{{ item.curl }}\n```\n"
        "{% if item.headers %}**Request Headers**\n```http\n{{ item.headers }}\n```\n{% endif %}"
        "{% if item.body %}**Request Body**\n```http\n{{ item.body }}\n```\n{% endif %}"
        "**Evidence (truncated)**\n```text\n{{ item.evidence }}\n```\n"
        "{% if item.artifact %}{{ item.artifact }}\n{% endif %}"
        "**Impact**\n{{ item.impact or 'Pending triage' }}\n\n"
        "**Remediation**\n- Validate and sanitize inputs; secure defaults.\n\n"
        "{% endfor %}\n"
    ),
    "synack": (
        "# {{ title }} (Synack)\n\n"
        "**Engagement:** {{ program }}\n\n"
        "{% for item in items %}### {{ loop.index }}. {{ item.category }} — {{ item.name }}\n"
        "- Endpoint: `{{ item.endpoint }}`\n"
        "- Severity: {{ item.severity or 'TBD' }}{% if item.score %} (CVSS {{ item.score }}){% endif %}\n"
        "- Repro:\n```bash\n{{ item.curl }}\n```\n"
        "{% if item.headers %}- Headers:\n```http\n{{ item.headers }}\n```\n{% endif %}"
        "{% if item.body %}- Body:\n```http\n{{ item.body }}\n```\n{% endif %}"
        "- Evidence:\n```text\n{{ item.evidence }}\n```\n"
        "{% if item.artifact %}  {{ item.artifact }}\n{% endif %}"
        "- Impact: {{ item.impact or 'Pending' }}\n\n"
        "{% endfor %}\n"
    ),
}

# Markdown, not HTML — default autoescape only triggers for html/xml names.
env = Environment(loader=DictLoader(TEMPLATES), autoescape=select_autoescape())


@dataclass
class ReportWriter:
    base: Path
    program: str
    template: str = "index"
    graph: Dict[str, Set[str]] = field(default_factory=dict)

    def _dir(self) -> Path:
        d = self.base
        d.mkdir(parents=True, exist_ok=True)
        return d

    async def write_finding(self, f: Any, llm: LLM) -> None:
        """
        Emit a single finding markdown file based on a 'Finding'-ish object.
        Expected attributes on f: url, method, category, evidence, curl,
        headers?, body?, confidence?, cvss?
        """
        # Stable, filesystem-safe name
        stem = slugify(f"{getattr(f, 'category', 'finding')} {getattr(f, 'url', '')}")[:120] or "finding"
        path = self._dir() / f"{stem}.md"

        # LLM risk summary (best-effort)
        try:
            prompt = (
                f"URL: {getattr(f,'url','')}\n"
                f"Method: {getattr(f,'method','')}\n"
                f"Evidence:\n{getattr(f,'evidence','')[:1000]}"
            )
            impact = await llm.summarize_risk(prompt) if llm else ""
        except Exception:
            impact = ""

        # CVSS
        vector = getattr(f, "cvss", "") or ""
        score, severity = calculate_cvss(vector) if vector else (0.0, "")

        # Optional fields
        headers = getattr(f, "headers", "") or ""
        body = getattr(f, "body", "") or ""
        confidence = float(getattr(f, "confidence", 0.0))

        artifact = self._artifact_snippet(stem)

        cvss_block = (
            f"**Severity:** {severity}\n**CVSS Score:** {score:.1f}\n**CVSS Vector:** `{vector}`\n"
            if severity
            else ""
        )

        md = (
            f"# {getattr(f,'category','Finding')}\n\n"
            f"**Program:** {self.program}\n"
            f"**Endpoint:** `{getattr(f,'url','')}`\n"
            f"**Method:** `{getattr(f,'method','')}`\n"
            f"**Confidence:** {confidence:.2f}\n"
            f"{cvss_block}"
            f"## Proof of Concept\n```bash\n{getattr(f,'curl','')}\n```\n"
            f"{f'## Request Headers\n```http\n{headers}\n```\n' if headers else ''}"
            f"{f'## Request Body\n```http\n{body}\n```\n' if body else ''}"
            f"## Evidence (Truncated)\n```text\n{getattr(f,'evidence','')}\n```\n"
            f"{(artifact + '\n') if artifact else ''}"
            f"## Impact (Concise)\n{impact or 'Pending triage.'}\n\n"
            f"## Remediation Hints\n"
            f"- Sanitize inputs, parameterize queries, encode output.\n"
            f"- Harden SSRF with allowlists and metadata protections.\n"
        )
        path.write_text(md, encoding="utf-8")

    async def generic_finding(
        self,
        category: str,
        endpoint: str,
        evidence: str,
        curl: str,
        headers: str = "",
        body: str = "",
        cvss_vector: str = "",
    ) -> None:
        """
        Create a finding file from raw fields (no LLM involvement).
        """
        stem = slugify(f"{category} {endpoint}")[:120] or "finding"
        path = self._dir() / f"{stem}.md"
        score, severity = calculate_cvss(cvss_vector) if cvss_vector else (0.0, "")
        artifact = self._artifact_snippet(stem)
        cvss_block = (
            f"**Severity:** {severity}\n**CVSS Score:** {score:.1f}\n**CVSS Vector:** `{cvss_vector}`\n"
            if severity
            else ""
        )

        md = (
            f"# {category}\n\n"
            f"**Program:** {self.program}\n"
            f"**Endpoint:** `{endpoint}`\n"
            f"{cvss_block}"
            f"## Proof of Concept\n```bash\n{curl}\n```\n"
            f"{f'## Request Headers\n```http\n{headers}\n```\n' if headers else ''}"
            f"{f'## Request Body\n```http\n{body}\n```\n' if body else ''}"
            f"## Evidence (Truncated)\n```text\n{evidence}\n```\n"
            f"{(artifact + '\n') if artifact else ''}"
        )
        path.write_text(md, encoding="utf-8")

    def finish_index(self) -> str:
        """
        Render an index for all findings in the directory (excluding INDEX.md).
        Returns the markdown string (caller may choose to write it).
        """
        files = sorted([f for f in self._dir().glob("*.md") if f.name != "INDEX.md"])
        items: List[Dict[str, str]] = []
        for fpath in files:
            txt = fpath.read_text(errors="ignore", encoding="utf-8")
            first = txt.splitlines()[0].lstrip("# ").strip() if txt else fpath.stem
            items.append(
                {
                    "name": fpath.stem,
                    "filename": fpath.name,
                    "category": first,
                    "endpoint": self._extract_field(txt, "Endpoint:"),
                    "curl": self._extract_block(txt, "Proof of Concept"),
                    "headers": self._extract_block(txt, "Request Headers"),
                    "body": self._extract_block(txt, "Request Body"),
                    "evidence": self._extract_block(txt, "Evidence"),
                    "impact": self._extract_section(txt, "Impact"),
                    "severity": self._extract_field(txt, "Severity:"),
                    "score": self._extract_field(txt, "CVSS Score:"),
                    "artifact": self._artifact_snippet(fpath.stem),
                }
            )
        # Build a graph linking findings with shared parameters or endpoints
        param_map: Dict[str, Set[str]] = defaultdict(set)
        path_map: Dict[str, Set[str]] = defaultdict(set)
        for item in items:
            endpoint = item.get("endpoint", "")
            if not endpoint:
                continue
            parsed = urlparse(endpoint)
            if parsed.path:
                path_map[parsed.path].add(item["name"])
            for p in parse_qs(parsed.query).keys():
                param_map[p].add(item["name"])

        graph: Dict[str, Set[str]] = {item["name"]: set() for item in items}
        for names in list(param_map.values()) + list(path_map.values()):
            for src in names:
                graph[src].update(names - {src})
        self.graph = graph

        # Analyze potential exploit chains
        chains = ChainAnalyzer(graph, items).suggest()

        tpl = env.get_template(self.template if self.template in TEMPLATES else "index")
        return tpl.render(
            title=f"Findings Index — {self.program}",
            items=items,
            program=self.program,
            chains=chains,
        )

    # Optional convenience: write the index file to disk.
    def write_index(self) -> Path:
        content = self.finish_index()
        out = self._dir() / "INDEX.md"
        out.write_text(content, encoding="utf-8")
        return out

    # ----------------- helpers -----------------

    @staticmethod
    def _extract_field(txt: str, key: str) -> str:
        for line in txt.splitlines():
            if line.strip().startswith(key):
                return line.split(key, 1)[-1].strip().strip("`").strip()
        return ""

    @staticmethod
    def _extract_block(txt: str, header: str) -> str:
        """
        Naive code-fence grab: returns the first fenced block after the header label.
        """
        loc = txt.lower().find(header.lower())
        if loc == -1:
            return ""
        segment = txt[loc:]
        parts = segment.split("```")
        if len(parts) >= 3:
            return parts[1].strip()[:600]
        return ""

    @staticmethod
    def _extract_section(txt: str, header: str) -> str:
        i = txt.lower().find(header.lower())
        return "" if i == -1 else txt[i : i + 400]

    @staticmethod
    def _artifact_snippet(slug: str) -> str:
        """
        If artifacts/<slug>.(png|jpg|jpeg|gif|txt|log) exists, inline a snippet.
        """
        d = Path("artifacts")
        if not d.exists():
            return ""
        for ext in (".png", ".jpg", ".jpeg", ".gif", ".txt", ".log"):
            p = d / f"{slug}{ext}"
            if p.exists():
                if ext in (".png", ".jpg", ".jpeg", ".gif"):
                    return f"![]({p.as_posix()})"
                try:
                    txt = p.read_text(errors="ignore", encoding="utf-8")[:600]
                except Exception:
                    txt = p.read_bytes()[:600].decode("utf-8", errors="ignore")
                return f"```{ext.lstrip('.')}\n{txt}\n```"
        return ""
