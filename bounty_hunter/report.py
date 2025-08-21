from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from slugify import slugify
from jinja2 import Environment, DictLoader, select_autoescape
from cvss import CVSS3
from .llm import LLM

def calculate_cvss(vector: str) -> tuple[float, str]:
    try:
        c = CVSS3(vector)
        score = c.scores()[0]
        severity = c.severities()[0]
        return score, severity
    except Exception:
        return 0.0, ""

TEMPLATES = {
    "index": """# {{ title }}\n\n{% for item in items %}- [{{ item.name }}]({{ item.filename }}) — {{ item.category }} ({{ item.severity or 'TBD' }})\n{% endfor %}\n""",
    "h1": """# {{ title }} (HackerOne)\n\n**Program:** {{ program }}\n\n{% for item in items %}---\n## {{ loop.index }}. {{ item.category }} — {{ item.name }}\n**Endpoint:** `{{ item.endpoint }}`\n**Severity:** {{ item.severity or 'TBD' }}{% if item.score %} (CVSS {{ item.score }}){% endif %}\n\n**Steps to Reproduce**\n```bash\n{{ item.curl }}\n```\n{% if item.headers %}**Request Headers**\n```http\n{{ item.headers }}\n```\n{% endif %}{% if item.body %}**Request Body**\n```http\n{{ item.body }}\n```\n{% endif %}**Evidence (truncated)**\n```text\n{{ item.evidence }}\n```\n{% if item.artifact %}{{ item.artifact }}\n{% endif %}**Impact**\n{{ item.impact or 'Pending triage' }}\n\n**Remediation**\n- Validate and sanitize inputs; secure defaults.\n\n{% endfor %}\n""",
    "synack": """# {{ title }} (Synack)\n\n**Engagement:** {{ program }}\n\n{% for item in items %}### {{ loop.index }}. {{ item.category }} — {{ item.name }}\n- Endpoint: `{{ item.endpoint }}`\n- Severity: {{ item.severity or 'TBD' }}{% if item.score %} (CVSS {{ item.score }}){% endif %}\n- Repro:\n```bash\n{{ item.curl }}\n```\n{% if item.headers %}- Headers:\n```http\n{{ item.headers }}\n```\n{% endif %}{% if item.body %}- Body:\n```http\n{{ item.body }}\n```\n{% endif %}- Evidence:\n```text\n{{ item.evidence }}\n```\n{% if item.artifact %}  {{ item.artifact }}\n{% endif %}- Impact: {{ item.impact or 'Pending' }}\n\n{% endfor %}\n""",
}

env = Environment(loader=DictLoader(TEMPLATES), autoescape=select_autoescape())

@dataclass
class ReportWriter:
    base: Path
    program: str
    template: str = "index"

    def _dir(self) -> Path:
        d = self.base
        d.mkdir(parents=True, exist_ok=True)
        return d

    async def write_finding(self, f, llm: LLM):
        name = slugify(f.category + " " + f.url)[:120]
        path = self._dir() / f"{name}.md"
        impact = (
            await llm.summarize_risk(
                f"URL: {f.url}\nMethod: {f.method}\nEvidence:\n{getattr(f,'evidence','')[:1000]}"
            )
            if llm
            else ""
        )
        vector = getattr(f, "cvss", "")
        score, severity = calculate_cvss(vector) if vector else (0.0, "")
        headers = getattr(f, "headers", "")
        body = getattr(f, "body", "")
        artifact = self._artifact_snippet(name)
        md = f"""# {f.category}

**Program:** {self.program}
**Endpoint:** `{f.url}`
**Method:** `{f.method}`
{f"**Severity:** {severity}\n**CVSS Score:** {score}\n**CVSS Vector:** `{vector}`\n" if severity else ""}## Proof of Concept
```bash
{getattr(f,'curl','')}
```
{f"## Request Headers\n```http\n{headers}\n```\n" if headers else ""}{f"## Request Body\n```http\n{body}\n```\n" if body else ""}## Evidence (Truncated)
```text
{getattr(f,'evidence','')}
```
{(artifact + '\n') if artifact else ''}## Impact (Concise)
{impact or 'Pending triage.'}

## Remediation Hints
- Sanitize inputs, parameterize queries, encode output.
- Harden SSRF with allowlists and metadata protections.
"""
        path.write_text(md)

    async def generic_finding(
        self,
        category: str,
        endpoint: str,
        evidence: str,
        curl: str,
        headers: str = "",
        body: str = "",
        cvss_vector: str = "",
    ):
        name = slugify(category + " " + endpoint)[:120]
        path = self._dir() / f"{name}.md"
        score, severity = calculate_cvss(cvss_vector) if cvss_vector else (0.0, "")
        artifact = self._artifact_snippet(name)
        md = f"""# {category}

**Program:** {self.program}
**Endpoint:** `{endpoint}`
{f"**Severity:** {severity}\n**CVSS Score:** {score}\n**CVSS Vector:** `{cvss_vector}`\n" if severity else ""}## Proof of Concept
```bash
{curl}
```
{f"## Request Headers\n```http\n{headers}\n```\n" if headers else ""}{f"## Request Body\n```http\n{body}\n```\n" if body else ""}## Evidence (Truncated)
```text
{evidence}
```
{(artifact + '\n') if artifact else ''}
"""
        path.write_text(md)

    def finish_index(self) -> str:
        files = sorted([f for f in self._dir().glob("*.md") if f.name != "INDEX.md"])
        items = []
        for f in files:
            txt = f.read_text(errors="ignore")
            first = txt.splitlines()[0].lstrip("# ").strip() if txt else f.stem
            items.append(
                {
                    "name": f.stem,
                    "filename": f.name,
                    "category": first,
                    "endpoint": self._extract_field(txt, "Endpoint:"),
                    "curl": self._extract_block(txt, "Proof of Concept"),
                    "headers": self._extract_block(txt, "Request Headers"),
                    "body": self._extract_block(txt, "Request Body"),
                    "evidence": self._extract_block(txt, "Evidence"),
                    "impact": self._extract_section(txt, "Impact"),
                    "severity": self._extract_field(txt, "Severity:"),
                    "score": self._extract_field(txt, "CVSS Score:"),
                    "artifact": self._artifact_snippet(f.stem),
                }
            )
        tpl = env.get_template(self.template if self.template in TEMPLATES else "index")
        return tpl.render(
            title=f"Findings Index — {self.program}", items=items, program=self.program
        )

    @staticmethod
    def _extract_field(txt: str, key: str) -> str:
        for line in txt.splitlines():
            if line.strip().startswith(key):
                return line.split(key, 1)[-1].strip().strip("`").strip()
        return ""

    @staticmethod
    def _extract_block(txt: str, header: str) -> str:
        if header.lower() in txt.lower():
            parts = txt.split("```")
            if len(parts) >= 3:
                return parts[1].strip()[:600]
        return ""

    @staticmethod
    def _extract_section(txt: str, header: str) -> str:
        i = txt.lower().find(header.lower())
        return "" if i == -1 else txt[i : i + 400]

    @staticmethod
    def _artifact_snippet(slug: str) -> str:
        d = Path("artifacts")
        if not d.exists():
            return ""
        for ext in (".png", ".jpg", ".jpeg", ".gif", ".txt", ".log"):
            p = d / f"{slug}{ext}"
            if p.exists():
                if ext in (".png", ".jpg", ".jpeg", ".gif"):
                    return f"![]({p.as_posix()})"
                else:
                    txt = p.read_text(errors="ignore")[:600]
                    return f"```{ext.lstrip('.')}\n{txt}\n```"
        return ""
