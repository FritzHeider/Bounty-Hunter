from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from slugify import slugify
from jinja2 import Environment, DictLoader, select_autoescape
from .llm import LLM

TEMPLATES={
"index": """# {{ title }}\n\n{% for item in items %}- [{{ item.name }}]({{ item.filename }}) — {{ item.category }}\n{% endfor %}\n""",
"h1": """# {{ title }} (HackerOne)\n\n**Program:** {{ program }}\n\n{% for item in items %}---\n## {{ loop.index }}. {{ item.category }} — {{ item.name }}\n**Endpoint:** `{{ item.endpoint }}`\n\n**Steps to Reproduce**\n```
{{ item.curl }}
```\n\n**Evidence (truncated)**\n```
{{ item.evidence }}
```\n\n**Impact**\n{{ item.impact or 'Pending triage' }}\n\n**Remediation**\n- Validate and sanitize inputs; secure defaults.\n\n{% endfor %}\n""",
"synack": """# {{ title }} (Synack)\n\n**Engagement:** {{ program }}\n\n{% for item in items %}### {{ loop.index }}. {{ item.category }} — {{ item.name }}\n- Endpoint: `{{ item.endpoint }}`\n- Repro:\n```
{{ item.curl }}
```\n- Evidence:\n```
{{ item.evidence }}
```\n- Impact: {{ item.impact or 'Pending' }}\n- Severity: TBD\n\n{% endfor %}\n""",
}

env=Environment(loader=DictLoader(TEMPLATES), autoescape=select_autoescape())

@dataclass
class ReportWriter:
    base: Path; program: str; template: str = "index"
    def _dir(self)->Path: d=self.base; d.mkdir(parents=True, exist_ok=True); return d
    async def write_finding(self, f, llm: LLM):
        name=slugify(f.category+" "+f.url)[:120]; path=self._dir()/f"{name}.md"
        impact=await llm.summarize_risk(f"URL: {f.url}\nMethod: {f.method}\nEvidence:\n{getattr(f,'evidence','')[:1000]}") if llm else ""
        md=f"""
# {f.category}

**Program:** {self.program}  
**Endpoint:** `{f.url}`  
**Method:** `{f.method}`

## Proof of Concept
```bash
{getattr(f,'curl','')}
```

## Evidence (Truncated)
```
{getattr(f,'evidence','')}
```

## Impact (Concise)
{impact or 'Pending triage.'}

## Remediation Hints
- Sanitize inputs, parameterize queries, encode output.
- Harden SSRF with allowlists and metadata protections.
"""; path.write_text(md)
    async def generic_finding(self, category: str, endpoint: str, evidence: str, curl: str):
        name=slugify(category+" "+endpoint)[:120]; path=self._dir()/f"{name}.md"
        md=f"""
# {category}

**Program:** {self.program}  
**Endpoint:** `{endpoint}`

## Proof of Concept
```bash
{curl}
```

## Evidence (Truncated)
```
{evidence}
```
"""; path.write_text(md)
    async def finish_index(self, llm: LLM | None = None)->str:
        files=[f for f in self._dir().glob("*.md") if f.name!="INDEX.md"]
        items=[]
        for f in files:
            txt=f.read_text(errors="ignore"); first=txt.splitlines()[0].lstrip('# ').strip() if txt else f.stem
            items.append({
                "name": f.stem, "filename": f.name, "category": first,
                "endpoint": self._extract_field(txt, "Endpoint:"),
                "curl": self._extract_block(txt, "Proof of Concept"),
                "evidence": self._extract_block(txt, "Evidence"),
                "impact": self._extract_section(txt, "Impact"),
            })
        if llm:
            for item in items:
                item["severity"]=await llm.rank_findings(item.get("evidence",""))
            items.sort(key=lambda x: x.get("severity",0), reverse=True)
        else:
            items.sort(key=lambda x: x["name"])
        tpl=env.get_template(self.template if self.template in TEMPLATES else "index")
        return tpl.render(title=f"Findings Index — {self.program}", items=items, program=self.program)
    @staticmethod
    def _extract_field(txt: str, key: str)->str:
        for line in txt.splitlines():
            if line.strip().startswith(key):
                return line.split(key,1)[-1].strip().strip('`').strip()
        return ""
    @staticmethod
    def _extract_block(txt: str, header: str)->str:
        if header.lower() in txt.lower():
            parts=txt.split('```')
            if len(parts)>=3: return parts[1].strip()[:600]
        return ""
    @staticmethod
    def _extract_section(txt: str, header: str)->str:
        i=txt.lower().find(header.lower());
        return "" if i==-1 else txt[i:i+400]
