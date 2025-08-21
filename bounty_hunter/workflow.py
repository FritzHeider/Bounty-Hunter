from __future__ import annotations
from dataclasses import dataclass
from typing import List
from .llm import LLM

@dataclass
class Form:
    url: str
    action: str
    method: str
    inputs: List[str]

@dataclass
class Navigation:
    source: str
    target: str
    text: str | None = None

@dataclass
class HarvestResult:
    endpoints: List[str]
    forms: List[Form]
    navigations: List[Navigation]

@dataclass
class Workflow:
    steps: List[Form | Navigation]

    def to_prompt(self) -> str:
        lines = []
        for s in self.steps:
            if isinstance(s, Navigation):
                lines.append(f"NAV {s.source} -> {s.target} text={s.text}")
            elif isinstance(s, Form):
                lines.append(
                    f"FORM {s.url} -> {s.action} method={s.method} inputs={s.inputs}"
                )
        return "\n".join(lines)

    def detect_logic_flaws(self) -> List[str]:
        issues: List[str] = []
        for s in self.steps:
            if isinstance(s, Form):
                if s.method.lower() == "get":
                    issues.append(
                        f"Form {s.action} uses GET which may expose sensitive data"
                    )
                if not any("csrf" in i.lower() for i in s.inputs):
                    issues.append(f"Form {s.action} lacks CSRF token field")
        return issues

class WorkflowAnalyzer:
    def __init__(self, forms: List[Form], navigations: List[Navigation], llm: LLM):
        self.forms = forms
        self.navigations = navigations
        self.llm = llm

    def build_workflows(self) -> List[Workflow]:
        wfs: List[Workflow] = []
        for form in self.forms:
            related = [n for n in self.navigations if n.target == form.url]
            steps: List[Form | Navigation] = []
            steps.extend(related)
            steps.append(form)
            wfs.append(Workflow(steps=steps))
        return wfs

    async def analyze(self) -> List[tuple[Workflow, List[str], str]]:
        results: List[tuple[Workflow, List[str], str]] = []
        for wf in self.build_workflows():
            issues = wf.detect_logic_flaws()
            llm_notes = await self.llm.analyze_workflows(wf.to_prompt())
            results.append((wf, issues, llm_notes))
        return results
