from __future__ import annotations
from dataclasses import dataclass
from .config import Settings

@dataclass
class LLM:
    provider: str = "none"
    openai_client: object | None = None
    model: str | None = None
    @classmethod
    def from_settings(cls, s: Settings) -> "LLM":
        if s.LLM_PROVIDER=="openai" and s.OPENAI_API_KEY:
            try:
                import openai
                client=openai.OpenAI(api_key=s.OPENAI_API_KEY)
                return cls(provider="openai", openai_client=client, model=s.OPENAI_MODEL)
            except Exception:
                return cls(provider="none")
        return cls(provider="none")
    async def advise_payloads(self, context: str) -> list[str]:
        if self.provider!="openai" or not self.openai_client: return []
        prompt=(
            "Suggest 5 safe, non-destructive payload mutations for XSS/SQLi/SSTI/SSRF based on context. Return JSON list only.\n"+context
        )
        try:
            resp=self.openai_client.chat.completions.create(model=self.model or "gpt-4o-mini",messages=[{"role":"user","content":prompt}],temperature=0.3)
            import json; arr=json.loads(resp.choices[0].message.content.strip()); return [str(x) for x in arr if isinstance(x,str)]
        except Exception: return []
    async def summarize_risk(self, evidence: str) -> str:
        if self.provider!="openai" or not self.openai_client: return ""
        prompt=("Draft a concise, accurate impact summary (3-5 sentences).\nEvidence:\n"+evidence)
        try:
            resp=self.openai_client.chat.completions.create(model=self.model or "gpt-4o-mini",messages=[{"role":"user","content":prompt}],temperature=0.2)
            return resp.choices[0].message.content.strip()
        except Exception: return ""
