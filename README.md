# AI Bug Bounty Hunter

Async recon → endpoint harvest → fuzz → AI triage → Markdown reports.

**Use only on authorized scope.** Defaults are non-destructive.

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m bounty_hunter scan --targets scope.txt --program "Acme BBP" --template h1
```

## Environment

Set `BH_ADAPTIVE_RATE=true` to enable adaptive throttling when many requests error.
