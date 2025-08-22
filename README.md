# AI Bug Bounty Hunter

Async recon → endpoint harvest → fuzz → AI triage → Markdown reports.

**Use only on authorized scope.** Defaults are non-destructive.

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m bounty_hunter scan --targets scope.txt --program "Acme BBP" --template h1
```

## Reporting

Findings are written as Markdown. When a CVSS v3 vector is supplied the
reporter calculates the numeric score and severity and injects the values
into the templates.  Reproduction steps include optional HTTP headers and
request bodies, and if a matching file exists under `artifacts/` it will be
embedded as an image or text snippet in the final report.
