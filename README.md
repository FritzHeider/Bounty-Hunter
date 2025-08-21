# AI Bug Bounty Hunter

Async recon → endpoint harvest → fuzz → AI triage → Markdown reports.

**Use only on authorized scope.** Defaults are non-destructive.

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m bounty_hunter scan --targets scope.txt --program "Acme BBP" --template h1
```

## Resuming & Configuration

- Resume a previous scan by pointing `--outdir` to an existing run and adding `--resume`.
- Module behaviour can be controlled via the `.env` file.  Set `BH_FUZZ_ENABLED=false`,
  `BH_JS_MINER_ENABLED=false`, etc. to disable specific modules.
