#!/usr/bin/env bash
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then echo "python3 not found"; exit 1; fi
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
echo "Bootstrap complete. Try:  python -m bounty_hunter scan --targets scope.txt --program 'Acme'"
