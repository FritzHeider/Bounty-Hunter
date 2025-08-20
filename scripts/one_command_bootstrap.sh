#!/usr/bin/env bash
set -euo pipefail
headline(){ printf "\n\033[1;36m==> %s\033[0m\n" "$1"; }
exists(){ command -v "$1" >/dev/null 2>&1; }
headline "AI Bug Bounty Hunter — macOS bootstrap"
if ! exists brew; then
  headline "Homebrew not found — installing (optional)"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  eval "$([ -f /opt/homebrew/bin/brew ] && echo 'eval $(/opt/homebrew/bin/brew shellenv)' || echo 'eval $(/usr/local/bin/brew shellenv)')"
fi
if ! python3.11 -V >/dev/null 2>&1; then
  headline "Installing Python 3.11 via Homebrew"; brew install python@3.11
fi
python3.11 -m venv .venv; source .venv/bin/activate
python -m pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
if [ ! -f .env ]; then cp .env.example .env || true; fi
if [ ! -f scope.txt ]; then echo "https://example.com" > scope.txt; fi
echo "Bootstrap complete."
echo "Run: python -m bounty_hunter scan --targets scope.txt --program 'Acme BBP' --template h1"
