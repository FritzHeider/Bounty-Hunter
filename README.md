# AI Bug Bounty Hunter

Async recon → endpoint harvest → fuzz → AI triage → Markdown reports.

**Use only on authorized scope.** Defaults are non-destructive.

## Prerequisites

- Python 3.11 or newer
- (Optional) OpenAI API key if using AI triage (`OPENAI_API_KEY`)
- (Optional) Redis instance for background task queue
- (Optional) Proxy, Tor or VPN for network anonymity (see [docs/OPSEC.md](docs/OPSEC.md))

## Installation

```bash
git clone https://example.com/Bounty-Hunter.git
cd Bounty-Hunter
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root to override defaults:

```bash
OPENAI_API_KEY=sk-...
BH_ADAPTIVE_RATE=true                # Adjust rate when errors spike
BH_PROXY_URL=socks5://127.0.0.1:9050 # Route traffic through Tor/VPN
```

Other tunables such as timeouts and concurrency can be set via
environment variables (see `bounty_hunter/config.py`).

## Usage

1. Add one target per line in `scope.txt`.
2. Run a scan:

```bash
python -m bounty_hunter scan \
  --targets scope.txt \
  --program "Acme BBP" \
  --template h1
```

Results are written as Markdown under `artifacts/`.

## Environment

`bounty_hunter` respects the following environment variables:

- `BH_TIMEOUT_S` – HTTP timeout in seconds (default 15)
- `BH_RETRY` – number of retries per request (default 2)
- `BH_MAX_CONCURRENCY` – maximum simultaneous requests (default 40)
- `BH_PER_HOST` – per-host concurrency limit (default 5)
- `BH_ADAPTIVE_RATE` – enable adaptive throttling
- `BH_PROXY_URL` – HTTP/SOCKS proxy URL
- `BH_REDIS_URL` – Redis connection string for task queue
- `BH_REDIS_QUEUE` – name of Redis queue
- `BH_CHUNK_SIZE` – number of targets per task (default 50)
- `BH_WORKERS` – number of worker processes (default 4)

## OPSEC

See [docs/OPSEC.md](docs/OPSEC.md) for tips on routing traffic through
Tor or VPNs before engaging targets.

## Reporting

Findings are written as Markdown. When a CVSS v3 vector is supplied the
reporter calculates the numeric score and severity and injects the values
into templates. Reproduction steps include optional HTTP headers and
request bodies, and if a matching file exists under `artifacts/` it will
be embedded as an image or text snippet in the final report.
