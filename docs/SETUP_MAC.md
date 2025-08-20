# AI Bug Bounty Hunter — Full macOS Setup & Run Guide

(See top-level README for summary.)

1) Install Python 3.11, git, Xcode CLT.
2) `python3.11 -m venv .venv && source .venv/bin/activate`
3) `pip install -r requirements.txt`
4) `cp .env.example .env` and set keys if needed.
5) Add targets to `scope.txt`.
6) Run scanner (see README commands).
