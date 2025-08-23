"""Canonical signatures used by the fuzzing engine.

Each category contains a list of compiled regular expressions so that new
patterns can be appended over time as they are discovered.  Keeping the
patterns centralised here allows other modules to share the same indicators and
remain backward compatible across branches.
"""

import re

# --- XSS -------------------------------------------------------------------
# The XSS list includes multiple representations of the sentinel value used by
# the scanner when probing for reflected injection points.
XSS_PATTERNS = [
    re.compile(r"BHXSS", re.I),
    re.compile(r"<script[^>]*>BHXSS</script>", re.I),
    re.compile(r"onerror=BHXSS", re.I),
    re.compile(r"\"BHXSS\"", re.I),
]

# --- SQL Injection ---------------------------------------------------------
# Common database error strings as well as generic SQL fragments that tend to
# surface when an injection succeeds.
SQLI_ERRORS = [
    re.compile(r"SQL syntax", re.I),
    re.compile(r"mysql_fetch|PDO|mysqli|ORA-\d+|PostgreSQL|SQLite", re.I),
    re.compile(r"SQLSTATE\[HY000\]", re.I),
    re.compile(r"UNION(?:\s+ALL)?\s+SELECT", re.I),
]

# --- Server-Side Template Injection ---------------------------------------
SSTI_PATTERNS = [
    re.compile(r"BHSTI", re.I),
    re.compile(r"7\s*\*\s*7", re.I),
    re.compile(r"{{\s*7\s*\*\s*7\s*}}", re.I),
]

# Responses taking longer than this threshold (in seconds) are flagged as
# potential time-based vulnerabilities (e.g. time-based SQLi).
RESPONSE_TIME_THRESHOLD = 5.0

