import re

# Multiple regex patterns for each category of indicator. These lists can be
# extended over time as new signatures are discovered.
XSS_PATTERNS=[
    re.compile(r"BHXSS",re.I),
    re.compile(r"<script[^>]*>BHXSS</script>",re.I),
]

SQLI_ERRORS=[
    re.compile(r"SQL syntax",re.I),
    re.compile(r"mysql_fetch|PDO|mysqli|ORA-\d+|PostgreSQL|SQLite",re.I),
    re.compile(r"SQLSTATE\[HY000\]",re.I),
]

SSTI_PATTERNS=[
    re.compile(r"BHSTI",re.I),
    re.compile(r"7\s*\*\s*7",re.I),
]

# Responses taking longer than this threshold (in seconds) will be flagged as
# potential time based vulnerabilities.
RESPONSE_TIME_THRESHOLD=5
