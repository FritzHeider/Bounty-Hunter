import re
XSS_REFLECTION=re.compile(r"BHXSS",re.I)
SQLI_ERRORS=[re.compile(r"SQL syntax",re.I),re.compile(r"mysql_fetch|PDO|mysqli|ORA-\d+|PostgreSQL|SQLite",re.I)]
SSTI_REFLECTION=re.compile(r"BHSTI",re.I)
