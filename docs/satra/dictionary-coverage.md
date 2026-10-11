# SATRA Security Dictionary Coverage Matrix

This matrix is automatically generated from `backend/satra/dictionary.py` and documents executable vs partial rules across vulnerability families.

| ID | Tier | Family | CWE | Status | Executable Test Path | Runnable Mutant |
|---|---|---|---|---|---|---|
| AUTHZ.IDOR.001 | Tier 1 | Authorization / IDOR | CWE-639 | **FULL** | `trusted_tests/test_authz_idor.py` | Yes |
| INJ.SQL.001 | Tier 1 | SQL Injection | CWE-89 | **FULL** | `trusted_tests/test_sqli.py` | Yes |
| PATH.TRAV.001 | Tier 1 | Path Traversal | CWE-22 | **FULL** | `trusted_tests/test_path_traversal.py` | Yes |
| AUTH.REQ.001 | Tier 1 | Authentication Required | CWE-306 | **FULL** | `trusted_tests/test_auth_required.py` | Yes |
| INJ.CMD.001 | Tier 2 | Command Injection | CWE-78 | **PARTIAL** | *Static / Stub Only* | No |
| DESER.INSEC.001 | Tier 2 | Insecure Deserialization | CWE-502 | **PARTIAL** | *Static / Stub Only* | No |
| SSRF.WEBHOOK.001 | Tier 2 | Server-Side Request Forgery | CWE-918 | **PARTIAL** | *Static / Stub Only* | No |
| XSS.STORED.001 | Tier 2 | Cross-Site Scripting (XSS) | CWE-79 | **PARTIAL** | *Static / Stub Only* | No |
| AUTH.CSRF.001 | Tier 2 | Cross-Site Request Forgery | CWE-352 | **PARTIAL** | *Static / Stub Only* | No |
