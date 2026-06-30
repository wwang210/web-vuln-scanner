"""
SQL injection detection: injects error-triggering payloads and checks for
database error strings in the response. Also checks for boolean-based
differences (true vs false conditions produce different response lengths).
"""

import time

import requests

from .models import Finding, Severity

ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "' OR '1'='2", "\\", "1; --"]

DB_ERRORS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    # PostgreSQL
    "pg_query()",
    "supplied argument is not a valid postgresql",
    "unterminated quoted string at or near",
    "pg_exec()",
    # MSSQL
    "microsoft sql server",
    "odbc sql server driver",
    "unclosed quotation mark",
    "syntax error converting",
    # Oracle
    "ora-00933",
    "ora-00907",
    "quoted string not properly terminated",
    # SQLite
    "sqlite_",
    "sqlite error",
    "unrecognized token",
    # Generic
    "sql syntax",
    "syntax error",
    "invalid query",
    "jdbc exception",
    "sqlexception",
]

# Boolean-blind probe: true vs false condition — a large body-size difference suggests injection
BOOL_TRUE  = "' OR '1'='1' --"
BOOL_FALSE = "' OR '1'='2' --"


def _inject(session: requests.Session, endpoint: dict, param: str, payload: str, delay: float) -> requests.Response | None:
    url = endpoint["url"]
    method = endpoint["method"]
    try:
        if method == "POST":
            data = {**endpoint["data"], param: payload}
            resp = session.post(url, data=data, timeout=10, allow_redirects=True)
        else:
            params = {**endpoint["params"], param: payload}
            resp = session.get(url, params=params, timeout=10, allow_redirects=True)
        time.sleep(delay)
        return resp
    except requests.RequestException:
        return None


def _has_db_error(text: str) -> str | None:
    lower = text.lower()
    for sig in DB_ERRORS:
        if sig in lower:
            return sig
    return None


def scan(session: requests.Session, endpoints: list[dict], delay: float = 0.2) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple] = set()

    for ep in endpoints:
        params = ep["params"] if ep["method"] == "GET" else ep["data"]
        for param in params:
            key = (ep["url"], param, ep["method"])
            if key in seen:
                continue

            # --- Error-based detection ---
            for payload in ERROR_PAYLOADS:
                resp = _inject(session, ep, param, payload, delay)
                if resp is None:
                    continue
                sig = _has_db_error(resp.text)
                if sig:
                    seen.add(key)
                    findings.append(Finding(
                        vuln_type="SQL Injection (error-based)",
                        severity=Severity.CRITICAL,
                        url=ep["url"],
                        parameter=param,
                        evidence=f"DB error '{sig}' triggered by payload: {payload}",
                        method=ep["method"],
                    ))
                    break

            if key in seen:
                continue

            # --- Boolean-blind detection ---
            resp_true  = _inject(session, ep, param, BOOL_TRUE, delay)
            resp_false = _inject(session, ep, param, BOOL_FALSE, delay)
            if resp_true and resp_false:
                diff = abs(len(resp_true.text) - len(resp_false.text))
                # A significant length difference (>20% of the smaller response) is suspicious
                threshold = max(50, min(len(resp_true.text), len(resp_false.text)) * 0.20)
                if diff > threshold:
                    seen.add(key)
                    findings.append(Finding(
                        vuln_type="SQL Injection (boolean-blind indicator)",
                        severity=Severity.HIGH,
                        url=ep["url"],
                        parameter=param,
                        evidence=f"Response length differs by {diff} bytes between true/false conditions",
                        method=ep["method"],
                    ))

    return findings
