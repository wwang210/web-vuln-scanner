"""
CORS misconfiguration detection:
  - Wildcard ACAO (*) combined with Access-Control-Allow-Credentials: true
  - Origin reflection (arbitrary origin echoed back with credentials allowed)
  - Null-origin allowed with credentials
  - Subdomain/prefix bypass (e.g. evil.target.com accepted)
"""

import time
from urllib.parse import urlparse

import requests

from .models import Finding, Severity

PROBE_ORIGINS = [
    "https://evil.example.com",
    "null",
]


def _get_cors_headers(session: requests.Session, url: str, origin: str, delay: float):
    try:
        resp = session.get(url, headers={"Origin": origin}, timeout=10)
        time.sleep(delay)
        return resp
    except requests.RequestException:
        return None


def scan(session: requests.Session, endpoints: list[dict], delay: float = 0.2) -> list[Finding]:
    findings: list[Finding] = []
    checked_urls: set[str] = set()

    for ep in endpoints:
        url = ep["url"]
        if url in checked_urls:
            continue
        checked_urls.add(url)

        parsed = urlparse(url)
        origin_host = f"{parsed.scheme}://{parsed.netloc}"

        # --- Check 1 + 2: wildcard+credentials and origin reflection ---
        # Both checks share the same probe requests, so we combine them into
        # a single loop to avoid sending duplicate requests per origin.
        for probe_origin in PROBE_ORIGINS:
            resp = _get_cors_headers(session, url, probe_origin, delay)
            if not resp:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*" and acac == "true":
                findings.append(Finding(
                    vuln_type="CORS Misconfiguration",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=None,
                    evidence="Wildcard ACAO (*) with Access-Control-Allow-Credentials: true",
                    method="GET",
                ))
                break

            if acao == probe_origin and acac == "true":
                sev = Severity.CRITICAL if probe_origin == "null" else Severity.HIGH
                findings.append(Finding(
                    vuln_type="CORS Misconfiguration",
                    severity=sev,
                    url=url,
                    parameter=None,
                    evidence=f"Origin '{probe_origin}' reflected in ACAO with credentials allowed",
                    method="GET",
                ))
                break

        # --- Check 3: subdomain/prefix bypass ---
        # e.g. if origin is https://target.com, try https://evil.target.com
        evil_sub = f"{parsed.scheme}://evil.{parsed.netloc}"
        resp = _get_cors_headers(session, url, evil_sub, delay)
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == evil_sub and acac == "true":
                findings.append(Finding(
                    vuln_type="CORS Misconfiguration (subdomain bypass)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=None,
                    evidence=f"Arbitrary subdomain '{evil_sub}' accepted with credentials",
                    method="GET",
                ))

    return findings
