"""
Reflected XSS detection: injects payloads into GET/POST parameters and checks
whether the raw payload is echoed back in the response body unescaped.
"""

import time
import requests

from .models import Finding, Severity

# Payloads that produce a distinctive marker if reflected unencoded.
# These are detection probes, not exploit payloads.
PAYLOADS = [
    '<script>xss_probe_1</script>',
    '"><img src=x onerror=xss_probe_2>',
    "';alert(xss_probe_3)//",
    '<svg/onload=xss_probe_4>',
]

# We only care whether the raw tag/event-handler syntax survives in the HTML.
MARKERS = [
    "<script>xss_probe_1</script>",
    'onerror=xss_probe_2',
    "';alert(xss_probe_3)",
    "<svg/onload=xss_probe_4>",
]


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


def scan(session: requests.Session, endpoints: list[dict], delay: float = 0.2) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple] = set()

    for ep in endpoints:
        params = ep["params"] if ep["method"] == "GET" else ep["data"]
        for param in params:
            for payload, marker in zip(PAYLOADS, MARKERS):
                resp = _inject(session, ep, param, payload, delay)
                if resp is None:
                    continue

                ct = resp.headers.get("Content-Type", "")
                if "html" not in ct:
                    continue

                if marker.lower() in resp.text.lower():
                    key = (ep["url"], param, ep["method"])
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            vuln_type="Reflected XSS",
                            severity=Severity.HIGH,
                            url=ep["url"],
                            parameter=param,
                            evidence=f"Payload reflected: {payload[:60]}",
                            method=ep["method"],
                        ))
                    break  # one confirmed finding per param is enough

    return findings
