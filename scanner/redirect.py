"""
Open redirect detection: looks for redirect-style parameter names and checks
whether the server follows a redirect to an external domain.
"""

import time
from urllib.parse import urlparse

import requests

from .models import Finding, Severity

# Common parameter names used for redirect destinations
REDIRECT_PARAMS = {
    "redirect", "redirect_to", "redirect_url", "redirecturl", "redirectUri",
    "redirect_uri", "return", "returnTo", "return_to", "returnUrl", "return_url",
    "next", "url", "goto", "go", "dest", "destination", "target", "ref",
    "referer", "referrer", "forward", "forward_url", "continue", "continueTo",
    "callback", "callback_url", "back", "backurl",
}

# Canary domain — distinctive enough that a redirect here is almost certainly a finding
CANARY = "https://open-redirect-canary.example.com/pwned"
CANARY_HOST = "open-redirect-canary.example.com"


def scan(session: requests.Session, endpoints: list[dict], delay: float = 0.2) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple] = set()

    # Build a no-follow session for this check
    no_follow = requests.Session()
    no_follow.headers = session.headers.copy()
    no_follow.cookies.update(session.cookies)
    no_follow.verify = session.verify

    for ep in endpoints:
        all_params = {**ep["params"], **ep["data"]}
        for param, _ in all_params.items():
            if param.lower() not in {p.lower() for p in REDIRECT_PARAMS}:
                continue

            key = (ep["url"], param)
            if key in seen:
                continue

            try:
                if ep["method"] == "POST":
                    data = {**ep["data"], param: CANARY}
                    resp = no_follow.post(ep["url"], data=data, timeout=10, allow_redirects=False)
                else:
                    params = {**ep["params"], param: CANARY}
                    resp = no_follow.get(ep["url"], params=params, timeout=10, allow_redirects=False)
                time.sleep(delay)
            except requests.RequestException:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                loc_host = urlparse(location).netloc
                if loc_host and loc_host != urlparse(ep["url"]).netloc:
                    seen.add(key)
                    findings.append(Finding(
                        vuln_type="Open Redirect",
                        severity=Severity.MEDIUM,
                        url=ep["url"],
                        parameter=param,
                        evidence=f"Redirects to external host: {location[:80]}",
                        method=ep["method"],
                    ))

    return findings
