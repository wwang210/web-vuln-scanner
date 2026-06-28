# Web Vulnerability Scanner

A lightweight Python CLI tool that crawls a target website and automatically checks for common web security vulnerabilities. Built for educational use, authorized penetration testing, and CTF challenges.

---

## ⚠️ Legal Disclaimer

> **Only scan systems you own or have explicit written authorization to test.**
>
> Scanning a website without permission may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction — even if no data is modified. Always obtain written authorization before testing any system you do not personally own.

---

## Features

| Check | Technique |
|-------|-----------|
| **Reflected XSS** | Injects probe payloads into parameters; detects if raw tags are echoed back unescaped |
| **SQL Injection** | Error-based (DB error string matching) + boolean-blind indicator (response size diff) |
| **Open Redirect** | Detects redirect-style parameters that follow off-domain `3xx` responses |
| **CORS Misconfiguration** | Probes for origin reflection + `Access-Control-Allow-Credentials: true` |

---

## How It Works

### Phase 1 — Crawl

The crawler starts at your target URL and BFS-spiders all same-origin pages (never follows off-site links). For each page it collects:
- URL query parameters from discovered links
- Form action URLs, methods (GET/POST), and input field names

### Phase 2 — Scan

Each check module receives the full list of discovered endpoints and iterates over every parameter:

**XSS** — Sends payloads like `<script>xss_probe</script>` and `"><img src=x onerror=probe>` into each parameter and checks whether the raw unescaped tag appears in the HTML response.

**SQLi** — Two detection strategies:
- *Error-based*: injects `'`, `"`, `\\` and scans for known database error strings (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- *Boolean-blind indicator*: compares response size for a true condition (`' OR '1'='1'`) vs. a false one (`' OR '1'='2'`) — a significant difference suggests an injectable parameter

**Open Redirect** — Looks for parameters named `next`, `redirect`, `return_url`, `goto`, etc., injects an external canary URL, and checks if the server issues a `3xx` pointing off-domain.

**CORS** — Sends requests with crafted `Origin` headers (`evil.example.com`, `null`, `evil.your-target.com`) and flags responses where the server echoes back the attacker origin with `Access-Control-Allow-Credentials: true`.

### Phase 3 — Report

Findings are color-coded by severity in the terminal and optionally exported as JSON.

```
Target URL
    │
    ▼
Crawler (BFS links + form extraction)
    │
    ▼
Endpoint list [{url, method, params}]
    │
    ├──▶ XSS check
    ├──▶ SQLi check
    ├──▶ Open Redirect check
    └──▶ CORS check
    │
    ▼
Reporter (colored terminal + optional JSON)
```

---

## Installation

**Requirements:** Python 3.10+, pip

```bash
git clone https://github.com/your-username/web-vuln-scanner.git
cd web-vuln-scanner

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

---

## Usage

### Basic scan (all checks)

```bash
python main.py https://your-target.com
```

### Common options

```bash
# Save findings to a JSON report
python main.py https://your-target.com --out report.json

# Run only specific checks
python main.py https://your-target.com --checks xss sqli

# Scan an authenticated session
python main.py https://your-target.com --cookies "session=abc123; csrf=xyz"

# Limit crawl depth and slow down requests
python main.py https://your-target.com --max-pages 30 --delay 0.5

# Skip TLS certificate verification (self-signed certs)
python main.py https://your-target.com --no-verify
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `--checks` | all | Space-separated list: `xss sqli redirect cors` |
| `--max-pages` | `100` | Maximum pages to crawl |
| `--delay` | `0.2` | Seconds between requests |
| `--cookies` | — | Auth cookies as `"name=val; name2=val2"` |
| `--user-agent` | `VulnScanner/1.0` | Custom User-Agent string |
| `--no-verify` | false | Disable TLS certificate validation |
| `--out` | — | Write JSON report to this file path |

---

## Authorized Testing Targets

**Never tested against a site you do not own.** Use one of these legal targets instead:

### Local (Docker — recommended)

```bash
# OWASP Juice Shop — modern, realistic Node.js app
docker run -d -p 3000:3000 bkimminich/juice-shop
python main.py http://localhost:3000

# DVWA — classic PHP app covering XSS, SQLi, CSRF, and more
docker run -d -p 80:80 vulnerables/web-dvwa
python main.py http://localhost:80

# WebGoat — Java/Spring, OWASP-maintained
docker run -d -p 8080:8080 webgoat/goat-and-wolf
python main.py http://localhost:8080
```

### Online labs

- [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-labs) — free browser-based labs, each provides a unique authorized subdomain
- [HackTheBox](https://www.hackthebox.com/) / [TryHackMe](https://tryhackme.com/) — spin up a machine, scan within the VPN
- [OWASP Juice Shop (live demo)](https://juice-shop.herokuapp.com) — publicly hosted, authorized for testing

---

## Project Structure

```
web-vuln-scanner/
├── main.py              # CLI entry point
├── requirements.txt
└── scanner/
    ├── crawler.py       # BFS site crawler
    ├── xss.py           # Reflected XSS detection
    ├── sqli.py          # SQL injection detection
    ├── redirect.py      # Open redirect detection
    ├── cors.py          # CORS misconfiguration detection
    ├── models.py        # Finding / Severity dataclasses
    └── reporter.py      # Terminal + JSON output
```

---

## Example Output

```
Web Vulnerability Scanner
================================================================
  Target : http://localhost:3000
  Checks : cors, redirect, sqli, xss
  Pages  : up to 100
================================================================
  Only use on systems you own or have permission to test.

[*] Crawling http://localhost:3000 ...
    Found 42 pages, 138 endpoints/forms
[*] Running XSS checks ...
    3 finding(s)
[*] Running SQLi checks ...
    2 finding(s)
[*] Running open-redirect checks ...
    1 finding(s)
[*] Running CORS checks ...
    0 finding(s)

================================================================
  Target  : http://localhost:3000
  Pages   : 42
  Elapsed : 38.2s
  Findings: 6
================================================================

  [HIGH]  (3 issues)
  ------------------------------------------------------------
  Reflected XSS
    GET http://localhost:3000/search  param=q
    Payload reflected: "><img src=x onerror=xss_probe_2>

  ...
```

---

## License

MIT — free to use, modify, and distribute. See `LICENSE` for details.
