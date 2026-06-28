#!/usr/bin/env python3
"""
Web Vulnerability Scanner
=========================
Crawls a target site and checks for:
  - Reflected XSS
  - SQL Injection (error-based + boolean-blind indicator)
  - Open Redirects
  - CORS Misconfiguration

Usage:
  python main.py https://example.com
  python main.py https://example.com --checks xss sqli --max-pages 50 --out report.json

IMPORTANT: Only scan systems you own or have explicit written permission to test.
"""

import argparse
import sys
import time

import requests
from colorama import Fore, Style, init

from scanner import cors, redirect, sqli, xss
from scanner.crawler import Crawler
from scanner.models import Finding
from scanner.reporter import print_summary, write_json

init(autoreset=True)

ALL_CHECKS = {"xss", "sqli", "redirect", "cors"}


def build_session(user_agent: str, cookies: str | None, no_verify: bool) -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = user_agent
    session.verify = not no_verify
    if cookies:
        for pair in cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                session.cookies.set(k.strip(), v.strip())
    return session


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Web vulnerability scanner — for authorized testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="Base URL to scan (e.g. https://example.com)")
    parser.add_argument(
        "--checks", nargs="+", choices=sorted(ALL_CHECKS), default=sorted(ALL_CHECKS),
        metavar="CHECK",
        help="Which checks to run (default: all). Choices: xss sqli redirect cors",
    )
    parser.add_argument("--max-pages", type=int, default=100,
                        help="Max pages to crawl (default: 100)")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="Seconds between requests (default: 0.2)")
    parser.add_argument("--cookies", type=str, default=None,
                        help='Session cookies, e.g. "session=abc; csrf=xyz"')
    parser.add_argument("--user-agent", default="VulnScanner/1.0 (educational)",
                        help="HTTP User-Agent header")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable TLS certificate verification")
    parser.add_argument("--out", type=str, default=None,
                        help="Write JSON report to this file path")
    args = parser.parse_args()

    # Sanity-check the target
    if not args.target.startswith(("http://", "https://")):
        print(Fore.RED + "Error: target must start with http:// or https://")
        sys.exit(1)

    print(Style.BRIGHT + "\nWeb Vulnerability Scanner" + Style.RESET_ALL)
    print("=" * 64)
    print(f"  Target : {args.target}")
    print(f"  Checks : {', '.join(sorted(args.checks))}")
    print(f"  Pages  : up to {args.max_pages}")
    print("=" * 64)
    print(Fore.YELLOW + "  Only use on systems you own or have permission to test." + Style.RESET_ALL)
    print()

    session = build_session(args.user_agent, args.cookies, args.no_verify)
    start = time.time()

    # Phase 1: Crawl
    print(f"[*] Crawling {args.target} ...")
    crawler = Crawler(args.target, session, max_pages=args.max_pages, delay=args.delay)
    endpoints = crawler.crawl()
    pages = len(crawler.visited)
    print(f"    Found {pages} pages, {len(endpoints)} endpoints/forms")

    checks = set(args.checks)
    all_findings: list[Finding] = []

    # Phase 2: Run selected checks
    if "xss" in checks:
        print("[*] Running XSS checks ...")
        found = xss.scan(session, endpoints, delay=args.delay)
        print(f"    {len(found)} finding(s)")
        all_findings.extend(found)

    if "sqli" in checks:
        print("[*] Running SQLi checks ...")
        found = sqli.scan(session, endpoints, delay=args.delay)
        print(f"    {len(found)} finding(s)")
        all_findings.extend(found)

    if "redirect" in checks:
        print("[*] Running open-redirect checks ...")
        found = redirect.scan(session, endpoints, delay=args.delay)
        print(f"    {len(found)} finding(s)")
        all_findings.extend(found)

    if "cors" in checks:
        print("[*] Running CORS checks ...")
        found = cors.scan(session, endpoints, delay=args.delay)
        print(f"    {len(found)} finding(s)")
        all_findings.extend(found)

    elapsed = time.time() - start
    print_summary(all_findings, args.target, elapsed, pages)

    if args.out:
        write_json(all_findings, args.target, args.out)


if __name__ == "__main__":
    main()
