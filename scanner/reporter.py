"""
Pretty-prints findings to stdout with color-coded severity, and optionally
writes a machine-readable JSON report.
"""

import json
from datetime import datetime, timezone

from colorama import Fore, Style, init

from .models import Finding, Severity

init(autoreset=True)

_SEV_COLOR = {
    Severity.CRITICAL: Fore.RED + Style.BRIGHT,
    Severity.HIGH:     Fore.RED,
    Severity.MEDIUM:   Fore.YELLOW,
    Severity.LOW:      Fore.CYAN,
    Severity.INFO:     Fore.WHITE,
}


def _sev_str(sev: Severity) -> str:
    return f"{_SEV_COLOR[sev]}[{sev.value}]{Style.RESET_ALL}"


def print_summary(findings: list[Finding], target: str, elapsed: float, pages_crawled: int) -> None:
    print()
    print(Style.BRIGHT + "=" * 64)
    print(f"  Target  : {target}")
    print(f"  Pages   : {pages_crawled}")
    print(f"  Elapsed : {elapsed:.1f}s")
    print(f"  Findings: {len(findings)}")
    print("=" * 64 + Style.RESET_ALL)

    if not findings:
        print(Fore.GREEN + "  No vulnerabilities detected." + Style.RESET_ALL)
        print()
        return

    by_sev: dict[Severity, list[Finding]] = {}
    for f in sorted(findings):
        by_sev.setdefault(f.severity, []).append(f)

    for sev in Severity:
        group = by_sev.get(sev, [])
        if not group:
            continue
        print(f"\n  {_sev_str(sev)}  ({len(group)} issue{'s' if len(group) != 1 else ''})")
        print("  " + "-" * 60)
        for f in group:
            param_str = f"  param={f.parameter}" if f.parameter else ""
            print(f"  {Style.BRIGHT}{f.vuln_type}{Style.RESET_ALL}")
            print(f"    {f.method} {f.url}{param_str}")
            print(f"    {Fore.WHITE}{f.evidence}{Style.RESET_ALL}")
    print()


def write_json(findings: list[Finding], target: str, path: str) -> None:
    report = {
        "target": target,
        "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "total": len(findings),
        "findings": [
            {
                "type": f.vuln_type,
                "severity": f.severity.value,
                "method": f.method,
                "url": f.url,
                "parameter": f.parameter,
                "evidence": f.evidence,
            }
            for f in sorted(findings)
        ],
    }
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"Report written to {path}")
