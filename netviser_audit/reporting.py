"""JSON, CSV and terminal reporting."""
import csv
import datetime
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TextIO

from . import __version__
from .checks.base import INFO, OK, REVIEW, UNKNOWN, Finding

SCOPE = ("Read-only configuration audit. Kernel CVE patch status compares the running kernel "
         "package with vendor advisory data (Ubuntu, Debian, Red Hat); it is not an "
         "exploitability test.")
STATUS_ORDER = {REVIEW: 0, UNKNOWN: 1, INFO: 2, OK: 3}


@dataclass
class HostResult:
    target: str
    status: str  # "ok" or "error"
    facts: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self):
        return {"target": self.target, "status": self.status, "error": self.error,
                "facts": self.facts, "findings": [f.to_dict() for f in self.findings]}

    def finding(self, key):
        return next((f for f in self.findings if f.key == key), None)


def build_report(results, checks, advisories=None):
    report = {
        "tool": {"name": "netviser-linux-security-auditor", "version": __version__},
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": SCOPE,
        "checks": [c.id for c in checks],
    }
    if advisories is not None:
        report["advisories"] = advisories.summary()
    report["results"] = [r.to_dict() for r in results]
    return report


def csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection from target-controlled values."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def csv_columns(checks, results=()) -> List[str]:
    columns = ["target", "status"]
    for check in checks:
        columns += [f for f in check.report_facts if f not in columns]
    for check in checks:
        columns += list(check.finding_keys)
    # Findings without a fixed key, e.g. one "patch.<CVE>" column per CVE.
    for r in results:
        columns += [f.key for f in r.findings if f.key not in columns]
    return columns + ["error"]


def write_csv(stream: TextIO, results, checks):
    columns = csv_columns(checks, results)
    writer = csv.writer(stream)
    writer.writerow(columns)
    for r in results:
        row = []
        for col in columns:
            if col in ("target", "status", "error"):
                value = getattr(r, col)
            elif col in r.facts:
                value = r.facts[col]
            else:
                f = r.finding(col)
                value = "%s:%s" % (f.status, f.verdict) if f else ""
            row.append(csv_safe(value))
        writer.writerow(row)


def write_json(stream: TextIO, report):
    json.dump(report, stream, ensure_ascii=False, indent=2)
    stream.write("\n")


def _verdict(result, key):
    f = result.finding(key)
    return f.verdict if f else "-"


def _patch_summary(result):
    """Most severe patch verdict, with the number of further CVEs."""
    found = [f for f in result.findings if f.key.startswith("patch.")]
    if not found:
        return "-"
    worst = min(found, key=lambda f: STATUS_ORDER.get(f.status, 9))
    return worst.verdict + (" +%d" % (len(found) - 1) if len(found) > 1 else "")


def print_summary(results, stream, verbose=False):
    header = "%-28s %-6s %-26s %-11s %-11s %-15s %s" % (
        "TARGET", "STATUS", "KERNEL", "MIGRATE", "MPTCP", "MPTCP USAGE", "CVE PATCH")
    stream.write(header + "\n" + "-" * len(header) + "\n")
    for r in results:
        stream.write("%-28.28s %-6.6s %-26.26s %-11.11s %-11.11s %-15.15s %s\n" % (
            r.target, r.status, r.facts.get("kernel_release", "-"),
            r.facts.get("tcp_migrate_req", "-"), r.facts.get("mptcp_enabled", "-"),
            _verdict(r, "mptcp.usage"), _patch_summary(r)))
    for r in results:
        if r.error:
            stream.write("\n%s\n  ERROR: %s\n" % (r.target, r.error))
            continue
        shown = [f for f in r.findings if verbose or f.status in (REVIEW, UNKNOWN)]
        if not shown:
            continue
        stream.write("\n%s\n" % r.target)
        for f in sorted(shown, key=lambda f: STATUS_ORDER.get(f.status, 9)):
            stream.write("  [%-7s] %-32s %s\n" % (f.status, f.key, f.title))
            if f.detail and (verbose or f.status == REVIEW):
                stream.write("            %s\n" % f.detail)
