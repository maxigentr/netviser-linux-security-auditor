"""Builds the collector script that runs on the target and parses its output."""
import re
from typing import Dict, Iterable, Tuple

from .advisories import CVE_RE

PREFIX = "NVA:"
END_KEY = "__end"
MAX_KEYS = 500
MAX_VALUE = 400

PRELUDE = r'''#!/bin/sh
# Netviser Linux Security Auditor collector. POSIX sh, read-only.
# Facts are printed as "NVA:key=value"; every other line is ignored.
LC_ALL=C; export LC_ALL
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH:/snap/bin; export PATH
nv_kv() { printf 'NVA:%s=' "$1"; printf '%s' "$2" | tr '\r\n\t' '   '; printf '\n'; }
nv_have() { command -v "$1" >/dev/null 2>&1; }
nv_sysctl() { if [ -r "/proc/sys/$1" ]; then cat "/proc/sys/$1" 2>/dev/null; else echo unavailable; fi; }
NV_UID="$(id -u 2>/dev/null)"
nv_kv uid "${NV_UID:-unknown}"
'''

_KEY_RE = re.compile(r"^[A-Za-z0-9_.]{1,64}$")
# C0/C1 control characters: values end up in terminals and CSV files.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def build_script(checks: Iterable, sample_interval: int = 0, cves: Iterable[str] = ()) -> str:
    cves = list(cves)
    for cve in cves:
        # Interpolated into the script: only strictly formatted ids are accepted.
        if not CVE_RE.match(cve):
            raise ValueError("invalid CVE id: %r" % cve)
    parts = [PRELUDE, "NV_SAMPLE_INTERVAL=%d" % int(sample_interval),
             "NV_CVES='%s'" % " ".join(cves)]
    for check in checks:
        if check.collector:
            parts.append("# --- check: %s ---" % check.id)
            parts.append(check.collector.strip("\n"))
    parts.append("nv_kv %s 1" % END_KEY)
    parts.append("exit 0\n")
    return "\n".join(parts)


def sanitize(value: str) -> str:
    return _CTRL_RE.sub("", value).strip()[:MAX_VALUE]


def parse_output(text: str) -> Tuple[Dict[str, str], bool]:
    """Return (facts, complete). Output from the target is untrusted."""
    facts = {}
    complete = False
    for line in text.splitlines():
        if not line.startswith(PREFIX) or "=" not in line:
            continue
        key, value = line[len(PREFIX):].split("=", 1)
        if not _KEY_RE.match(key):
            continue
        if key == END_KEY:
            complete = True
            continue
        if key not in facts and len(facts) >= MAX_KEYS:
            continue
        facts[key] = sanitize(value)
    return facts, complete
