"""Debian (dpkg) and RPM version comparison, ported from the reference C code.

Plain string or "natural" comparison gets distribution versions wrong
(``5.15.0-101`` vs ``5.15.0-99``, ``~`` pre-releases, epochs, backports), so
patch status must be decided with the package manager's own algorithm.
Both functions return a negative number, zero or a positive number.
"""
import re

_DIGITS = "0123456789"
_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


# --- dpkg (lib/dpkg/version.c) ---

def _dpkg_order(c):
    if not c or c in _DIGITS:
        return 0
    if c in _ALPHA:
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and a[i] not in _DIGITS) or (j < len(b) and b[j] not in _DIGITS):
            ac = _dpkg_order(a[i] if i < len(a) else "")
            bc = _dpkg_order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and j < len(b) and a[i] in _DIGITS and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i] in _DIGITS:
            return 1
        if j < len(b) and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_parse(version):
    version = version.strip()
    epoch = 0
    if ":" in version:
        head, version = version.split(":", 1)
        epoch = int(head) if head.isdigit() else 0
    upstream, _, revision = version.rpartition("-")
    if not upstream:
        upstream, revision = revision, ""
    return epoch, upstream, revision


def dpkg_compare(a, b):
    ea, ua, ra = _dpkg_parse(a)
    eb, ub, rb = _dpkg_parse(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# --- RPM (rpmio/rpmvercmp.c) ---

def _is_alnum(c):
    return c in _DIGITS or c in _ALPHA


def rpmvercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _is_alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _is_alnum(b[j]) and b[j] not in "~^":
            j += 1

        # "~" sorts before everything, even the end of the string.
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue

        # "^" sorts after the end of the string but before everything else.
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue

        if not (i < len(a) and j < len(b)):
            break

        charset = _DIGITS if a[i] in _DIGITS else _ALPHA
        i2, j2 = i, j
        while i2 < len(a) and a[i2] in charset:
            i2 += 1
        while j2 < len(b) and b[j2] in charset:
            j2 += 1
        seg_a, seg_b = a[i:i2], b[j:j2]
        if not seg_b:
            # Different segment types: numeric is newer than alpha.
            return 1 if charset is _DIGITS else -1
        if charset is _DIGITS:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return len(seg_a) - len(seg_b)
        if seg_a != seg_b:
            return -1 if seg_a < seg_b else 1
        i, j = i2, j2

    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


_EVR_RE = re.compile(r"^(?:(?P<epoch>\d+|\(none\)):)?(?P<version>[^-]+)(?:-(?P<release>.+))?$")


def parse_evr(evr):
    """Split ``[epoch:]version[-release]``; ``(none)`` epochs (old rpm) become 0."""
    m = _EVR_RE.match(evr.strip())
    if not m:
        raise ValueError("invalid EVR: %r" % evr)
    epoch = m.group("epoch")
    return (int(epoch) if epoch and epoch.isdigit() else 0,
            m.group("version"), m.group("release") or "")


def rpm_compare(a, b):
    ea, va, ra = parse_evr(a)
    eb, vb, rb = parse_evr(b)
    if ea != eb:
        return ea - eb
    return rpmvercmp(va, vb) or rpmvercmp(ra, rb)
