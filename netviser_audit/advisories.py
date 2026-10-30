"""Vendor security advisory data for kernel CVEs: fetching, normalising, caching.

Only CVE identifiers are sent to the vendors' public APIs; nothing about the
audited hosts leaves the controller. Records are reduced to the kernel source
packages and the fields patch evaluation needs, so they can be saved with
``--save-advisories`` and reused offline with ``--advisories``.
"""
import datetime
import json
import re
import urllib.error
import urllib.request
from typing import Callable, Dict, Iterable, Optional

from . import __version__
from .versions import rpm_compare

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
FORMAT = 1
MAX_BYTES = 32 * 1024 * 1024

SOURCES = {
    "ubuntu": "https://ubuntu.com/security/cves/{cve}.json",
    "debian": "https://api.osv.dev/v1/vulns/DEBIAN-{cve}",
    "redhat": "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json",
}
VENDORS = tuple(SOURCES)
RHEL_PACKAGES = ("kernel", "kernel-rt")

_RH_CPE_RE = re.compile(r"^cpe:/[ao]:redhat:enterprise_linux:(\d+)(?:$|:)")
_RH_PKG_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.+-]+?)-(?P<evr>\d+:[^-:\s]+-[^-:\s]+)$")
_DEBIAN_ECO_RE = re.compile(r"^Debian:(\d+)$")


class AdvisoryError(Exception):
    pass


def _str(value):
    return value if isinstance(value, str) else ""


def _list(value):
    return value if isinstance(value, list) else []


def _dict(value):
    return value if isinstance(value, dict) else {}


def normalize_ubuntu(doc):
    """{"packages": {source: {codename: [status, version]}}}"""
    packages = {}
    for pkg in _list(_dict(doc).get("packages")):
        name = _str(_dict(pkg).get("name"))
        if not name.startswith("linux"):
            continue
        releases = {}
        for s in _list(pkg.get("statuses")):
            s = _dict(s)
            codename = _str(s.get("release_codename"))
            if codename:
                releases[codename] = [_str(s.get("status")), _str(s.get("description"))]
        packages[name] = releases
    return {"found": True, "packages": packages}


def normalize_debian(doc):
    """OSV record. {"packages": {source: {major: ["fixed", version] | ["unfixed", ""]}}}"""
    packages = {}
    for affected in _list(_dict(doc).get("affected")):
        pkg = _dict(_dict(affected).get("package"))
        m = _DEBIAN_ECO_RE.match(_str(pkg.get("ecosystem")))
        name = _str(pkg.get("name"))
        if not m or not name.startswith("linux"):
            continue
        fixed = ""
        for rng in _list(affected.get("ranges")):
            for event in _list(_dict(rng).get("events")):
                fixed = _str(_dict(event).get("fixed")) or fixed
        packages.setdefault(name, {})[m.group(1)] = ["fixed", fixed] if fixed else ["unfixed", ""]
    return {"found": True, "packages": packages}


def normalize_redhat(doc):
    """{"packages": {name: {major: {"fixed": "E:V-R", "state": "..."}}}}

    Only the main RHEL streams are kept; EUS/AUS/TUS/E4S streams are ignored.
    When several errata fix the CVE in one stream, the earliest fix wins.
    """
    doc = _dict(doc)
    packages = {}
    for rel in _list(doc.get("affected_release")):
        rel = _dict(rel)
        cpe = _RH_CPE_RE.match(_str(rel.get("cpe")))
        pkg = _RH_PKG_RE.match(_str(rel.get("package")))
        if not cpe or not pkg or pkg.group("name") not in RHEL_PACKAGES:
            continue
        entry = packages.setdefault(pkg.group("name"), {}).setdefault(cpe.group(1), {})
        evr = pkg.group("evr")
        if "fixed" not in entry or rpm_compare(evr, entry["fixed"]) < 0:
            entry["fixed"] = evr
            entry["advisory"] = _str(rel.get("advisory"))
    for state in _list(doc.get("package_state")):
        state = _dict(state)
        cpe = _RH_CPE_RE.match(_str(state.get("cpe")))
        name = _str(state.get("package_name"))
        if cpe and name in RHEL_PACKAGES:
            packages.setdefault(name, {}).setdefault(cpe.group(1), {})["state"] = \
                _str(state.get("fix_state"))
    return {"found": True, "packages": packages}


NORMALIZERS = {"ubuntu": normalize_ubuntu, "debian": normalize_debian,
               "redhat": normalize_redhat}


def fetch_json(url, timeout=20.0):
    """Return the decoded JSON document, or None when the vendor has no record (404)."""
    request = urllib.request.Request(url, headers={
        "User-Agent": "netviser-audit/%s" % __version__, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise AdvisoryError("HTTP %d from %s" % (exc.code, url))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise AdvisoryError("%s: %s" % (url, getattr(exc, "reason", exc)))
    if len(body) > MAX_BYTES:
        raise AdvisoryError("response from %s is too large" % url)
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        raise AdvisoryError("invalid JSON from %s" % url)


class AdvisoryDB:
    """Normalised advisory records keyed by CVE id and vendor."""

    def __init__(self):
        self.records: Dict[str, Dict[str, dict]] = {}
        self.errors: Dict[str, str] = {}  # "CVE/vendor" -> message

    def get(self, cve, vendor) -> Optional[dict]:
        return self.records.get(cve, {}).get(vendor)

    def error(self, cve, vendor) -> Optional[str]:
        return self.errors.get("%s/%s" % (cve, vendor))

    def fetch(self, cves: Iterable[str], vendors: Iterable[str],
              fetcher: Callable = fetch_json, log=None):
        """Fetch records that are not loaded yet. Failures are recorded, not raised."""
        for cve in cves:
            for vendor in vendors:
                if self.get(cve, vendor) is not None:
                    continue
                url = SOURCES[vendor].format(cve=cve)
                if log:
                    log("Fetching %s advisory data for %s" % (vendor, cve))
                try:
                    doc = fetcher(url)
                    record = {"found": False} if doc is None else NORMALIZERS[vendor](doc)
                except AdvisoryError as exc:
                    self.errors["%s/%s" % (cve, vendor)] = str(exc)
                    continue
                record["source"] = url
                record["fetched_utc"] = _now()
                self.records.setdefault(cve, {})[vendor] = record

    def summary(self):
        return {
            "sources": dict(SOURCES),
            "records": {cve: {v: {"found": r.get("found"), "fetched_utc": r.get("fetched_utc")}
                              for v, r in vendors.items()}
                        for cve, vendors in self.records.items()},
            "errors": dict(self.errors),
        }

    def to_dict(self):
        return {"format": FORMAT, "tool": "netviser-audit %s" % __version__,
                "records": self.records}

    @classmethod
    def from_dict(cls, data):
        data = _dict(data)
        if data.get("format") != FORMAT:
            raise ValueError("unsupported advisory file format")
        db = cls()
        for cve, vendors in _dict(data.get("records")).items():
            if not CVE_RE.match(cve):
                continue
            for vendor, record in _dict(vendors).items():
                if vendor in VENDORS and isinstance(record, dict):
                    db.records.setdefault(cve, {})[vendor] = record
        return db

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def save(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=1, sort_keys=True)
            f.write("\n")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
