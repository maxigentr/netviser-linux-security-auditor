"""Kernel CVE patch status from vendor advisory data.

The target reports the package that owns the *running* kernel (name, version,
source package) plus CVE ids mentioned in its changelog and in loaded
livepatches. The controller compares the running version with the vendor's
fixed version using dpkg/rpm ordering.

Supported: Ubuntu (Ubuntu Security API), Debian (Debian data via OSV), Red Hat
Enterprise Linux and its rebuilds Rocky Linux, AlmaLinux and CentOS (Red Hat
Security Data API).
"""
from .base import INFO, OK, REVIEW, UNKNOWN, Check, Finding
from ..versions import dpkg_compare, rpm_compare

COLLECTOR = r'''
NV_K="$(uname -r 2>/dev/null)"
NV_KFMT=unavailable; NV_KNAME=; NV_KVER=; NV_KSRC=; NV_CL=; NV_CL_OK=
if nv_have dpkg-query; then
  # linux-modules-* carries the kernel source package name on Ubuntu (linux, linux-hwe-6.8, ...).
  for NV_P in "linux-modules-$NV_K" "linux-image-unsigned-$NV_K" "linux-image-$NV_K"; do
    NV_L="$(dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}|${Source}' "$NV_P" 2>/dev/null)" || continue
    case "$NV_L" in ii*) ;; *) continue ;; esac
    NV_KFMT=deb
    NV_KNAME="$(printf '%s' "$NV_L" | cut -d'|' -f2)"
    NV_KVER="$(printf '%s' "$NV_L" | cut -d'|' -f3)"
    NV_KSRC="$(printf '%s' "$NV_L" | cut -d'|' -f4 | sed 's/ .*//')"
    NV_F="/usr/share/doc/$NV_KNAME/changelog.Debian.gz"
    if [ -r "$NV_F" ] && nv_have gzip; then
      NV_CL_OK=yes
      NV_CL="$(gzip -dc "$NV_F" 2>/dev/null | grep -o 'CVE-[0-9]*-[0-9]*' | sort -u)"
    fi
    break
  done
elif nv_have rpm; then
  for NV_F in "/lib/modules/$NV_K/vmlinuz" "/boot/vmlinuz-$NV_K"; do
    NV_L="$(rpm -qf --qf '%{NAME}|%{EPOCH}:%{VERSION}-%{RELEASE}\n' "$NV_F" 2>/dev/null)" || continue
    NV_L="$(printf '%s\n' "$NV_L" | head -n1)"
    NV_KFMT=rpm
    NV_KNAME="${NV_L%%|*}"
    NV_KVER="${NV_L#*|}"
    NV_CL_OK=yes
    NV_CL="$(rpm -qf --changelog "$NV_F" 2>/dev/null | grep -o 'CVE-[0-9]*-[0-9]*' | sort -u)"
    break
  done
fi
nv_kv kernel_pkg_format "$NV_KFMT"
nv_kv kernel_pkg_name "${NV_KNAME:-unavailable}"
nv_kv kernel_pkg_version "${NV_KVER:-unavailable}"
nv_kv kernel_pkg_source "${NV_KSRC:-unavailable}"
if [ -d /sys/kernel/livepatch ]; then
  nv_kv livepatch_loaded "$(ls -1 /sys/kernel/livepatch 2>/dev/null | wc -l | tr -d ' ')"
else
  nv_kv livepatch_loaded unavailable
fi
NV_LP=; NV_LP_OK=
if nv_have canonical-livepatch && [ "$NV_UID" = 0 ]; then
  if NV_OUT="$(canonical-livepatch status --verbose 2>/dev/null)"; then
    NV_LP_OK=yes
    NV_LP="$(printf '%s\n' "$NV_OUT" | grep -io 'cve-[0-9]*-[0-9]*' | tr 'a-z' 'A-Z' | sort -u)"
  fi
fi
if [ "$NV_KFMT" = rpm ]; then
  NV_KP="kpatch-patch-$(printf '%s' "$NV_K" | sed 's/\.el[0-9].*$//; s/\./_/g')"
  if rpm -q "$NV_KP" >/dev/null 2>&1; then
    NV_LP_OK=yes
    NV_LP="$NV_LP
$(rpm -q --changelog "$NV_KP" 2>/dev/null | grep -o 'CVE-[0-9]*-[0-9]*' | sort -u)"
  fi
fi
for NV_C in $NV_CVES; do
  NV_KEY="cve.$(printf '%s' "$NV_C" | tr '-' '_')"
  if [ -z "$NV_CL_OK" ]; then nv_kv "$NV_KEY.changelog" unavailable
  elif printf '%s\n' "$NV_CL" | grep -qx "$NV_C"; then nv_kv "$NV_KEY.changelog" yes
  else nv_kv "$NV_KEY.changelog" no; fi
  if [ -z "$NV_LP_OK" ]; then nv_kv "$NV_KEY.livepatch" unavailable
  elif printf '%s\n' "$NV_LP" | grep -qx "$NV_C"; then nv_kv "$NV_KEY.livepatch" yes
  else nv_kv "$NV_KEY.livepatch" no; fi
done
'''

# Verdicts
PATCHED = "PATCHED"
NOT_AFFECTED = "NOT_AFFECTED"
LIVEPATCHED = "LIVEPATCHED"
VULNERABLE = "VULNERABLE"
FIX_PENDING = "FIX_PENDING"
FIX_NOT_AVAILABLE = "FIX_NOT_AVAILABLE"
WONT_FIX = "WONT_FIX"
MENTIONED_IN_CHANGELOG = "MENTIONED_IN_CHANGELOG"
NO_DATA = "NO_DATA"
UNSUPPORTED = "UNSUPPORTED"
NOT_CHECKED = "NOT_CHECKED"

STATUS = {PATCHED: OK, NOT_AFFECTED: OK, LIVEPATCHED: OK, VULNERABLE: REVIEW,
          FIX_PENDING: REVIEW, FIX_NOT_AVAILABLE: REVIEW, WONT_FIX: REVIEW,
          MENTIONED_IN_CHANGELOG: INFO, NO_DATA: UNKNOWN, UNSUPPORTED: UNKNOWN,
          NOT_CHECKED: UNKNOWN}
OPEN = (VULNERABLE, FIX_PENDING, FIX_NOT_AVAILABLE, WONT_FIX)

RHEL_FAMILY = ("rhel", "centos", "rocky", "almalinux")
DEBIAN_ARCHES = ("amd64", "arm64", "armhf", "armel", "i386", "ppc64el", "s390x", "riscv64",
                 "mips64el")
OS_NAMES = {"rhel": "Red Hat Enterprise Linux", "centos": "CentOS", "rocky": "Rocky Linux",
            "almalinux": "AlmaLinux"}


def fact_key(cve, kind):
    return "cve.%s.%s" % (cve.replace("-", "_"), kind)


def vendor_release(facts):
    """Map the target's OS to (advisory vendor, release key), or None if unsupported."""
    os_id = facts.get("os_id", "")
    major = facts.get("os_version_id", "").split(".")[0]
    if os_id == "ubuntu" and facts.get("os_version_codename"):
        return "ubuntu", facts["os_version_codename"]
    if os_id == "debian" and major.isdigit():
        return "debian", major
    if os_id in RHEL_FAMILY and major.isdigit():
        return "redhat", major
    return None


def source_package(facts):
    """Kernel source package as named by the vendor's tracker."""
    src = facts.get("kernel_pkg_source", "")
    if not src or src == "unavailable":
        return None
    if src.startswith("linux-signed"):
        # linux-signed -> linux, linux-signed-hwe-6.8 -> linux-hwe-6.8 (Ubuntu);
        # linux-signed-amd64 -> linux (Debian)
        rest = src[len("linux-signed"):]
        for arch in DEBIAN_ARCHES:
            if rest.endswith("-" + arch):
                rest = rest[:-len(arch) - 1]
                break
        src = "linux" + rest
    return src


class PatchCheck(Check):
    id = "patch"
    title = "Kernel CVE patch status (vendor advisories)"
    requires = ("kernel",)
    collector = COLLECTOR
    report_facts = ("kernel_pkg_version",)

    def evaluate(self, facts, context=None):
        if context is None or not context.cves:
            return []
        return [assess(facts, cve, context) for cve in context.cves]


def _finding(cve, verdict, title, detail=""):
    return Finding("patch." + cve, STATUS[verdict], verdict, title, detail)


def assess(facts, cve, context):
    verdict, title, detail = _assess_vendor(facts, cve, context)
    livepatch = facts.get(fact_key(cve, "livepatch"))
    changelog = facts.get(fact_key(cve, "changelog"))

    if verdict in OPEN and livepatch == "yes":
        return _finding(cve, LIVEPATCHED, "%s is fixed by a loaded livepatch" % cve,
                        "%s Livepatch reports the fix; install the kernel update before the "
                        "livepatch support window ends." % title)
    if verdict in (NO_DATA, UNSUPPORTED, NOT_CHECKED) and changelog == "yes":
        return _finding(cve, MENTIONED_IN_CHANGELOG,
                        "%s is mentioned in the running kernel's changelog" % cve,
                        "%s The changelog reference suggests a fix but is not proof." % title)
    if verdict == VULNERABLE and facts.get("kernel_newest_installed") not in \
            (None, "unavailable", facts.get("kernel_release")):
        detail = ("Kernel %s is already installed but not running: reboot into it and re-run "
                  "the audit; if it is still older than the fixed version, install the update."
                  % facts["kernel_newest_installed"])
    return _finding(cve, verdict, title, detail.strip())


def _assess_vendor(facts, cve, context):
    if facts.get("kernel_name") != "Linux":
        return NOT_CHECKED, "Not a Linux target", ""
    target = vendor_release(facts)
    if target is None:
        return (UNSUPPORTED, "%s: no supported advisory source for %s" %
                (cve, facts.get("os_pretty_name") or facts.get("os_id") or "this OS"),
                "Supported: Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, CentOS.")
    vendor, release = target
    running = facts.get("kernel_pkg_version", "unavailable")
    if running == "unavailable":
        return (NOT_CHECKED, "%s: running kernel package could not be identified" % cve,
                "No installed package owns kernel %s." % facts.get("kernel_release", "?"))

    record = context.advisories.get(cve, vendor) if context.advisories else None
    if record is None:
        error = context.advisories.error(cve, vendor) if context.advisories else None
        reason = error or ("--offline and no saved advisory data" if context.offline
                           else "advisory data not loaded")
        return NOT_CHECKED, "%s: %s advisory data unavailable" % (cve, vendor), reason
    if not record.get("found"):
        return (NO_DATA, "%s: no %s record for this CVE" % (cve, vendor),
                "The vendor has not published data for %s." % cve)
    if vendor == "ubuntu":
        return _ubuntu(facts, cve, record, release, running)
    if vendor == "debian":
        return _debian(facts, cve, record, release, running)
    return _redhat(facts, cve, record, release, running)


def _display(version):
    """Drop a zero epoch ("0:" or old rpm's "(none):") for readability."""
    for prefix in ("(none):", "0:"):
        if version.startswith(prefix):
            return version[len(prefix):]
    return version


def _compare_fixed(cmp, cve, running, fixed, vendor_hint):
    if cmp(running, fixed) >= 0:
        return (PATCHED, "%s fixed: running %s >= %s" % (cve, _display(running), _display(fixed)),
                "")
    return (VULNERABLE, "%s not fixed: running %s, fixed in %s"
            % (cve, _display(running), _display(fixed)),
            "Install the kernel security update (%s) and reboot." % vendor_hint)


def _ubuntu(facts, cve, record, codename, running):
    src = source_package(facts)
    releases = record.get("packages", {}).get(src) if src else None
    if not isinstance(releases, dict):
        return (NO_DATA, "%s: Ubuntu does not track kernel source '%s'" % (cve, src),
                "Running kernel package %s %s." % (facts.get("kernel_pkg_name"), running))
    entry = releases.get(codename)
    if not isinstance(entry, list) or len(entry) != 2:
        return NO_DATA, "%s: no Ubuntu %s status for %s" % (cve, codename, src), ""
    status, version = entry
    where = "%s/%s" % (src, codename)
    if status == "not-affected":
        return NOT_AFFECTED, "%s does not affect %s" % (cve, where), version
    if status in ("released", "pending") and version:
        if dpkg_compare(running, version) >= 0:
            return PATCHED, "%s fixed: running %s >= %s" % (cve, running, version), ""
        if status == "released":
            return (VULNERABLE, "%s not fixed: running %s, fixed in %s" % (cve, running, version),
                    "Install the kernel security update (apt update && apt full-upgrade) and "
                    "reboot.")
        return (FIX_PENDING, "%s: fix %s prepared by Ubuntu, not yet released" % (cve, version),
                "Running %s. Watch the Ubuntu security notices for %s." % (running, where))
    if status in ("needed", "needs-triage", "deferred", "pending"):
        return (FIX_NOT_AVAILABLE, "%s: no Ubuntu fix for %s yet (%s)" % (cve, where, status),
                "Running %s." % running)
    if status == "ignored":
        return WONT_FIX, "%s: Ubuntu will not fix %s" % (cve, where), version
    return NO_DATA, "%s: Ubuntu status '%s' for %s" % (cve, status, where), ""


def _debian(facts, cve, record, major, running):
    src = source_package(facts)
    releases = record.get("packages", {}).get(src) if src else None
    entry = releases.get(major) if isinstance(releases, dict) else None
    if not isinstance(entry, list) or len(entry) != 2:
        return (NO_DATA, "%s: no Debian %s entry for %s" % (cve, major, src),
                "Debian lists no affected '%s' package for this release; it may be not affected "
                "or not tracked." % src)
    state, fixed = entry
    if state == "fixed" and fixed == "0":
        return NOT_AFFECTED, "%s does not affect %s in Debian %s" % (cve, src, major), ""
    if state == "fixed" and fixed:
        return _compare_fixed(dpkg_compare, cve, running, fixed,
                              "apt update && apt full-upgrade")
    return (FIX_NOT_AVAILABLE, "%s: no Debian %s fix for %s yet" % (cve, major, src),
            "Running %s." % running)


def _redhat(facts, cve, record, major, running):
    name = "kernel-rt" if facts.get("kernel_pkg_name", "").startswith("kernel-rt") else "kernel"
    entry = record.get("packages", {}).get(name, {}).get(major)
    os_id = facts.get("os_id")
    notes = []
    if os_id == "centos" and major in ("7", "8"):
        notes.append("Compared with Red Hat Enterprise Linux %s data. CentOS Linux %s is "
                     "end-of-life and receives none of these fixes." % (major, major))
    elif os_id == "centos":
        notes.append("Compared with Red Hat Enterprise Linux %s data. CentOS Stream kernels run "
                     "ahead of RHEL; the comparison is approximate." % major)
    elif os_id != "rhel":
        notes.append("Compared with Red Hat Enterprise Linux %s data; %s rebuilds the same "
                     "kernel versions, usually shortly after Red Hat." % (major, OS_NAMES[os_id]))
    note = " ".join(notes)

    if not isinstance(entry, dict):
        return NO_DATA, "%s: no RHEL %s entry for %s" % (cve, major, name), note
    fixed = entry.get("fixed")
    if isinstance(fixed, str) and fixed:
        try:
            verdict, title, detail = _compare_fixed(rpm_compare, cve, running, fixed,
                                                    entry.get("advisory") or "dnf update kernel")
        except ValueError:
            return NO_DATA, "%s: unparsable version data" % cve, note
        return verdict, title, (detail + " " + note).strip()
    state = entry.get("state", "")
    if state == "Not affected":
        return NOT_AFFECTED, "%s does not affect RHEL %s %s" % (cve, major, name), note
    if state in ("Will not fix", "Out of support scope"):
        return WONT_FIX, "%s: Red Hat will not fix RHEL %s (%s)" % (cve, major, state), note
    if state in ("Affected", "Fix deferred", "Under investigation"):
        return (FIX_NOT_AVAILABLE, "%s: no RHEL %s fix yet (%s)" % (cve, major, state),
                ("Running %s. " % _display(running) + note).strip())
    return NO_DATA, "%s: Red Hat state '%s' for RHEL %s" % (cve, state, major), note
