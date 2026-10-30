"""Kernel and distribution identification."""
from .base import INFO, OK, REVIEW, UNKNOWN, Check, Finding

COLLECTOR = r'''
nv_osr() { sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | head -n1 | tr -d "\"'"; }
nv_kv kernel_name "$(uname -s 2>/dev/null)"
nv_kv kernel_release "$(uname -r 2>/dev/null)"
nv_kv kernel_version "$(uname -v 2>/dev/null)"
nv_kv architecture "$(uname -m 2>/dev/null)"
if [ -r /etc/os-release ]; then
  nv_kv os_pretty_name "$(nv_osr PRETTY_NAME)"
  nv_kv os_id "$(nv_osr ID)"
  nv_kv os_version_id "$(nv_osr VERSION_ID)"
  nv_kv os_version_codename "$(nv_osr VERSION_CODENAME)"
else
  nv_kv os_pretty_name "$(uname -s 2>/dev/null)"
  nv_kv os_id unknown
  nv_kv os_version_id unknown
fi
NV_K="$(uname -r 2>/dev/null)"
if nv_have dpkg-query; then
  NV_PKG="$(dpkg-query -W -f='${Package} ${Version}' "linux-image-$NV_K" 2>/dev/null)" || NV_PKG="$(dpkg-query -W -f='${Package} ${Version}' "linux-image-unsigned-$NV_K" 2>/dev/null)" || NV_PKG=unavailable
elif nv_have rpm; then
  NV_PKG="$(rpm -qf "/lib/modules/$NV_K/vmlinuz" 2>/dev/null)" || NV_PKG="$(rpm -qf "/boot/vmlinuz-$NV_K" 2>/dev/null)" || NV_PKG=unavailable
else
  NV_PKG=unavailable
fi
nv_kv kernel_package "${NV_PKG:-unavailable}"
if [ -e "/boot/vmlinuz-$NV_K" ]; then nv_kv kernel_running_image_present yes; else nv_kv kernel_running_image_present no; fi
NV_NEWEST="$(ls -1 /boot 2>/dev/null | sed -n 's/^vmlinuz-//p' | grep -v rescue | sort -V 2>/dev/null | tail -n1)"
nv_kv kernel_newest_installed "${NV_NEWEST:-unavailable}"
if [ -e /var/run/reboot-required ]; then nv_kv reboot_required_flag yes; else nv_kv reboot_required_flag no; fi
'''


class KernelCheck(Check):
    id = "kernel"
    title = "Kernel and distribution identification"
    collector = COLLECTOR
    report_facts = ("os_pretty_name", "kernel_release", "architecture", "kernel_package",
                    "kernel_newest_installed")
    finding_keys = ("kernel.identity", "kernel.pending_reboot")

    def evaluate(self, facts, context=None):
        release = facts.get("kernel_release", "")
        if facts.get("kernel_name") != "Linux":
            identity = Finding("kernel.identity", UNKNOWN, "NOT_LINUX",
                               "Target is not Linux (%s); Linux checks do not apply"
                               % (facts.get("kernel_name") or "unknown"))
        else:
            identity = Finding("kernel.identity", INFO, "IDENTIFIED",
                               "%s, kernel %s (%s)" % (facts.get("os_pretty_name", "unknown OS"),
                                                       release, facts.get("architecture", "?")),
                               "Package: %s" % facts.get("kernel_package", "unavailable"))
        return [identity, self._pending_reboot(facts, release)]

    @staticmethod
    def _pending_reboot(facts, release):
        key = "kernel.pending_reboot"
        if facts.get("reboot_required_flag") == "yes":
            return Finding(key, REVIEW, "REBOOT_REQUIRED",
                           "/var/run/reboot-required is present; installed updates need a reboot")
        newest = facts.get("kernel_newest_installed", "unavailable")
        if newest == "unavailable" or facts.get("kernel_running_image_present") != "yes":
            return Finding(key, UNKNOWN, "UNDETERMINED",
                           "Could not compare running and installed kernels")
        if newest != release:
            return Finding(key, REVIEW, "NEWER_KERNEL_INSTALLED",
                           "Newer kernel %s is installed but %s is running" % (newest, release),
                           "Kernel security updates only take effect after a reboot.")
        return Finding(key, OK, "RUNNING_NEWEST", "Running the newest installed kernel")
