"""CVE-2026-98432: Linux kernel IPv4 TCP use-after-free.

This check does NOT determine whether the vendor fix is installed. It reports
the kernel features this project associates with the vulnerability (TCP request
socket migration and MPTCP) and always marks patch status as unverified.
"""
from .base import INFO, REVIEW, UNKNOWN, Check, Finding, to_int

CVE_ID = "CVE-2026-98432"


class Cve202698432Check(Check):
    id = "cve_2026_98432"
    title = CVE_ID + " related configuration"
    requires = ("kernel", "tcp_migration", "mptcp")
    finding_keys = ("cve_2026_98432.related_config", "cve_2026_98432.patch_status")

    def evaluate(self, facts):
        return [self._related_config(facts), self._patch_status(facts)]

    @staticmethod
    def _related_config(facts):
        key = "cve_2026_98432.related_config"
        migrate = facts.get("tcp_migrate_req")
        mptcp = facts.get("mptcp_enabled")
        progs = to_int(facts.get("bpf_sk_reuseport_progs"))

        enabled = []
        if migrate == "1":
            enabled.append("net.ipv4.tcp_migrate_req=1")
        if progs:
            enabled.append("%d sk_reuseport BPF program(s)" % progs)
        if mptcp == "1":
            enabled.append("net.mptcp.enabled=1")
        if enabled:
            return Finding(key, REVIEW, "RELATED_FEATURES_ENABLED",
                           "Features related to %s are enabled: %s" % (CVE_ID, ", ".join(enabled)),
                           "Install the vendor kernel update. Disabling these features is not a "
                           "verified mitigation; check application dependencies first.")
        if migrate is None and mptcp is None:
            return Finding(key, UNKNOWN, "UNDETERMINED",
                           "Related kernel features could not be inspected")
        if migrate == "unavailable" and mptcp == "unavailable":
            return Finding(key, INFO, "RELATED_FEATURES_NOT_PRESENT",
                           "Related features are not present in this kernel",
                           "This does not establish protection against %s." % CVE_ID)
        return Finding(key, INFO, "RELATED_FEATURES_DISABLED",
                       "Related features are disabled or not present",
                       "This does not establish protection against %s." % CVE_ID)

    @staticmethod
    def _patch_status(facts):
        vendor = facts.get("os_id")
        if not vendor or vendor == "unknown":
            vendor = "distribution"
        return Finding("cve_2026_98432.patch_status", UNKNOWN, "UNVERIFIED",
                       "Vendor patch status is not verified by this tool",
                       "Compare kernel package '%s' (%s) with the %s security advisory for %s."
                       % (facts.get("kernel_package", "unavailable"),
                          facts.get("kernel_release", "?"),
                          vendor, CVE_ID))
