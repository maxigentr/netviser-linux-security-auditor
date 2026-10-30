"""CVE-2026-98432: Linux kernel IPv4 TCP use-after-free.

This check reports the kernel features this project associates with the
vulnerability (TCP request socket migration and MPTCP). Whether the vendor fix
is installed is reported by the ``patch`` check as ``patch.CVE-2026-98432``.
"""
from .base import INFO, REVIEW, UNKNOWN, Check, Finding, to_int

CVE_ID = "CVE-2026-98432"


class Cve202698432Check(Check):
    id = "cve_2026_98432"
    title = CVE_ID + " related configuration"
    requires = ("kernel", "tcp_migration", "mptcp", "patch")
    finding_keys = ("cve_2026_98432.related_config",)
    cve_ids = (CVE_ID,)

    def evaluate(self, facts, context=None):
        return [self._related_config(facts)]

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
