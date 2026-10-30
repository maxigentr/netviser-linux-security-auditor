"""Multipath TCP configuration and usage.

Answers the question "is anything on this host using MPTCP?" before anyone
considers setting net.mptcp.enabled = 0. Evidence gathered:

* sockets visible to ``ss -M`` (listening / established, owning processes)
* MPTCP MIB counters from /proc/net/netstat, optionally sampled twice to see
  whether handshakes are happening *now* rather than at some point since boot
* mptcpize (LD_PRELOAD wrapper) installation, systemd drop-ins and processes
  that have libmptcpwrap mapped

None of this proves the absence of MPTCP usage; it is a point-in-time view and
non-root users only see their own processes.
"""
from .base import INFO, OK, REVIEW, UNKNOWN, Check, Finding, split_list, to_int

# Handshake counters that indicate real MPTCP traffic. Names differ by kernel
# version; whatever subset exists is used.
ACTIVITY_COUNTERS = (
    "MPCapableSYNRX", "MPCapableSYNTX", "MPCapableSYNACKRX", "MPCapableACKRX",
    "MPJoinSynRx", "MPJoinSynAckRx",
)

COLLECTOR = r'''
nv_kv mptcp_enabled "$(nv_sysctl net/mptcp/enabled)"
nv_kv mptcp_pm_type "$(nv_sysctl net/mptcp/pm_type)"
NV_K="$(uname -r 2>/dev/null)"
if [ -r "/boot/config-$NV_K" ]; then
  NV_CFG="$(grep '^CONFIG_MPTCP=' "/boot/config-$NV_K" 2>/dev/null | head -n1)"
elif [ -r /proc/config.gz ] && nv_have gzip; then
  NV_CFG="$(gzip -dc /proc/config.gz 2>/dev/null | grep '^CONFIG_MPTCP=' | head -n1)"
else
  NV_CFG=unavailable
fi
nv_kv config_mptcp "${NV_CFG:-not_set}"

if nv_have ss && NV_SS="$(ss -M -a -n -p 2>/dev/null)"; then
  NV_SS="$(printf '%s\n' "$NV_SS" | sed 1d)"
  nv_kv mptcp_sockets_total "$(printf '%s\n' "$NV_SS" | grep -c .)"
  nv_kv mptcp_sockets_listen "$(printf '%s\n' "$NV_SS" | grep -c '^LISTEN')"
  nv_kv mptcp_sockets_established "$(printf '%s\n' "$NV_SS" | grep -c '^ESTAB')"
  nv_kv mptcp_processes "$(printf '%s\n' "$NV_SS" | grep -o '("[^"]*",pid=' | sed 's/^("//; s/",pid=$//' | sort -u | tr '\n' ',' | sed 's/,$//')"
else
  nv_kv mptcp_sockets_total unavailable
  nv_kv mptcp_sockets_listen unavailable
  nv_kv mptcp_sockets_established unavailable
  nv_kv mptcp_processes unavailable
fi

nv_mptcp_ctr() {
  awk -v p="$1" '$1 == "MPTcpExt:" {
    if (!h) { for (i = 2; i <= NF; i++) n[i] = $i; h = 1 }
    else { for (i = 2; i <= NF; i++) if (n[i] ~ /^MP(Capable|Join)/) printf "NVA:%s%s=%s\n", p, n[i], $i }
  }' /proc/net/netstat 2>/dev/null
}
if grep -q '^MPTcpExt:' /proc/net/netstat 2>/dev/null; then
  nv_kv mptcp_counters_available yes
  nv_mptcp_ctr ctr0.
  if [ "$NV_SAMPLE_INTERVAL" -gt 0 ]; then
    sleep "$NV_SAMPLE_INTERVAL"
    nv_mptcp_ctr ctr1.
    nv_kv mptcp_sample_seconds "$NV_SAMPLE_INTERVAL"
  fi
else
  nv_kv mptcp_counters_available no
fi

if nv_have mptcpize; then nv_kv mptcpize_installed yes; else nv_kv mptcpize_installed no; fi
nv_kv mptcpize_units "$(grep -rlsE 'mptcpize|libmptcpwrap' /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')"
nv_kv mptcp_wrapped_processes "$(grep -ls libmptcpwrap /proc/[0-9]*/maps 2>/dev/null | while read -r f; do cat "${f%/maps}/comm" 2>/dev/null; done | sort -u | tr '\n' ',' | sed 's/,$//')"
'''


def counter_sum(facts, prefix):
    """Sum the activity counters under ``prefix``; None if none are present."""
    values = [to_int(facts.get(prefix + name)) for name in ACTIVITY_COUNTERS]
    values = [v for v in values if v is not None]
    return sum(values) if values else None


class MptcpCheck(Check):
    id = "mptcp"
    title = "Multipath TCP configuration and usage"
    collector = COLLECTOR
    report_facts = ("mptcp_enabled", "mptcp_pm_type", "config_mptcp", "mptcp_sockets_total",
                    "mptcp_sockets_listen", "mptcp_sockets_established", "mptcp_processes",
                    "mptcpize_units", "mptcp_wrapped_processes")
    finding_keys = ("mptcp.sysctl", "mptcp.sockets", "mptcp.counters", "mptcp.dependencies",
                    "mptcp.usage")

    def evaluate(self, facts):
        sysctl = self._sysctl(facts)
        sockets = self._sockets(facts)
        counters = self._counters(facts)
        dependencies = self._dependencies(facts)
        return [sysctl, sockets, counters, dependencies,
                self._usage(facts, sysctl, sockets, counters, dependencies)]

    @staticmethod
    def _sysctl(facts):
        value = facts.get("mptcp_enabled", "unavailable")
        if value == "1":
            return Finding("mptcp.sysctl", REVIEW, "ENABLED", "net.mptcp.enabled = 1")
        if value == "0":
            return Finding("mptcp.sysctl", OK, "DISABLED", "net.mptcp.enabled = 0")
        if value == "unavailable":
            return Finding("mptcp.sysctl", INFO, "NOT_PRESENT",
                           "net.mptcp.enabled is not present",
                           "Kernel built without MPTCP (config: %s), or not exposed in this "
                           "network namespace." % facts.get("config_mptcp", "unavailable"))
        return Finding("mptcp.sysctl", UNKNOWN, "UNEXPECTED_VALUE",
                       "Unexpected net.mptcp.enabled value: %r" % value)

    @staticmethod
    def _sockets(facts):
        total = to_int(facts.get("mptcp_sockets_total"))
        if total is None:
            return Finding("mptcp.sockets", UNKNOWN, "NOT_INSPECTED",
                           "MPTCP sockets could not be listed",
                           "'ss -M' unavailable: iproute2 too old or MPTCP diag not supported.")
        if total == 0:
            return Finding("mptcp.sockets", OK, "NONE", "No MPTCP sockets visible to ss")
        processes = split_list(facts.get("mptcp_processes"))
        established = to_int(facts.get("mptcp_sockets_established"))
        status, verdict = (INFO, "LISTENING_ONLY") if established == 0 else (REVIEW, "ESTABLISHED")
        return Finding("mptcp.sockets", status, verdict,
                       "%d MPTCP socket(s): %s listening, %s established"
                       % (total, facts.get("mptcp_sockets_listen", "?"),
                          facts.get("mptcp_sockets_established", "?")),
                       "Processes: %s" % (", ".join(processes) if processes
                                          else "not visible (run as root or use --sudo)"))

    @staticmethod
    def _counters(facts):
        if facts.get("mptcp_counters_available") != "yes":
            return Finding("mptcp.counters", UNKNOWN, "NOT_AVAILABLE",
                           "MPTCP counters not available in /proc/net/netstat")
        before = counter_sum(facts, "ctr0.")
        if before is None:
            return Finding("mptcp.counters", UNKNOWN, "NOT_AVAILABLE",
                           "No known MPTCP handshake counters on this kernel")
        after = counter_sum(facts, "ctr1.")
        if after is not None:
            seconds = facts.get("mptcp_sample_seconds", "?")
            delta = after - before
            if delta > 0:
                return Finding("mptcp.counters", REVIEW, "INCREASING",
                               "MPTCP handshake counters increased by %d in %ss" % (delta, seconds),
                               "MPTCP connections are being established right now.")
            return Finding("mptcp.counters", OK, "NOT_INCREASING",
                           "No new MPTCP handshakes during the %ss sample (%d since boot)"
                           % (seconds, before))
        if before > 0:
            return Finding("mptcp.counters", INFO, "NONZERO_SINCE_BOOT",
                           "%d MPTCP handshake(s) counted since boot" % before,
                           "Shows past activity only. Re-run with --sample-interval 60 to see "
                           "whether the counters are still increasing.")
        return Finding("mptcp.counters", OK, "ZERO_SINCE_BOOT",
                       "No MPTCP handshakes counted since boot")

    @staticmethod
    def _dependencies(facts):
        units = split_list(facts.get("mptcpize_units"))
        wrapped = split_list(facts.get("mptcp_wrapped_processes"))
        if units or wrapped:
            parts = []
            if units:
                parts.append("systemd units: " + ", ".join(units))
            if wrapped:
                parts.append("wrapped processes: " + ", ".join(wrapped))
            return Finding("mptcp.dependencies", REVIEW, "MPTCPIZE_IN_USE",
                           "Services are configured to run under mptcpize", "; ".join(parts))
        if facts.get("mptcpize_installed") == "yes":
            return Finding("mptcp.dependencies", INFO, "MPTCPIZE_INSTALLED",
                           "mptcpize is installed but no wrapped service or process was found")
        return Finding("mptcp.dependencies", OK, "NONE_FOUND", "No mptcpize usage found")

    @staticmethod
    def _usage(facts, sysctl, sockets, counters, dependencies):
        """Overall answer to: can MPTCP be disabled without breaking something?"""
        key = "mptcp.usage"
        caveat = ("Point-in-time observation. Applications that open IPPROTO_MPTCP sockets "
                  "directly only show up while they hold a socket.")
        if facts.get("uid") != "0":
            caveat += " Not run as root: processes of other users are not visible."

        handshakes = counter_sum(facts, "ctr0.")
        if (sockets.verdict == "ESTABLISHED" or dependencies.verdict == "MPTCPIZE_IN_USE"
                or (sockets.verdict == "LISTENING_ONLY" and handshakes)):
            return Finding(key, REVIEW, "IN_USE",
                           "MPTCP is in use; identify the dependent services before disabling it",
                           "; ".join(x for x in (sockets.detail, dependencies.detail) if x))
        if sockets.verdict == "LISTENING_ONLY" and counters.verdict != "INCREASING":
            return Finding(key, INFO, "LISTENING_ONLY",
                           "MPTCP listeners exist, but no MPTCP connection has been made since boot",
                           sockets.detail + ". Usually applications that enable MPTCP "
                           "opportunistically (e.g. Go 1.24+ programs do so for listening "
                           "sockets by default) and fall back to plain TCP. Sockets already "
                           "open keep MPTCP until the service restarts. " + caveat)
        if counters.verdict == "INCREASING":
            return Finding(key, REVIEW, "ACTIVE_TRAFFIC",
                           "MPTCP handshakes are occurring; find their source before disabling",
                           "Short-lived connections may not appear in ss. " + caveat)
        if sysctl.verdict == "DISABLED":
            return Finding(key, OK, "DISABLED", "MPTCP is disabled")
        if sysctl.verdict == "NOT_PRESENT":
            return Finding(key, INFO, "NOT_APPLICABLE", "MPTCP is not available on this kernel")
        if sockets.verdict == "NOT_INSPECTED" and counters.verdict == "NOT_AVAILABLE":
            return Finding(key, UNKNOWN, "UNDETERMINED", "Not enough data to assess MPTCP usage")
        if counters.verdict == "NONZERO_SINCE_BOOT":
            return Finding(key, INFO, "PAST_ACTIVITY",
                           "No current MPTCP usage seen, but MPTCP was used since boot",
                           "Re-run with --sample-interval 60 before planning a change. " + caveat)
        return Finding(key, OK, "NONE_OBSERVED",
                       "No MPTCP usage observed; a planned, reversible disable test is possible",
                       caveat)
