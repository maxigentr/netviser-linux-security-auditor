"""TCP request socket migration (net.ipv4.tcp_migrate_req, SO_REUSEPORT BPF)."""
from .base import INFO, OK, REVIEW, UNKNOWN, Check, Finding, to_int

COLLECTOR = r'''
nv_kv tcp_migrate_req "$(nv_sysctl net/ipv4/tcp_migrate_req)"
if [ -r /sys/kernel/btf/vmlinux ]; then nv_kv btf_available yes; else nv_kv btf_available no; fi
if nv_have bpftool; then nv_kv bpftool_installed yes; else nv_kv bpftool_installed no; fi
NV_BPF=unavailable
if nv_have bpftool && [ "$NV_UID" = 0 ]; then
  if NV_OUT="$(bpftool prog show 2>/dev/null)"; then
    NV_BPF="$(printf '%s\n' "$NV_OUT" | grep -c 'sk_reuseport')"
  fi
fi
nv_kv bpf_sk_reuseport_progs "$NV_BPF"
'''


class TcpMigrationCheck(Check):
    id = "tcp_migration"
    title = "TCP request socket migration"
    collector = COLLECTOR
    report_facts = ("tcp_migrate_req", "bpf_sk_reuseport_progs")
    finding_keys = ("tcp_migration.sysctl", "tcp_migration.bpf")

    def evaluate(self, facts, context=None):
        value = facts.get("tcp_migrate_req", "unavailable")
        if value == "1":
            sysctl = Finding("tcp_migration.sysctl", REVIEW, "ENABLED",
                             "net.ipv4.tcp_migrate_req = 1 (request socket migration enabled)")
        elif value == "0":
            sysctl = Finding("tcp_migration.sysctl", OK, "DISABLED",
                             "net.ipv4.tcp_migrate_req = 0")
        elif value == "unavailable":
            sysctl = Finding("tcp_migration.sysctl", INFO, "NOT_PRESENT",
                             "net.ipv4.tcp_migrate_req is not present",
                             "Kernel older than 5.14, or not exposed in this network namespace.")
        else:
            sysctl = Finding("tcp_migration.sysctl", UNKNOWN, "UNEXPECTED_VALUE",
                             "Unexpected net.ipv4.tcp_migrate_req value: %r" % value)

        progs = to_int(facts.get("bpf_sk_reuseport_progs"))
        if progs is None:
            need = ("bpftool is not installed" if facts.get("uid") == "0"
                    else "Requires root (or --sudo) and bpftool on the target.")
            bpf = Finding("tcp_migration.bpf", UNKNOWN, "NOT_INSPECTED",
                          "SO_REUSEPORT BPF programs not inspected", need)
        elif progs > 0:
            bpf = Finding("tcp_migration.bpf", REVIEW, "SK_REUSEPORT_PROGS_LOADED",
                          "%d sk_reuseport BPF program(s) loaded" % progs,
                          "Programs attached as BPF_SK_REUSEPORT_SELECT_OR_MIGRATE can migrate "
                          "request sockets even when net.ipv4.tcp_migrate_req = 0.")
        else:
            bpf = Finding("tcp_migration.bpf", OK, "NONE_LOADED",
                          "No sk_reuseport BPF programs loaded")
        return [sysctl, bpf]
