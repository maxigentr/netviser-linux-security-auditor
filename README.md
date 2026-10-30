# Netviser Linux Security Auditor

A lightweight, open-source Linux security auditing tool written in Python.

Audit local and remote Linux servers over SSH without installing agents or
modifying system configuration.

> **This is a configuration auditor, not a vulnerability scanner.**
> It reports kernel settings and usage associated with a vulnerability. It does
> **not** verify whether a vendor's CVE patch has been installed.

## Features

| Feature | v0.1.0 |
|---|---|
| Python 3.8+, no third-party dependencies | ✅ |
| Local Linux audit | ✅ |
| Remote audit over SSH (agentless) | ✅ |
| Multi-server scanning in parallel | ✅ |
| Ubuntu / Debian / Rocky / AlmaLinux / RHEL / Fedora | ✅ |
| TCP request socket migration inspection | ✅ |
| MPTCP configuration **and usage** inspection | ✅ |
| Kernel, distribution and pending-reboot detection | ✅ |
| JSON / CSV reporting | ✅ |
| CVE patch verification | ❌ not yet |
| Automatic security updates | ❌ never |
| Changing server configuration | ❌ never |

## How it works

The controller (your Mac or Linux workstation) builds a small POSIX `sh`
script from the selected checks and pipes it to `sh -s` on each target over
SSH. Nothing is copied to or installed on the target. The script prints
`key=value` facts; all evaluation happens on the controller, which treats the
target's output as untrusted (control characters stripped, values truncated,
CSV formula injection neutralised).

Review exactly what will run on your servers before you run it:

```sh
python3 netviser_cve_audit.py --print-script
```

**Targets** need only `sh` and standard tools (`ss` from iproute2, `awk`,
`grep`, `sed`). Python is not required on targets.
**Controller** needs Python 3.8+ and OpenSSH (macOS or Linux).

## Quick start

```sh
git clone https://github.com/maxigentr/netviser-linux-security-auditor.git
cd netviser-linux-security-auditor

# Audit this Linux machine
python3 netviser_cve_audit.py --local

# Audit a remote server
python3 netviser_cve_audit.py --host root@192.168.1.10

# Custom SSH port and key
python3 netviser_cve_audit.py --host root@192.168.1.10 --port 2290 --identity ~/.ssh/audit_ed25519

# Multiple servers, 10 in parallel
python3 netviser_cve_audit.py --hosts servers.txt --workers 10

# Non-root SSH user with passwordless sudo, for full process and BPF visibility
python3 netviser_cve_audit.py --host admin@web01 --sudo

# Watch MPTCP counters for 60 seconds to see if MPTCP is used right now
python3 netviser_cve_audit.py --hosts servers.txt --sample-interval 60
```

The tool can also be installed (`pip install .`) and run as `netviser-audit`
or `python3 -m netviser_audit`.

See [`examples/servers.example.txt`](examples/servers.example.txt) for the
hosts file format. Per-host ports use `ssh://user@host:port` or an
`~/.ssh/config` alias.

### Options

| Option | Description |
|---|---|
| `--local` / `--host H` / `--hosts FILE` | What to audit |
| `--checks IDS` | Comma-separated subset (see `--list-checks`); dependencies are added automatically |
| `--sudo` | Run the collector with `sudo -n` (never prompts) |
| `--sample-interval N` | Read MPTCP counters twice, N seconds apart |
| `--output PREFIX` | Report prefix (default `netviser_audit` → `.json`, `.csv`) |
| `--no-report` | Print to the terminal only |
| `--fail-on-review` | Exit 3 when any `REVIEW` finding exists (for CI / cron) |
| `-v`, `--verbose` | Show all findings, not only `REVIEW` / `UNKNOWN` |

SSH runs with `BatchMode=yes` (key-based authentication only) and
`StrictHostKeyChecking=accept-new`.

Exit status: `0` success, `1` a target could not be scanned, `2` usage error,
`3` review findings present (only with `--fail-on-review`).

## Checks

| Id | What it inspects |
|---|---|
| `kernel` | Distribution, kernel release, running kernel package, newer installed kernel / reboot required |
| `tcp_migration` | `net.ipv4.tcp_migrate_req`; loaded `sk_reuseport` BPF programs (root + bpftool) |
| `mptcp` | `net.mptcp.enabled`, path manager, `CONFIG_MPTCP`, MPTCP sockets and processes, handshake counters, mptcpize usage |
| `cve_2026_98432` | Summary of the above for CVE-2026-98432; patch status always *unverified* |

Every finding has a status — `OK`, `INFO`, `REVIEW` or `UNKNOWN` — and a
machine-readable verdict (e.g. `mptcp.usage = IN_USE`).

## MPTCP usage assessment

`net.mptcp.enabled = 1` only means MPTCP sockets *can* be created. Before
anyone disables MPTCP, the `mptcp` check gathers evidence of real use:

| Evidence | Source |
|---|---|
| Listening / established MPTCP sockets and their processes | `ss -M -a -n -p` |
| Handshake counters (`MPCapableSYNRX`, `MPJoinSynRx`, …) | `/proc/net/netstat` (`MPTcpExt`) |
| Counter increase during a sample window | `--sample-interval N` |
| Services wrapped with mptcpize | systemd units / drop-ins referencing `mptcpize` or `libmptcpwrap` |
| Running processes with `libmptcpwrap` loaded | `/proc/<pid>/maps` |

The result is summarised in `mptcp.usage`:

| Verdict | Meaning | Suggested action |
|---|---|---|
| `IN_USE` | Established MPTCP connections, mptcpize-wrapped services, or MPTCP listeners that have accepted MPTCP connections | Identify the dependent service before any change |
| `ACTIVE_TRAFFIC` | Handshake counters increased during sampling | Find the source of the traffic |
| `LISTENING_ONLY` | MPTCP listeners, but no MPTCP handshake since boot — typically programs that enable MPTCP opportunistically (Go 1.24+ does this for listeners by default) | Usually no dependency; open listeners keep MPTCP until restarted |
| `PAST_ACTIVITY` | Counters non-zero since boot, no current sockets | Re-run with `--sample-interval 60` |
| `NONE_OBSERVED` | No sockets, no counter activity, no mptcpize | A planned, reversible disable test is possible |
| `DISABLED` / `NOT_APPLICABLE` | MPTCP off or not built into the kernel | — |

`NONE_OBSERVED` is a point-in-time observation, not proof. Applications that
open `IPPROTO_MPTCP` sockets directly only appear while they hold a socket,
and without root only your own processes are visible.

If you decide to test disabling MPTCP, do it in a maintenance window, at
runtime first (`sysctl -w net.mptcp.enabled=0`), then watch service
connections and logs before making it persistent. This tool never makes that
change for you.

## CVE-2026-98432

The initial release focuses on configuration associated with CVE-2026-98432,
a Linux kernel IPv4 TCP use-after-free vulnerability. The tool inspects:

- `net.ipv4.tcp_migrate_req` and `sk_reuseport` BPF programs
- `net.mptcp.enabled` and actual MPTCP usage
- Linux kernel version and package
- Operating system information

### Important security notice

- This tool does **not** verify whether your vendor's security patch is installed.
- Disabling TCP migration or MPTCP is **not** a verified mitigation for CVE-2026-98432.
- Always consult your distribution's official security advisories and install
  the kernel security update. Kernel updates only take effect after a reboot —
  the `kernel.pending_reboot` finding flags hosts that still run an older kernel.

## Read-only operation

The tool does not:

- modify kernel parameters
- install packages
- change firewall rules
- reboot servers
- apply security patches

Commands run on targets only read: `/proc`, `/sys`, `/etc/os-release`,
`/boot`, `uname`, `ss`, `dpkg-query`/`rpm`, `bpftool prog show` and `grep` over
systemd unit directories. Two side effects to be aware of: querying MPTCP
sockets with `ss -M` may cause the kernel to autoload the `mptcp_diag`
diagnostics module, and SSH logins appear in the target's auth logs.

## Development

```sh
python3 -m unittest discover -s tests -t . -v
```

CI runs the unit tests on Python 3.8–3.13 and a local audit inside Ubuntu
22.04/24.04, Debian 12, Rocky Linux 9, AlmaLinux 9 and Fedora containers.

### Adding a check

1. Create `netviser_audit/checks/<name>.py` with a `Check` subclass: a POSIX
   `sh` `collector` that emits facts with `nv_kv key value`, and an
   `evaluate(facts)` method returning `Finding`s.
2. Register it in `ALL_CHECKS` in `netviser_audit/checks/__init__.py`.
3. Add evaluation tests in `tests/test_checks.py`.

Collectors must stay read-only and POSIX `sh` compatible (they are
syntax-checked with `sh`, `dash` and `bash` in the tests).

### Single-file build

```sh
mkdir -p build/pyz dist && cp -R netviser_audit build/pyz/
python3 -m zipapp build/pyz -m netviser_audit.cli:main -p "/usr/bin/env python3" -o dist/netviser-audit.pyz
```

## Roadmap

- Vendor-specific CVE patch verification
- Additional Linux kernel security checks
- Extended eBPF inspection
- HTML reporting
- Package distribution through PyPI

## Maintainer

Developed and maintained by Netviser Bilişim Teknolojileri.

## License

[MIT](LICENSE)
