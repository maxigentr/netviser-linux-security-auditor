# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-30

### Added
- Modular check framework (`netviser_audit/checks/`); each check ships a POSIX sh
  collector and a controller-side evaluator.
- `kernel` check: distribution, kernel release, running kernel package, pending
  reboot detection (newer installed kernel, `/var/run/reboot-required`).
- `tcp_migration` check: `net.ipv4.tcp_migrate_req` and loaded `sk_reuseport`
  BPF programs (root + bpftool).
- `mptcp` check: `net.mptcp.enabled`, path manager, `CONFIG_MPTCP`, MPTCP sockets
  and owning processes (`ss -M`), handshake counters from `/proc/net/netstat`
  with optional sampling (`--sample-interval`), mptcpize systemd drop-ins and
  processes with `libmptcpwrap` loaded, and an overall usage verdict that tells
  opportunistic listeners (e.g. Go 1.24+ programs) apart from real MPTCP use.
- `cve_2026_98432` check: related configuration summary; patch status always
  reported as unverified.
- Local and SSH execution, multi-host scanning, `--sudo`, `--checks`,
  `--print-script`, `--list-checks`, `--fail-on-review`.
- JSON and CSV reports; CSV cells are protected against formula injection and
  target output is sanitised of control characters.
- `netviser_cve_audit.py` kept as a backward-compatible entry point.
