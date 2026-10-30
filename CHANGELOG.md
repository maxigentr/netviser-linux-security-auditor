# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-30

### Added
- `patch` check: kernel CVE patch status for the running kernel package, from
  vendor advisory data — Ubuntu Security API, Debian (via OSV) and the Red Hat
  Security Data API (RHEL, Rocky Linux, AlmaLinux, CentOS). Versions are
  compared with dpkg and rpm ordering. Verdicts: `PATCHED`, `NOT_AFFECTED`,
  `LIVEPATCHED`, `VULNERABLE`, `FIX_PENDING`, `FIX_NOT_AVAILABLE`, `WONT_FIX`,
  `MENTIONED_IN_CHANGELOG`, `NO_DATA`, `UNSUPPORTED`, `NOT_CHECKED`.
- Livepatch evidence (`canonical-livepatch`, `kpatch-patch`) and changelog
  CVE references for the running kernel package.
- `--cve`, `--offline`, `--advisories FILE`, `--save-advisories FILE`.
- `os_version_codename` fact; `CVE PATCH` column in the terminal summary; one
  `patch.<CVE>` column per CVE in the CSV report; advisory sources and download
  errors in the JSON report.

### Changed
- `cve_2026_98432.patch_status` (always `UNVERIFIED`) is replaced by
  `patch.CVE-2026-98432`.
- `Check.evaluate()` takes an optional `context` argument.

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
