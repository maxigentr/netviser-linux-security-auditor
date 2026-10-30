"""Command line interface."""
import argparse
import concurrent.futures
import pathlib
import sys

from . import __version__
from .checks import ALL_CHECKS, select_checks
from .checks.base import REVIEW
from .reporting import HostResult, build_report, print_summary, write_csv, write_json
from .ssh import LOCAL, RunOptions, run
from .system import build_script, parse_output

EXIT_OK, EXIT_SCAN_ERROR, EXIT_REVIEW = 0, 1, 3


def scan(target, script, checks, opts):
    stdout, error = run(target, script, opts)
    if error:
        return HostResult(target, "error", error=error)
    facts, complete = parse_output(stdout)
    if not complete:
        return HostResult(target, "error", facts=facts,
                          error="incomplete or invalid response from target")
    findings = [f for check in checks for f in check.evaluate(facts)]
    return HostResult(target, "ok", facts=facts, findings=findings)


def read_targets(path):
    lines = pathlib.Path(path).read_text(encoding="utf-8").splitlines()
    return [x.strip() for x in lines if x.strip() and not x.lstrip().startswith("#")]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netviser-audit",
        description="Read-only Linux kernel security configuration audit, locally or over SSH.",
        epilog="Exit status: 0 success, 1 a target could not be scanned, 2 usage error, "
               "3 REVIEW findings present (only with --fail-on-review).")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--local", action="store_true", help="audit this machine")
    source.add_argument("--host", help="SSH destination, e.g. root@10.0.0.5, an ~/.ssh/config "
                                       "alias or ssh://user@host:port")
    source.add_argument("--hosts", metavar="FILE",
                        help="file with one SSH destination per line; # starts a comment")
    source.add_argument("--print-script", action="store_true",
                        help="print the shell script that runs on targets, then exit")
    source.add_argument("--list-checks", action="store_true", help="list available checks")
    parser.add_argument("--checks", metavar="IDS",
                        help="comma-separated check ids (default: all)")
    parser.add_argument("--identity", metavar="KEY", help="SSH private key file")
    parser.add_argument("--port", type=int, help="SSH port (same for all targets)")
    parser.add_argument("--sudo", action="store_true",
                        help="run the collector with 'sudo -n' for full process/BPF visibility")
    parser.add_argument("--workers", type=int, default=8, help="parallel targets (default: 8)")
    parser.add_argument("--timeout", type=int, default=25,
                        help="per-target timeout in seconds, excluding --sample-interval")
    parser.add_argument("--connect-timeout", type=int, default=8, help="SSH connect timeout")
    parser.add_argument("--sample-interval", type=int, default=0, metavar="SECONDS",
                        help="read MPTCP counters twice, SECONDS apart, to detect current "
                             "activity (e.g. 60; default: 0 = single reading)")
    parser.add_argument("--output", default="netviser_audit", metavar="PREFIX",
                        help="report file prefix; writes PREFIX.json and PREFIX.csv")
    parser.add_argument("--no-report", action="store_true", help="do not write report files")
    parser.add_argument("--fail-on-review", action="store_true",
                        help="exit with status 3 if any REVIEW finding is reported")
    parser.add_argument("-v", "--verbose", action="store_true", help="show all findings")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        for check in ALL_CHECKS:
            print("%-16s %s" % (check.id, check.title))
        return EXIT_OK

    try:
        ids = [x.strip() for x in args.checks.split(",") if x.strip()] if args.checks else \
            [c.id for c in ALL_CHECKS]
        checks = select_checks(ids)
    except KeyError as exc:
        parser.error("unknown check: %s (see --list-checks)" % exc.args[0])
    if not 1 <= args.workers <= 64:
        parser.error("--workers must be between 1 and 64")
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be between 1 and 3600")
    if not 1 <= args.connect_timeout <= 300:
        parser.error("--connect-timeout must be between 1 and 300")
    if not 0 <= args.sample_interval <= 3600:
        parser.error("--sample-interval must be between 0 and 3600")
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    script = build_script(checks, args.sample_interval)
    if args.print_script:
        sys.stdout.write(script)
        return EXIT_OK

    if args.local:
        targets = [LOCAL]
    elif args.host:
        targets = [args.host]
    else:
        try:
            targets = read_targets(args.hosts)
        except (OSError, UnicodeDecodeError) as exc:
            parser.error(str(exc))
    if not targets:
        parser.error("no targets found")

    opts = RunOptions(identity=args.identity, port=args.port,
                      connect_timeout=args.connect_timeout,
                      timeout=args.timeout + args.sample_interval, sudo=args.sudo)
    if args.sample_interval:
        print("Sampling MPTCP counters for %ds per target..." % args.sample_interval,
              file=sys.stderr)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda t: scan(t, script, checks, opts), targets))

    print_summary(results, sys.stdout, verbose=args.verbose)
    if not args.no_report:
        json_path, csv_path = args.output + ".json", args.output + ".csv"
        with open(json_path, "w", encoding="utf-8") as f:
            write_json(f, build_report(results, checks))
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            write_csv(f, results, checks)
        print("\nReports: %s, %s" % (json_path, csv_path))
    print("CVE patch status: NOT VERIFIED. Confirm with your distribution's security advisory.")

    if any(r.status != "ok" for r in results):
        return EXIT_SCAN_ERROR
    if args.fail_on_review and any(f.status == REVIEW for r in results for f in r.findings):
        return EXIT_REVIEW
    return EXIT_OK
