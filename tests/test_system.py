import io
import os
import shutil
import subprocess
import tempfile
import unittest

from netviser_audit.checks import ALL_CHECKS, select_checks
from netviser_audit.checks.mptcp import COLLECTOR as MPTCP_COLLECTOR
from netviser_audit.reporting import HostResult, csv_safe, write_csv
from netviser_audit.ssh import LOCAL, RunOptions, build_command, valid_target
from netviser_audit.system import PRELUDE, build_script, parse_output

SS_FIXTURE = """\
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   0.0.0.0:8080       0.0.0.0:*         users:(("nginx",pid=10,fd=6),("nginx",pid=11,fd=6))
ESTAB  0      0      10.0.0.5:8080      10.0.0.9:51000    users:(("nginx",pid=11,fd=9))
ESTAB  0      0      10.0.0.5:40000     10.0.0.7:443      users:(("curl",pid=99,fd=3))
"""


def run_sh(script, shell="sh"):
    return subprocess.run([shell, "-s"], input=script, text=True, capture_output=True,
                          timeout=30).stdout


class ParseOutputTests(unittest.TestCase):
    def test_only_prefixed_lines_are_parsed(self):
        facts, complete = parse_output("Welcome banner\nkernel_release=evil\n"
                                       "NVA:kernel_release=6.8.0\nNVA:__end=1\n")
        self.assertEqual(facts, {"kernel_release": "6.8.0"})
        self.assertTrue(complete)

    def test_missing_end_marker_is_incomplete(self):
        _, complete = parse_output("NVA:kernel_release=6.8.0\n")
        self.assertFalse(complete)

    def test_control_characters_are_removed(self):
        facts, _ = parse_output("NVA:os_pretty_name=\x1b[31mUbuntu\x07 24.04\nNVA:__end=1")
        self.assertEqual(facts["os_pretty_name"], "[31mUbuntu 24.04")

    def test_invalid_keys_and_long_values(self):
        facts, _ = parse_output("NVA:bad key=1\nNVA:k=" + "x" * 5000 + "\nNVA:__end=1")
        self.assertNotIn("bad key", facts)
        self.assertEqual(len(facts["k"]), 400)

    def test_key_limit(self):
        text = "".join("NVA:k%d=1\n" % i for i in range(1000)) + "NVA:__end=1"
        facts, complete = parse_output(text)
        self.assertEqual(len(facts), 500)
        self.assertTrue(complete)


class ScriptTests(unittest.TestCase):
    def test_script_contains_all_collectors_and_interval(self):
        script = build_script(ALL_CHECKS, sample_interval=60)
        self.assertIn("NV_SAMPLE_INTERVAL=60", script)
        for check in ALL_CHECKS:
            if check.collector:
                self.assertIn("# --- check: %s ---" % check.id, script)
        self.assertTrue(script.rstrip().endswith("exit 0"))

    def test_script_syntax(self):
        script = build_script(ALL_CHECKS)
        for shell in ("sh", "dash", "bash"):
            if shutil.which(shell):
                proc = subprocess.run([shell, "-n"], input=script, text=True,
                                      capture_output=True)
                self.assertEqual(proc.returncode, 0, "%s: %s" % (shell, proc.stderr))

    def test_script_runs_and_terminates(self):
        facts, complete = parse_output(run_sh(build_script(ALL_CHECKS)))
        self.assertTrue(complete)
        self.assertIn("kernel_release", facts)
        self.assertIn("mptcp_enabled", facts)

    def test_mptcp_socket_parsing_with_fake_ss(self):
        fake = "ss() { cat <<'NV_EOF'\n%sNV_EOF\n}\n" % SS_FIXTURE
        script = PRELUDE + "NV_SAMPLE_INTERVAL=0\n" + fake + MPTCP_COLLECTOR + "nv_kv __end 1\n"
        facts, complete = parse_output(run_sh(script))
        self.assertTrue(complete)
        self.assertEqual(facts["mptcp_sockets_total"], "3")
        self.assertEqual(facts["mptcp_sockets_listen"], "1")
        self.assertEqual(facts["mptcp_sockets_established"], "2")
        self.assertEqual(facts["mptcp_processes"], "curl,nginx")

    def test_mptcp_counter_sampling_with_fake_netstat(self):
        with tempfile.NamedTemporaryFile("w", suffix=".netstat", delete=False) as f:
            f.write("TcpExt: SyncookiesSent\nTcpExt: 5\n"
                    "MPTcpExt: MPCapableSYNRX MPJoinSynRx AddAddr\n"
                    "MPTcpExt: 7 2 9\n")
        self.addCleanup(os.unlink, f.name)
        collector = MPTCP_COLLECTOR.replace("/proc/net/netstat", f.name)
        script = PRELUDE + "NV_SAMPLE_INTERVAL=1\n" + collector + "nv_kv __end 1\n"
        facts, complete = parse_output(run_sh(script))
        self.assertTrue(complete)
        self.assertEqual(facts["mptcp_counters_available"], "yes")
        self.assertEqual(facts["ctr0.MPCapableSYNRX"], "7")
        self.assertEqual(facts["ctr1.MPJoinSynRx"], "2")
        self.assertEqual(facts["mptcp_sample_seconds"], "1")
        self.assertNotIn("ctr0.AddAddr", facts)


class SelectionTests(unittest.TestCase):
    def test_dependencies_are_added_in_registry_order(self):
        ids = [c.id for c in select_checks(["cve_2026_98432"])]
        self.assertEqual(ids, ["kernel", "tcp_migration", "mptcp", "cve_2026_98432"])

    def test_unknown_check(self):
        with self.assertRaises(KeyError):
            select_checks(["nope"])


class SshTests(unittest.TestCase):
    def test_option_injection_rejected(self):
        for target in ("-oProxyCommand=id", "host name", "host\nx", ""):
            self.assertFalse(valid_target(target), target)
        self.assertTrue(valid_target("root@10.0.0.5"))
        self.assertTrue(valid_target("ssh://root@host:2290"))

    def test_command(self):
        cmd = build_command("root@h", RunOptions(port=2290, identity="k", sudo=True))
        self.assertEqual(cmd[cmd.index("-i") + 1], "k")
        self.assertEqual(cmd[cmd.index("-p") + 1], "2290")
        self.assertEqual(cmd[-3:], ["--", "root@h", "sudo -n sh -s"])
        self.assertIn("BatchMode=yes", cmd)
        self.assertEqual(build_command(LOCAL, RunOptions()), ["sh", "-s"])


class ReportingTests(unittest.TestCase):
    def test_csv_formula_injection(self):
        self.assertEqual(csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(csv_safe("6.8.0"), "6.8.0")

    def test_csv_columns_and_error_row(self):
        out = io.StringIO()
        write_csv(out, [HostResult("h1", "error", error="timed out")], ALL_CHECKS)
        header, row = out.getvalue().splitlines()
        self.assertTrue(header.startswith("target,status,os_pretty_name"))
        self.assertIn("mptcp.usage", header)
        self.assertTrue(row.startswith("h1,error,"))
        self.assertTrue(row.endswith("timed out"))


if __name__ == "__main__":
    unittest.main()
