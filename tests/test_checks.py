import unittest

from netviser_audit.checks.cve_2026_98432 import Cve202698432Check
from netviser_audit.checks.kernel import KernelCheck
from netviser_audit.checks.mptcp import MptcpCheck
from netviser_audit.checks.tcp_migration import TcpMigrationCheck

BASE = {
    "uid": "0",
    "kernel_name": "Linux",
    "kernel_release": "6.8.0-45-generic",
    "architecture": "x86_64",
    "os_pretty_name": "Ubuntu 24.04.1 LTS",
    "os_id": "ubuntu",
    "kernel_package": "linux-image-6.8.0-45-generic 6.8.0-45.45",
    "kernel_running_image_present": "yes",
    "kernel_newest_installed": "6.8.0-45-generic",
    "reboot_required_flag": "no",
    "tcp_migrate_req": "0",
    "bpf_sk_reuseport_progs": "0",
    "mptcp_enabled": "1",
    "mptcp_sockets_total": "0",
    "mptcp_sockets_listen": "0",
    "mptcp_sockets_established": "0",
    "mptcp_processes": "",
    "mptcp_counters_available": "yes",
    "ctr0.MPCapableSYNRX": "0",
    "ctr0.MPJoinSynRx": "0",
    "mptcpize_installed": "no",
    "mptcpize_units": "",
    "mptcp_wrapped_processes": "",
}


def facts(**overrides):
    result = dict(BASE)
    result.update(overrides)
    return result


def by_key(check, data):
    return {f.key: f for f in check.evaluate(data)}


class KernelTests(unittest.TestCase):
    def test_running_newest(self):
        f = by_key(KernelCheck(), facts())
        self.assertEqual(f["kernel.identity"].verdict, "IDENTIFIED")
        self.assertEqual(f["kernel.pending_reboot"].verdict, "RUNNING_NEWEST")

    def test_newer_kernel_installed(self):
        f = by_key(KernelCheck(), facts(kernel_newest_installed="6.8.0-48-generic"))
        self.assertEqual(f["kernel.pending_reboot"].verdict, "NEWER_KERNEL_INSTALLED")
        self.assertEqual(f["kernel.pending_reboot"].status, "REVIEW")

    def test_reboot_required_flag(self):
        f = by_key(KernelCheck(), facts(reboot_required_flag="yes"))
        self.assertEqual(f["kernel.pending_reboot"].verdict, "REBOOT_REQUIRED")

    def test_not_linux(self):
        f = by_key(KernelCheck(), facts(kernel_name="Darwin"))
        self.assertEqual(f["kernel.identity"].verdict, "NOT_LINUX")


class TcpMigrationTests(unittest.TestCase):
    def test_values(self):
        cases = {"1": "ENABLED", "0": "DISABLED", "unavailable": "NOT_PRESENT", "x": "UNEXPECTED_VALUE"}
        for value, verdict in cases.items():
            f = by_key(TcpMigrationCheck(), facts(tcp_migrate_req=value))
            self.assertEqual(f["tcp_migration.sysctl"].verdict, verdict, value)

    def test_bpf(self):
        check = TcpMigrationCheck()
        self.assertEqual(by_key(check, facts(bpf_sk_reuseport_progs="2"))["tcp_migration.bpf"].status,
                         "REVIEW")
        self.assertEqual(by_key(check, facts(bpf_sk_reuseport_progs="unavailable"))
                         ["tcp_migration.bpf"].verdict, "NOT_INSPECTED")


class MptcpTests(unittest.TestCase):
    def usage(self, **overrides):
        return by_key(MptcpCheck(), facts(**overrides))["mptcp.usage"]

    def test_none_observed(self):
        u = self.usage()
        self.assertEqual((u.status, u.verdict), ("OK", "NONE_OBSERVED"))

    def test_established_sockets_mean_in_use(self):
        u = self.usage(mptcp_sockets_total="3", mptcp_sockets_listen="1",
                       mptcp_sockets_established="2", mptcp_processes="nginx,curl")
        self.assertEqual(u.verdict, "IN_USE")
        self.assertIn("nginx", u.detail)

    def test_listeners_without_handshakes(self):
        f = by_key(MptcpCheck(), facts(mptcp_sockets_total="4", mptcp_sockets_listen="4",
                                       mptcp_processes="prometheus,grafana"))
        self.assertEqual(f["mptcp.sockets"].verdict, "LISTENING_ONLY")
        self.assertEqual((f["mptcp.usage"].status, f["mptcp.usage"].verdict),
                         ("INFO", "LISTENING_ONLY"))
        self.assertIn("prometheus", f["mptcp.usage"].detail)

    def test_listeners_with_past_handshakes_mean_in_use(self):
        u = self.usage(mptcp_sockets_total="1", mptcp_sockets_listen="1",
                       **{"ctr0.MPCapableSYNRX": "5"})
        self.assertEqual(u.verdict, "IN_USE")

    def test_mptcpize_units_mean_in_use(self):
        u = self.usage(mptcpize_units="/etc/systemd/system/app.service.d/mptcp.conf")
        self.assertEqual(u.verdict, "IN_USE")

    def test_increasing_counters(self):
        f = by_key(MptcpCheck(), facts(**{"ctr1.MPCapableSYNRX": "4", "ctr1.MPJoinSynRx": "1",
                                          "mptcp_sample_seconds": "60"}))
        self.assertEqual(f["mptcp.counters"].verdict, "INCREASING")
        self.assertIn("by 5 in 60s", f["mptcp.counters"].title)
        self.assertEqual(f["mptcp.usage"].verdict, "ACTIVE_TRAFFIC")

    def test_sampled_without_increase(self):
        f = by_key(MptcpCheck(), facts(**{"ctr0.MPCapableSYNRX": "7", "ctr1.MPCapableSYNRX": "7",
                                          "ctr0.MPJoinSynRx": "0", "ctr1.MPJoinSynRx": "0",
                                          "mptcp_sample_seconds": "60"}))
        self.assertEqual(f["mptcp.counters"].verdict, "NOT_INCREASING")
        self.assertEqual(f["mptcp.usage"].verdict, "NONE_OBSERVED")

    def test_past_activity(self):
        self.assertEqual(self.usage(**{"ctr0.MPCapableSYNRX": "12"}).verdict, "PAST_ACTIVITY")

    def test_disabled(self):
        self.assertEqual(self.usage(mptcp_enabled="0").verdict, "DISABLED")

    def test_not_present(self):
        self.assertEqual(self.usage(mptcp_enabled="unavailable").verdict, "NOT_APPLICABLE")

    def test_non_root_caveat(self):
        self.assertIn("Not run as root", self.usage(uid="1000").detail)


class CveTests(unittest.TestCase):
    def test_related_features_enabled(self):
        f = by_key(Cve202698432Check(), facts(tcp_migrate_req="1"))
        related = f["cve_2026_98432.related_config"]
        self.assertEqual(related.verdict, "RELATED_FEATURES_ENABLED")
        self.assertIn("net.ipv4.tcp_migrate_req=1", related.title)
        self.assertIn("net.mptcp.enabled=1", related.title)

    def test_disabled_is_not_reported_as_safe(self):
        f = by_key(Cve202698432Check(), facts(mptcp_enabled="0"))
        self.assertEqual(f["cve_2026_98432.related_config"].status, "INFO")
        self.assertIn("does not establish protection", f["cve_2026_98432.related_config"].detail)

    def test_features_absent_from_old_kernel(self):
        f = by_key(Cve202698432Check(), facts(tcp_migrate_req="unavailable",
                                              mptcp_enabled="unavailable"))
        self.assertEqual(f["cve_2026_98432.related_config"].verdict, "RELATED_FEATURES_NOT_PRESENT")


if __name__ == "__main__":
    unittest.main()
