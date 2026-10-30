import gzip
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from netviser_audit.advisories import (AdvisoryDB, AdvisoryError, normalize_debian,
                                       normalize_redhat, normalize_ubuntu)
from netviser_audit.checks.base import Context
from netviser_audit.checks.patch import COLLECTOR, PatchCheck, source_package, vendor_release
from netviser_audit.cli import parse_cves
from netviser_audit.reporting import HostResult, write_csv
from netviser_audit.system import PRELUDE, build_script, parse_output
from netviser_audit.versions import dpkg_compare, rpm_compare, rpmvercmp

CVE = "CVE-2026-98432"

UBUNTU_DOC = {"id": CVE, "packages": [
    {"name": "linux", "statuses": [
        {"release_codename": "jammy", "status": "released", "description": "5.15.0-203.213"},
        {"release_codename": "noble", "status": "pending", "description": "6.8.0-149.149"},
        {"release_codename": "focal", "status": "needed", "description": ""},
        {"release_codename": "trusty", "status": "not-affected", "description": "3.11.0-12.19"},
        {"release_codename": "xenial", "status": "ignored", "description": "end of support"}]},
    {"name": "linux-hwe-6.8", "statuses": [
        {"release_codename": "jammy", "status": "released",
         "description": "6.8.0-149.149~22.04.1"}]},
    {"name": "firefox", "statuses": []}]}

DEBIAN_DOC = {"id": "DEBIAN-" + CVE, "affected": [
    {"package": {"name": "linux", "ecosystem": "Debian:12"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.1.190-1"}]}]},
    {"package": {"name": "linux", "ecosystem": "Debian:13"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
    {"package": {"name": "linux", "ecosystem": "Debian:11"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0"}]}]}]}

REDHAT_DOC = {"name": CVE, "affected_release": [
    {"product_name": "Red Hat Enterprise Linux 9", "cpe": "cpe:/o:redhat:enterprise_linux:9",
     "package": "kernel-0:5.14.0-503.40.1.el9_5", "advisory": "RHSA-2026:2000"},
    {"product_name": "Red Hat Enterprise Linux 9", "cpe": "cpe:/a:redhat:enterprise_linux:9",
     "package": "kernel-0:5.14.0-427.13.1.el9_4", "advisory": "RHSA-2026:1000"},
    {"product_name": "RHEL 9.2 EUS", "cpe": "cpe:/a:redhat:rhel_eus:9.2",
     "package": "kernel-0:5.14.0-284.55.1.el9_2", "advisory": "RHSA-2026:3000"},
    {"product_name": "Red Hat Enterprise Linux 9", "cpe": "cpe:/o:redhat:enterprise_linux:9",
     "package": "kpatch-patch", "advisory": "RHSA-2026:4000"}],
    "package_state": [
        {"product_name": "Red Hat Enterprise Linux 8", "cpe": "cpe:/o:redhat:enterprise_linux:8",
         "package_name": "kernel", "fix_state": "Affected"},
        {"product_name": "Red Hat Enterprise Linux 7", "cpe": "cpe:/o:redhat:enterprise_linux:7",
         "package_name": "kernel", "fix_state": "Not affected"},
        {"product_name": "Red Hat Enterprise Linux 6", "cpe": "cpe:/o:redhat:enterprise_linux:6",
         "package_name": "kernel", "fix_state": "Out of support scope"}]}

DOCS = {"ubuntu.com": UBUNTU_DOC, "osv.dev": DEBIAN_DOC, "redhat.com": REDHAT_DOC}


def fake_fetcher(url):
    for host, doc in DOCS.items():
        if host in url:
            return doc if CVE in url else None
    raise AssertionError(url)


def make_db():
    db = AdvisoryDB()
    db.fetch([CVE, "CVE-2099-0001"], ["ubuntu", "debian", "redhat"], fetcher=fake_fetcher)
    return db


UBUNTU = {"kernel_name": "Linux", "os_id": "ubuntu", "os_version_id": "22.04",
          "os_version_codename": "jammy", "kernel_release": "5.15.0-194-generic",
          "kernel_newest_installed": "5.15.0-194-generic", "kernel_pkg_format": "deb",
          "kernel_pkg_name": "linux-modules-5.15.0-194-generic",
          "kernel_pkg_version": "5.15.0-194.204", "kernel_pkg_source": "linux"}
DEBIAN = {"kernel_name": "Linux", "os_id": "debian", "os_version_id": "12",
          "os_version_codename": "bookworm", "kernel_pkg_format": "deb",
          "kernel_pkg_name": "linux-image-6.1.0-40-amd64", "kernel_pkg_version": "6.1.153-1",
          "kernel_pkg_source": "linux-signed-amd64"}
RHEL = {"kernel_name": "Linux", "os_id": "rhel", "os_version_id": "9.4",
        "kernel_pkg_format": "rpm", "kernel_pkg_name": "kernel-core",
        "kernel_pkg_version": "(none):5.14.0-427.13.1.el9_4"}


def assess(base, **overrides):
    facts = dict(base)
    facts.update(overrides)
    findings = PatchCheck().evaluate(facts, Context(cves=(CVE,), advisories=make_db()))
    return findings[0]


class VersionTests(unittest.TestCase):
    def test_dpkg(self):
        cases = [
            ("5.15.0-194.204", "5.15.0-203.213", -1),
            ("5.15.0-203.213", "5.15.0-203.213", 0),
            ("5.15.0-99.109", "5.15.0-101.111", -1),
            ("6.8.0-149.149~22.04.1", "6.8.0-149.149", -1),
            ("1.0~rc1", "1.0", -1),
            ("1:1.0", "2.0", 1),
            ("1.0a", "1.0", 1),
            ("1.0.1", "1.0a", 1),
            ("6.1.153-1", "6.1.190-1", -1),
            ("6.12.113-1~deb12u1", "6.12.113-1", -1),
            ("1.0-1", "1.0-1+b1", -1),
        ]
        for a, b, expected in cases:
            result = dpkg_compare(a, b)
            self.assertEqual((result > 0) - (result < 0), expected, (a, b))
            result = dpkg_compare(b, a)
            self.assertEqual((result > 0) - (result < 0), -expected, (b, a))

    def test_rpm(self):
        cases = [
            ("3.10.0-1160.53.1.el7", "3.10.0-1160.114.2.el7", -1),
            ("5.14.0-427.13.1.el9_4", "5.14.0-503.40.1.el9_5", -1),
            ("5.14.0-427.13.1.el9_4", "5.14.0-427.13.1.el9_4", 0),
            ("4.18.0-513.24.1.el8_9", "4.18.0-513.9.1.el8_9", 1),
            ("1.0~rc1", "1.0", -1),
            ("1.0^1", "1.0", 1),
            ("1.0^1", "1.0.1", -1),
            ("1.0a", "1.0.1", -1),
            ("1.010", "1.9", 1),
            ("1:1.0-1", "2.0-1", 1),
            ("(none):1.0-1", "0:1.0-1", 0),
        ]
        for a, b, expected in cases:
            result = rpm_compare(a, b) if "-" in a else rpmvercmp(a, b)
            reverse = rpm_compare(b, a) if "-" in a else rpmvercmp(b, a)
            self.assertEqual((result > 0) - (result < 0), expected, (a, b))
            self.assertEqual((reverse > 0) - (reverse < 0), -expected, (b, a))


class NormalizeTests(unittest.TestCase):
    def test_ubuntu_keeps_kernel_packages_only(self):
        record = normalize_ubuntu(UBUNTU_DOC)
        self.assertEqual(sorted(record["packages"]), ["linux", "linux-hwe-6.8"])
        self.assertEqual(record["packages"]["linux"]["jammy"], ["released", "5.15.0-203.213"])

    def test_debian(self):
        packages = normalize_debian(DEBIAN_DOC)["packages"]["linux"]
        self.assertEqual(packages["12"], ["fixed", "6.1.190-1"])
        self.assertEqual(packages["13"], ["unfixed", ""])

    def test_redhat_main_stream_earliest_fix(self):
        packages = normalize_redhat(REDHAT_DOC)["packages"]
        self.assertEqual(packages["kernel"]["9"]["fixed"], "0:5.14.0-427.13.1.el9_4")
        self.assertEqual(packages["kernel"]["9"]["advisory"], "RHSA-2026:1000")
        self.assertNotIn("9.2", packages["kernel"])
        self.assertEqual(packages["kernel"]["8"], {"state": "Affected"})
        self.assertNotIn("kpatch-patch", packages)

    def test_malformed_documents_do_not_crash(self):
        for doc in ({}, [], {"packages": "x"}, {"affected": [None, 1, {"package": []}]},
                    {"affected_release": [{"cpe": 1, "package": None}]}):
            normalize_ubuntu(doc)
            normalize_debian(doc)
            normalize_redhat(doc)


class AdvisoryDBTests(unittest.TestCase):
    def test_not_found_and_errors(self):
        db = make_db()
        self.assertTrue(db.get(CVE, "ubuntu")["found"])
        self.assertFalse(db.get("CVE-2099-0001", "ubuntu")["found"])

        def failing(url):
            raise AdvisoryError("timed out")
        db.fetch(["CVE-2024-1086"], ["ubuntu"], fetcher=failing)
        self.assertIsNone(db.get("CVE-2024-1086", "ubuntu"))
        self.assertEqual(db.error("CVE-2024-1086", "ubuntu"), "timed out")

    def test_save_and_load_round_trip(self):
        db = make_db()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            path = f.name
        self.addCleanup(os.unlink, path)
        db.save(path)
        loaded = AdvisoryDB.load(path)
        self.assertEqual(loaded.records, db.records)
        calls = []
        loaded.fetch([CVE], ["ubuntu"], fetcher=lambda url: calls.append(url))
        self.assertEqual(calls, [], "loaded records must not be fetched again")

    def test_load_rejects_unknown_format_and_filters_keys(self):
        with self.assertRaises(ValueError):
            AdvisoryDB.from_dict({"format": 99})
        db = AdvisoryDB.from_dict({"format": 1, "records": {
            "CVE-2024-1086": {"ubuntu": {"found": True}, "evil": {}},
            "not-a-cve": {"ubuntu": {"found": True}}}})
        self.assertEqual(list(db.records), ["CVE-2024-1086"])
        self.assertEqual(list(db.records["CVE-2024-1086"]), ["ubuntu"])


class MappingTests(unittest.TestCase):
    def test_vendor_release(self):
        self.assertEqual(vendor_release(UBUNTU), ("ubuntu", "jammy"))
        self.assertEqual(vendor_release(DEBIAN), ("debian", "12"))
        self.assertEqual(vendor_release(RHEL), ("redhat", "9"))
        self.assertEqual(vendor_release({"os_id": "rocky", "os_version_id": "8.10"}),
                         ("redhat", "8"))
        self.assertIsNone(vendor_release({"os_id": "fedora", "os_version_id": "41"}))
        self.assertIsNone(vendor_release({"os_id": "ubuntu", "os_version_id": "24.04"}))

    def test_source_package(self):
        for source, expected in (("linux", "linux"), ("linux-signed", "linux"),
                                 ("linux-signed-hwe-6.8", "linux-hwe-6.8"),
                                 ("linux-signed-amd64", "linux"),
                                 ("linux-signed-arm64", "linux"), ("linux-aws", "linux-aws")):
            self.assertEqual(source_package({"kernel_pkg_source": source}), expected, source)
        self.assertIsNone(source_package({"kernel_pkg_source": "unavailable"}))


class AssessTests(unittest.TestCase):
    def test_ubuntu_released_vulnerable(self):
        f = assess(UBUNTU)
        self.assertEqual((f.key, f.status, f.verdict), ("patch." + CVE, "REVIEW", "VULNERABLE"))
        self.assertIn("5.15.0-203.213", f.title)
        self.assertIn("reboot", f.detail)

    def test_ubuntu_patched(self):
        self.assertEqual(assess(UBUNTU, kernel_pkg_version="5.15.0-210.220").verdict, "PATCHED")
        self.assertEqual(assess(UBUNTU, kernel_pkg_version="5.15.0-203.213").status, "OK")

    def test_ubuntu_vulnerable_with_newer_kernel_installed(self):
        f = assess(UBUNTU, kernel_newest_installed="5.15.0-210-generic")
        self.assertEqual(f.verdict, "VULNERABLE")
        self.assertIn("5.15.0-210-generic is already installed", f.detail)

    def test_ubuntu_statuses(self):
        cases = {"noble": "FIX_PENDING", "focal": "FIX_NOT_AVAILABLE", "trusty": "NOT_AFFECTED",
                 "xenial": "WONT_FIX", "plucky": "NO_DATA"}
        for codename, verdict in cases.items():
            self.assertEqual(assess(UBUNTU, os_version_codename=codename).verdict, verdict,
                             codename)

    def test_ubuntu_pending_already_installed(self):
        f = assess(UBUNTU, os_version_codename="noble", kernel_pkg_version="6.8.0-149.149")
        self.assertEqual(f.verdict, "PATCHED")

    def test_ubuntu_hwe_source(self):
        f = assess(UBUNTU, kernel_pkg_source="linux-hwe-6.8",
                   kernel_pkg_version="6.8.0-149.149~22.04.1")
        self.assertEqual(f.verdict, "PATCHED")
        f = assess(UBUNTU, kernel_pkg_source="linux-azure")
        self.assertEqual(f.verdict, "NO_DATA")

    def test_debian(self):
        self.assertEqual(assess(DEBIAN).verdict, "VULNERABLE")
        self.assertEqual(assess(DEBIAN, kernel_pkg_version="6.1.190-1").verdict, "PATCHED")
        self.assertEqual(assess(DEBIAN, os_version_id="13").verdict, "FIX_NOT_AVAILABLE")
        self.assertEqual(assess(DEBIAN, os_version_id="11").verdict, "NOT_AFFECTED")
        self.assertEqual(assess(DEBIAN, os_version_id="10").verdict, "NO_DATA")

    def test_redhat(self):
        f = assess(RHEL)
        self.assertEqual(f.verdict, "PATCHED")
        self.assertNotIn("(none)", f.title)
        f = assess(RHEL, kernel_pkg_version="0:5.14.0-362.8.1.el9_3")
        self.assertEqual(f.verdict, "VULNERABLE")
        self.assertIn("RHSA-2026:1000", f.detail)
        self.assertEqual(assess(RHEL, os_version_id="8.10").verdict, "FIX_NOT_AVAILABLE")
        self.assertEqual(assess(RHEL, os_version_id="6.10").verdict, "WONT_FIX")
        self.assertEqual(assess(RHEL, kernel_pkg_name="kernel-rt-core").verdict, "NO_DATA")

    def test_rebuilds_and_centos(self):
        f = assess(RHEL, os_id="rocky")
        self.assertEqual(f.verdict, "PATCHED")
        f = assess(RHEL, os_id="almalinux", kernel_pkg_version="0:5.14.0-362.8.1.el9_3")
        self.assertIn("AlmaLinux rebuilds", f.detail)
        f = assess(RHEL, os_id="centos", os_version_id="7",
                   kernel_pkg_version="(none):3.10.0-1160.53.1.el7")
        self.assertEqual(f.verdict, "NOT_AFFECTED")
        self.assertIn("end-of-life", f.detail)

    def test_livepatch_overrides_open_verdicts(self):
        f = assess(UBUNTU, **{"cve.CVE_2026_98432.livepatch": "yes"})
        self.assertEqual((f.verdict, f.status), ("LIVEPATCHED", "OK"))
        f = assess(UBUNTU, os_version_codename="trusty", **{"cve.CVE_2026_98432.livepatch": "yes"})
        self.assertEqual(f.verdict, "NOT_AFFECTED")

    def test_changelog_only_used_without_vendor_verdict(self):
        f = assess(UBUNTU, kernel_pkg_source="linux-azure",
                   **{"cve.CVE_2026_98432.changelog": "yes"})
        self.assertEqual((f.verdict, f.status), ("MENTIONED_IN_CHANGELOG", "INFO"))
        f = assess(UBUNTU, **{"cve.CVE_2026_98432.changelog": "yes"})
        self.assertEqual(f.verdict, "VULNERABLE")

    def test_unknown_cve_unsupported_os_and_missing_data(self):
        facts = dict(UBUNTU)
        f = PatchCheck().evaluate(facts, Context(cves=("CVE-2099-0001",), advisories=make_db()))[0]
        self.assertEqual(f.verdict, "NO_DATA")
        self.assertEqual(assess(UBUNTU, os_id="fedora").verdict, "UNSUPPORTED")
        self.assertEqual(assess(UBUNTU, kernel_pkg_version="unavailable").verdict, "NOT_CHECKED")
        self.assertEqual(assess(UBUNTU, kernel_name="Darwin").verdict, "NOT_CHECKED")
        f = PatchCheck().evaluate(dict(UBUNTU), Context(cves=(CVE,), offline=True))[0]
        self.assertEqual((f.verdict, f.status), ("NOT_CHECKED", "UNKNOWN"))
        self.assertIn("--offline", f.detail)

    def test_no_context_no_findings(self):
        self.assertEqual(PatchCheck().evaluate(dict(UBUNTU)), [])


def _executable(directory, name, body):
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def run_collector(self, collector, cves):
        script = PRELUDE + "NV_CVES='%s'\n" % " ".join(cves) + collector + "nv_kv __end 1\n"
        out = subprocess.run(["sh", "-s"], input=script, text=True, capture_output=True,
                             timeout=30).stdout
        facts, complete = parse_output(out)
        self.assertTrue(complete)
        return facts

    def test_deb_package_and_changelog(self):
        # Not-installed packages ("un") must be skipped.
        dpkg = _executable(self.dir, "dpkg-query", """
case "$3" in
  linux-modules-*) exit 1 ;;
  linux-image-unsigned-*) printf 'un |linux-image-unsigned-6.8.0-1-generic||' ;;
  linux-image-*) printf 'ii |linux-image-6.8.0-1-generic|6.8.0-1.1|linux-signed-hwe-6.8 (6.8.0-1.1)' ;;
esac
""")
        docdir = os.path.join(self.dir, "doc", "linux-image-6.8.0-1-generic")
        os.makedirs(docdir)
        with gzip.open(os.path.join(docdir, "changelog.Debian.gz"), "wt") as f:
            f.write("  * fix use-after-free (CVE-2024-1086)\n  - CVE-2023-00011\n")
        collector = (COLLECTOR.replace("dpkg-query", dpkg)
                     .replace("/usr/share/doc/", os.path.join(self.dir, "doc") + "/"))
        facts = self.run_collector(collector, ["CVE-2024-1086", "CVE-2023-0001", "CVE-2026-98432"])
        self.assertEqual(facts["kernel_pkg_format"], "deb")
        self.assertEqual(facts["kernel_pkg_name"], "linux-image-6.8.0-1-generic")
        self.assertEqual(facts["kernel_pkg_version"], "6.8.0-1.1")
        self.assertEqual(facts["kernel_pkg_source"], "linux-signed-hwe-6.8")
        self.assertEqual(facts["cve.CVE_2024_1086.changelog"], "yes")
        self.assertEqual(facts["cve.CVE_2023_0001.changelog"], "no")
        self.assertEqual(facts["cve.CVE_2026_98432.changelog"], "no")
        self.assertEqual(facts["cve.CVE_2026_98432.livepatch"], "unavailable")

    def test_rpm_package_and_changelog(self):
        rpm = _executable(self.dir, "fake-rpm", """
case "$*" in
  *--qf*) printf 'kernel-core|(none):5.14.0-427.13.1.el9_4\\n' ;;
  *--changelog*) printf -- '- net: fix uaf (CVE-2026-98432)\\n' ;;
  *) exit 1 ;;
esac
""")
        collector = (COLLECTOR.replace("nv_have dpkg-query", "false")
                     .replace("nv_have rpm", "nv_have " + rpm).replace("rpm -q", rpm + " -q"))
        facts = self.run_collector(collector, [CVE])
        self.assertEqual(facts["kernel_pkg_format"], "rpm")
        self.assertEqual(facts["kernel_pkg_name"], "kernel-core")
        self.assertEqual(facts["kernel_pkg_version"], "(none):5.14.0-427.13.1.el9_4")
        self.assertEqual(facts["cve.CVE_2026_98432.changelog"], "yes")
        self.assertEqual(facts["cve.CVE_2026_98432.livepatch"], "unavailable")

    def test_no_package_manager(self):
        collector = COLLECTOR.replace("nv_have dpkg-query", "false").replace("nv_have rpm", "false")
        facts = self.run_collector(collector, [CVE])
        self.assertEqual(facts["kernel_pkg_format"], "unavailable")
        self.assertEqual(facts["kernel_pkg_version"], "unavailable")
        self.assertEqual(facts["cve.CVE_2026_98432.changelog"], "unavailable")


class ScriptAndCliTests(unittest.TestCase):
    def test_cve_ids_are_validated_before_entering_the_script(self):
        for bad in ("CVE-2024-1086'; reboot; '", "CVE-2024-1", "cve-2024-1086 x", "$(id)"):
            with self.assertRaises(ValueError):
                build_script([PatchCheck()], cves=[bad])
        self.assertIn("NV_CVES='CVE-2024-1086 CVE-2026-98432'",
                      build_script([PatchCheck()], cves=["CVE-2024-1086", CVE]))

    def test_parse_cves(self):
        self.assertEqual(parse_cves(["cve-2024-1086,CVE-2026-98432", "CVE-2024-1086"]),
                         ["CVE-2024-1086", "CVE-2026-98432"])
        with self.assertRaises(ValueError):
            parse_cves(["CVE-2024-1086;id"])

    def test_csv_has_one_column_per_cve(self):
        facts = dict(UBUNTU)
        findings = PatchCheck().evaluate(
            facts, Context(cves=(CVE, "CVE-2099-0001"), advisories=make_db()))
        out = io.StringIO()
        write_csv(out, [HostResult("h1", "ok", facts=facts, findings=findings)], [PatchCheck()])
        header, row = out.getvalue().splitlines()
        self.assertIn("patch.%s" % CVE, header.split(","))
        self.assertIn("patch.CVE-2099-0001", header.split(","))
        self.assertIn("REVIEW:VULNERABLE", row)
        self.assertIn("UNKNOWN:NO_DATA", row)

    def test_report_is_json_serialisable(self):
        db = make_db()
        json.dumps(db.summary())
        json.dumps(db.to_dict())


if __name__ == "__main__":
    unittest.main()
