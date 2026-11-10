"""Synthetic KMI Guard tests; no device or proprietary modules required."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from scripts import kmi_guard


class KmiGuardTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        (self.path / "symvers").write_text(
            "0x12345678\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\t\n"
            "0xabcdef01\tschedule\tvmlinux\tEXPORT_SYMBOL\t\n"
            "0x99999999\tvendor_private\tvendor.ko\tEXPORT_SYMBOL\t\n"
        )
        (self.path / "config").write_text(
            "CONFIG_MODVERSIONS=y\n"
            "# CONFIG_CGROUP_PIDS is not set\n"
            "# CONFIG_CFS_BANDWIDTH is not set\n"
        )

    def manifest(self, crc="0xabcdef01", imports=None, error="", fingerprint="oneplus13-test-build"):
        obj = {
            "schema_version": 1,
            "device_build_fingerprint": fingerprint,
            "sources": [{"label": "vendor_dlkm", "module_count": 1}],
            "modules": [{
                "path": "vendor_dlkm/test.ko",
                "boot_requested": True,
                "boot_critical_reviewed": False,
                "required_crcs": imports if imports is not None else {
                    "module_layout": "0x12345678", "schedule": crc
                },
                "capture_error": error,
            }],
        }
        (self.path / "vendor.json").write_text(json.dumps(obj))
        return self.path / "vendor.json"

    def run_audit(self, manifest=None, mode="audit", baseline=None,
                  before=None, after=None, approve=True):
        argv = [
            "audit", "--symvers", str(self.path / "symvers"),
            "--config", str(self.path / "config"),
            "--mode", mode, "--report-json", str(self.path / "report.json"),
            "--report-md", str(self.path / "report.md"),
        ]
        if manifest:
            argv += ["--vendor-manifest", str(manifest)]
            if approve:
                data = json.loads(manifest.read_text())
                approval = {
                    "schema_version": 1,
                    "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                    "device_build_fingerprint": data["device_build_fingerprint"],
                    "verified_sources": [s["label"] for s in data["sources"]],
                    "startup_load_lists_verified": True,
                }
                (self.path / "approval.json").write_text(json.dumps(approval))
                argv += ["--approved-manifest", str(self.path / "approval.json")]
        if baseline:
            argv += ["--baseline-symvers", str(baseline)]
        if before:
            argv += ["--baseline-layouts", str(before)]
        if after:
            argv += ["--candidate-layouts", str(after)]
        rc = kmi_guard.main(argv)
        return rc, json.loads((self.path / "report.json").read_text())

    def test_matching_imports(self):
        rc, r = self.run_audit(self.manifest(), mode="enforce")
        self.assertEqual(rc, 0)
        self.assertEqual(r["status"], "NO_CHECKED_MISMATCH")
        self.assertEqual(r["checked_import_count"], 2)

    def test_mismatched_crc_definitely_rejects_module(self):
        rc, r = self.run_audit(self.manifest(crc="0xabcdef02"), mode="enforce")
        self.assertEqual(rc, 3)
        self.assertEqual(r["status"], "MODULE_LOAD_REJECTION")
        self.assertEqual(r["definite_module_rejections"][0]["symbol"], "schedule")

    def test_hex_case_equivalence(self):
        self.assertEqual(self.run_audit(self.manifest(crc="0xABCDEF01"), "enforce")[0], 0)

    def test_missing_vendor_manifest_is_unverified_not_pass(self):
        rc, r = self.run_audit(mode="enforce")
        self.assertEqual(rc, 3)
        self.assertEqual(r["status"], "UNVERIFIED")

    def test_external_module_symbol_is_not_vmlinux(self):
        rc, r = self.run_audit(self.manifest(imports={
            "vendor_private": "0x99999999", "schedule": "0xabcdef01"
        }))
        self.assertEqual(rc, 0)
        self.assertEqual(r["status"], "UNVERIFIED")
        self.assertEqual(r["definite_module_rejections"], [])

    def test_baseline_proves_missing_export(self):
        baseline = self.path / "baseline"
        baseline.write_text("0xaabbccdd\told_kernel_symbol\tvmlinux\tEXPORT_SYMBOL\t\n")
        rc, r = self.run_audit(self.manifest(imports={
            "old_kernel_symbol": "0xaabbccdd"
        }), mode="enforce", baseline=baseline)
        self.assertEqual(rc, 3)
        self.assertIsNone(r["definite_module_rejections"][0]["kernel_crc"])

    def test_partial_module_capture_cannot_pass_enforce(self):
        rc, r = self.run_audit(self.manifest(error="missing modversion section"), "enforce")
        self.assertEqual(rc, 3)
        self.assertEqual(r["status"], "UNVERIFIED")

    def test_incomplete_vendor_manifest_requires_review(self):
        rc, r = self.run_audit(self.manifest(), "enforce", approve=False)
        self.assertEqual(rc, 3)
        self.assertEqual(r["status"], "UNVERIFIED")
        self.assertTrue(any("not approved" in s for s in r["unverified"]))

    def test_missing_fingerprint_cannot_pass_enforce(self):
        rc, r = self.run_audit(self.manifest(fingerprint="UNVERIFIED"), "enforce")
        self.assertEqual(rc, 3)
        self.assertEqual(r["status"], "UNVERIFIED")

    def test_known_bad_config_is_risk_not_proof(self):
        with (self.path / "config").open("a") as file:
            file.write("CONFIG_CGROUP_PIDS=y\n")
        rc, r = self.run_audit(self.manifest())
        self.assertEqual(rc, 0)
        self.assertEqual(r["status"], "NO_CHECKED_MISMATCH")
        self.assertTrue(any(x["kind"] == "KNOWN_KMI_HAZARD" for x in r["potential_risks"]))

    def test_no_modversions_is_error(self):
        (self.path / "config").write_text("# CONFIG_MODVERSIONS is not set\n")
        rc = kmi_guard.main([
            "audit", "--symvers", str(self.path / "symvers"),
            "--config", str(self.path / "config"),
            "--report-json", str(self.path / "report.json"),
            "--report-md", str(self.path / "report.md"),
        ])
        self.assertEqual(rc, 2)

    def test_ignore_exports_from_other_modules(self):
        exports = kmi_guard.symbol_table(self.path / "symvers")
        self.assertNotIn("vendor_private", exports)
        self.assertEqual(exports["schedule"], "0xabcdef01")

    def test_compressed_module_name_matches_modules_load(self):
        self.assertEqual(kmi_guard.module_key("subdir/foo-bar.ko.zst"), "foo_bar")
        self.assertEqual(kmi_guard.module_key("foo-bar.ko.xz"), "foo_bar")
        self.assertEqual(kmi_guard.module_key("foo-bar.ko.gz"), "foo_bar")
        self.assertEqual(kmi_guard.module_key("foo-bar.ko"), "foo_bar")
        load = self.path / "modules.load"
        load.write_text("# boot modules\nfoo-bar.ko\n")
        self.assertEqual(kmi_guard.module_names([load]), {"foo_bar"})

    def test_capture_compressed_module_with_multiple_roots(self):
        from unittest.mock import patch
        import hashlib
        one = self.path / "vendor"
        two = self.path / "odm"
        one.mkdir()
        two.mkdir()
        (one / "my-device.ko.zst").write_bytes(b"compressed")
        (two / "test2.ko.xz").write_bytes(b"compressed2")
        load = self.path / "modules.load"
        load.write_text("my-device.ko\n")
        def fake_command(cmd):
            if "--show-modversions" in cmd:
                return "0x12345678\tmodule_layout\n", ""
            return "6.6.144 SMP modversions\n", ""
        with patch.object(kmi_guard, "command", side_effect=fake_command):
            rc = kmi_guard.main([
                "capture", "--modules-root", str(one),
                "--modules-root", str(two),
                "--modules-load", str(load),
                "--fingerprint", "verified-build",
                "--output", str(self.path / "captured.json"),
            ])
        self.assertEqual(rc, 0)
        rows = json.loads((self.path / "captured.json").read_text())["modules"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0]["boot_requested"])
        self.assertFalse(rows[1]["boot_requested"])
        self.assertEqual(rows[0]["module_sha256"], hashlib.sha256(b"compressed").hexdigest())

    def test_layout_difference_is_risk_not_proven_rejection(self):
        (self.path / "before").write_text("old\n")
        (self.path / "after").write_text("new\n")
        rc, r = self.run_audit(
            self.manifest(), mode="enforce",
            before=self.path / "before", after=self.path / "after"
        )
        self.assertEqual(rc, 0)
        self.assertTrue(any(x["kind"] == "MONITORED_TYPE_LAYOUT_DIFF"
                            for x in r["potential_risks"]))


if __name__ == "__main__":
    unittest.main()
