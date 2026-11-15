"""Cross-manifest import matching and private/public evidence separation."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from scripts.kmi_compare_module_imports import (
    compare_manifests, main, read_source_manifests
)


def mod(path, req, exp=None, **kwargs):
    return {"path": path, "required_crcs": req, "exported_crcs": exp or {},
            "capture_error": "", "export_capture_note": "", **kwargs}


def symvers(**syms):
    return {key: f"0x{value:08x}" for key, value in syms.items()}


BASE = symvers(sk_filter_trim_cap=0x11111111, bpf_prog_create=0xabababab,
               strp_init=0x88888888, module_layout=0x12345678)
ALT = symvers(sk_filter_trim_cap=0x22222222, bpf_prog_create=0xcdcdcdcd,
              module_layout=0x12345678)


class PrivateModuleABTests(unittest.TestCase):
    def setUp(self):
        self.modules = [
            mod("vendor/alpha.ko",
                {"sk_filter_trim_cap": "0x22222222",
                 "bpf_prog_create": "0xabababab",
                 "strp_init": "0x88888888",
                 "rfkill_alloc": "0x12345678"}),
            mod("system_dlkm/rfkill.ko", {"module_layout": "0x12345678"},
                {"rfkill_alloc": "0x12345678"})]

    def test_recovers_bluetooth_but_catches_new_mismatches_and_removal(self):
        pub, private = compare_manifests(self.modules, BASE, ALT)
        self.assertEqual(pub["module_count"], 2)
        self.assertEqual(pub["observed_required_import_count"], 5)
        self.assertEqual(pub["baseline"]["crc_mismatch"], 1)
        self.assertEqual(pub["variant"]["crc_mismatch"], 1)
        self.assertEqual(pub["variant"]["missing_export"], 1)
        self.assertEqual(pub["baseline"]["matched"], 4)
        self.assertEqual(pub["variant"]["matched"], 3)
        self.assertEqual(pub["sk_filter_trim_cap"]["supplied_importer_count"], 1)
        self.assertEqual(pub["baseline_definite_rejection_modules"], 1)
        self.assertEqual(pub["variant_definite_rejection_modules"], 1)
        self.assertIn("vendor/alpha.ko", private["delta_importers"]["sk_filter_trim_cap"])

    def test_module_provider_crosses_manifest_boundaries(self):
        pub, _ = compare_manifests(self.modules, BASE, ALT)
        self.assertEqual(pub["baseline"].get("unknown_provider"), None)

    def test_ambiguous_providers_not_silent(self):
        self.modules.append(mod("system_dlkm/rfkill_alt.ko",
                                {"module_layout": "0x12345678"},
                                {"rfkill_alloc": "0x12345678"}))
        pub, _ = compare_manifests(self.modules, BASE, ALT)
        self.assertEqual(pub["variant"]["ambiguous_provider"], 1)

    def test_unknown_provider_not_silent(self):
        self.modules[1]["exported_crcs"] = {}
        pub, _ = compare_manifests(self.modules, BASE, ALT)
        self.assertEqual(pub["variant"]["unknown_provider"], 1)

    def test_bad_or_duplicate_manifests_fail(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw = {"schema_version": 1, "sources": [{"label": "vendor"}],
                   "modules": [self.modules[0]]}
            a = root / "a.json"
            a.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                read_source_manifests([a, a])
            raw["modules"][0]["required_crcs"]["bad"] = "NOTHEX"
            a.write_text(json.dumps(raw))
            with self.assertRaises(ValueError):
                read_source_manifests([a])

    def test_output_privacy_and_completeness(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for key, syms in (("on", BASE), ("off", ALT)):
                (root / (key + ".symvers")).write_text(
                    "".join(f"{crc}\t{name}\tvmlinux\tEXPORT_SYMBOL\n"
                            for name, crc in syms.items()))
            for key, module in (("vendor", self.modules[0]),
                                ("system", self.modules[1])):
                (root / (key + ".json")).write_text(json.dumps({
                    "schema_version": 1,
                    "sources": [{"label": key, "available": True,
                                 "module_count": 1}],
                    "modules": [module]}))
            private, public = root / "private.json", root / "public.json"
            rc = main(["--manifest", str(root / "vendor.json"),
                       "--manifest", str(root / "system.json"),
                       "--baseline-symvers", str(root / "on.symvers"),
                       "--variant-symvers", str(root / "off.symvers"),
                       "--expected-modules", "2", "--expected-imports", "5",
                       "--private-report", str(private),
                       "--public-report", str(public)])
            self.assertEqual(rc, 0)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
            self.assertNotIn("vendor/alpha", public.read_text())
            self.assertNotIn("system_dlkm/rfkill", public.read_text())
            self.assertEqual(json.loads(public.read_text())["status"],
                             "COMPLETE_FOR_SUPPLIED_MANIFESTS")
            self.assertEqual(len(json.loads(private.read_text())
                                 ["input_manifest_sha256"]), 2)
            # Missing modules and incomplete imports must prevent COMPLETE.
            private = root / "private-second.json"
            rc = main(["--manifest", str(root / "vendor.json"),
                       "--manifest", str(root / "system.json"),
                       "--baseline-symvers", str(root / "on.symvers"),
                       "--variant-symvers", str(root / "off.symvers"),
                       "--expected-modules", "593", "--expected-imports", "34353",
                       "--private-report", str(private),
                       "--public-report", str(public)])
            self.assertEqual(rc, 2)
            self.assertEqual(json.loads(public.read_text())["status"],
                             "PARTIAL_OR_UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
