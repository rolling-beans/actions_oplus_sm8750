"""Read-only Android ELF collector tests; no rooted device required."""
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import kmi_collect_android as collect


class AndroidKmiCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_linux_6_6_basic_64_byte_versions(self):
        blob = (struct.pack("<Q", 0x12345678) +
                b"module_layout\0".ljust(56, b"\0"))
        sections = {
            "__versions": (blob, 0),
            ".modinfo": (b"vermagic=6.6.144-test SMP modversions \0", 0),
        }
        with patch.object(collect, "get_elf_bytes", return_value=b"ELF"), \
             patch.object(collect, "elf_sections", return_value=sections):
            crcs, magic = collect.parse_module(self.root / "a.ko")
        self.assertEqual(crcs, {"module_layout": "0x12345678"})
        self.assertTrue(magic.startswith("6.6.144-test"))

    def test_extended_modversions_preferred(self):
        sections = {
            "__versions": (b"invalid basic", 0),
            "__version_ext_names": (b"module_layout\0schedule\0", 0),
            "__version_ext_crcs": (struct.pack("<II", 0x12345678, 0xabcdef01), 0),
            ".modinfo": (b"vermagic=6.6.144-test\0", 0),
        }
        with patch.object(collect, "get_elf_bytes", return_value=b"ELF"), \
             patch.object(collect, "elf_sections", return_value=sections):
            crcs, _ = collect.parse_module(self.root / "a.ko")
        self.assertEqual(crcs["schedule"], "0xabcdef01")
        self.assertEqual(len(crcs), 2)

    def test_unknown_versions_fail_closed(self):
        with patch.object(collect, "get_elf_bytes", return_value=b"ELF"), \
             patch.object(collect, "elf_sections", return_value={".modinfo": (b"", 0)}):
            with self.assertRaisesRegex(ValueError, "no MODVERSIONS"):
                collect.parse_module(self.root / "a.ko")

    def test_vendor_load_list_in_separate_etc_directory(self):
        root = self.root / "vendor_dlkm" / "lib" / "modules"
        root.mkdir(parents=True)
        (root / "foo-bar.ko").write_bytes(b"not-an-elf")
        policy = self.root / "vendor_dlkm" / "etc"
        policy.mkdir(parents=True)
        (policy / "modules.load").write_text("foo-bar.ko\n")
        args = type("Arg", (), {"root": [("vendor", str(root))],
                                "output": str(self.root / "capture.json")})()
        with patch.dict(collect.LOAD_LIST_DIRS, {"vendor": (str(policy),)}), \
             patch.object(collect, "prop", return_value="test-fingerprint"):
            rc = collect.collect(args)
        manifest = json.loads((self.root / "capture.json").read_text())
        self.assertEqual(rc, 0)
        self.assertEqual(len(manifest["load_lists"]), 1)
        self.assertEqual(manifest["load_lists"][0]["entries"], ["foo-bar.ko"])
        self.assertTrue(manifest["modules"][0]["boot_requested"])

    def test_metadata_only_no_modules_copied(self):
        source = self.root / "vendor"
        source.mkdir()
        binary = source / "foo-bar.ko"
        binary.write_bytes(b"not-an-elf")
        (source / "modules.load").write_text("foo-bar.ko\n")
        with patch.object(collect, "prop", return_value="test-fingerprint"):
            args = type("Arg", (), {"root": [("vendor", str(source))],
                                    "output": str(self.root / "manifest.json")})()
            rc = collect.collect(args)
        self.assertEqual(rc, 0)
        manifest = json.loads((self.root / "manifest.json").read_text())
        self.assertEqual(manifest["sources"][0]["module_count"], 1)
        self.assertEqual(len(manifest["modules"]), 1)
        self.assertTrue(manifest["modules"][0]["boot_requested"])
        self.assertTrue(manifest["modules"][0]["capture_error"])
        self.assertNotIn("binary_data", manifest["modules"][0])
        self.assertEqual(manifest["modules"][0]["module_sha256"], __import__("hashlib").sha256(b"not-an-elf").hexdigest())


if __name__ == "__main__":
    unittest.main()
