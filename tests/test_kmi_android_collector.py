"""Read-only Android ELF collector tests; no rooted device required."""
import json
import struct
import subprocess
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

    def test_nobits_section_has_no_file_bytes(self):
        # ELF64 with a .bss section whose memory size exceeds file length.
        # SHT_NOBITS carries no actual payload and must not be rejected.
        strings = b"\x00.shstrtab\x00.bss\x00"
        hdr = bytearray(64)
        hdr[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", hdr, 40, 64)
        struct.pack_into("<HHH", hdr, 58, 64, 3, 1)
        def section(name_id, typ, offset, size):
            return struct.pack("<IIQQQQIIQQ", name_id, typ, 0, 0,
                               offset, size, 0, 0, 1, 0)
        blob = (bytes(hdr) + bytes(64) +
                section(1, 3, 64 + 64 * 3, len(strings)) +
                section(11, 8, 1_000_000, 1_000_000) + strings)
        sections = collect.elf_sections(blob)
        self.assertEqual(sections[".shstrtab"][0], strings)
        self.assertEqual(sections[".bss"][0], b"")

    def test_export_crc_from_symbols_and_kcrctab(self):
        # Tiny synthetic relocatable ELF with a GPL export and matching
        # __crc_test_func symbol pointing into __kcrctab_gpl.
        names = b"\x00.shstrtab\x00.strtab\x00.symtab\x00__kcrctab_gpl\x00__ksymtab_gpl\x00"
        sym_names = b"\x00__ksymtab_test_func\x00__crc_test_func\x00"
        crc = struct.pack("<I", 0x12345678)
        symzero = bytes(24)
        def sym_entry(name, section, value):
            return struct.pack("<IBBHQQ", sym_names.index(name), 0, 0,
                               section, value, 0)
        syms = (symzero + sym_entry(b"__ksymtab_test_func", 5, 0) +
                sym_entry(b"__crc_test_func", 4, 0))
        section_blobs = [b"", names, sym_names, syms, crc, bytes(12)]
        offset = 64 + 6 * 64
        descriptors = []
        payload = b""
        section_names = ["", ".shstrtab", ".strtab", ".symtab",
                         "__kcrctab_gpl", "__ksymtab_gpl"]
        for i, (name, blob) in enumerate(zip(section_names, section_blobs)):
            header_type = 0 if i == 0 else 2 if i == 3 else 3 if i in (1, 2) else 1
            descriptors.append(struct.pack(
                "<IIQQQQIIQQ", names.index(name.encode()) if name else 0,
                header_type, 0, 0, offset, len(blob),
                2 if i == 3 else 0, 0, 8, 24 if i == 3 else 0
            ))
            payload += blob
            offset += len(blob)
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", header, 40, 64)
        struct.pack_into("<HHH", header, 58, 64, 6, 1)
        elf = bytes(header) + b"".join(descriptors) + payload
        exports, note = collect.elf_exported_crcs(elf)
        self.assertEqual(exports, {"test_func": "0x12345678"})
        self.assertEqual(note, "")

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

    def test_termux_wrapper_shell_syntax(self):
        root = Path(__file__).resolve().parents[1] / "scripts"
        for name in ("kmi_capture_termux.sh", "kmi_capture_btf_termux.sh",
                     "kmi_next_stage_termux.sh"):
            with self.subTest(script=name):
                script = root / name
                proc = subprocess.run(["bash", "-n", str(script)],
                                      capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_default_output_is_saf_accessible_documents(self):
        with patch.object(collect, "collect", return_value=0) as action:
            self.assertEqual(collect.main([]), 0)
        destination = action.call_args.args[0].output
        self.assertTrue(destination.startswith(
            "/sdcard/Documents/KMI-Guard/android-kmi-vendor-"))
        self.assertTrue(destination.endswith(".json"))

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
