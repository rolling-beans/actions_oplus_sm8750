"""Checks STG CRC differences remain separate from boot-failure assertions."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts import kmi_stg_crc_diff as audit


class STGCRCCompareTests(unittest.TestCase):
    def setUp(self):
        self.stg = (
            'version: 0x00000002\n'
            'elf_symbol {\n  id: 0x1\n  name: "sk_filter_trim_cap"\n'
            '  is_defined: true\n  symbol_type: FUNCTION\n'
            '  crc: 0x553e24af\n}\n'
            'elf_symbol {\n  id: 0x2\n  name: "icc_put"\n'
            '  is_defined: true\n  crc: 0x3\n}\n'
            'elf_symbol {\n  id: 0x3\n  name: "other"\n'
            '  is_defined: true\n  crc: 0x7\n}\n'
        )
        self.symvers = (
            "0x43eebd89\tsk_filter_trim_cap\tvmlinux\tEXPORT_SYMBOL\t\n"
            "0x00000003\ticc_put\tvmlinux\tEXPORT_SYMBOL\t\n"
            "0x00000007\tother\tvmlinux\tEXPORT_SYMBOL\t\n"
        )

    def test_detects_crc_change_but_never_predicts_bootloop(self):
        data = audit.compare(self.stg, self.symvers)
        self.assertEqual(data["status"], "STG_CRC_DIFFERENCE")
        self.assertEqual(data["mismatched"], 1)
        self.assertEqual(data["matched"], 2)
        self.assertEqual(data["mismatch_groups"], {"bpf_socket_xdp": 1})
        self.assertEqual(data["mismatches"][0]["reference_crc"], "0x553e24af")
        self.assertEqual(data["mismatches"][0]["candidate_crc"], "0x43eebd89")
        self.assertFalse(data["guaranteed_android_boot_failure"])
        self.assertFalse(data["guaranteed_module_load_failure"])

    def test_equivalent_stg_and_symvers(self):
        source = self.symvers.replace("0x43eebd89", "0x553e24af")
        self.assertEqual(audit.compare(self.stg, source)["status"],
                         "NO_CHECKED_CRC_DIFFERENCE")

    def test_missing_export_does_not_count_as_crc_mismatch(self):
        source = self.symvers.splitlines()[1] + "\n"
        data = audit.compare(self.stg, source)
        self.assertEqual(data["mismatched"], 0)
        self.assertEqual(data["overlap_compared"], 1)

    def test_ambiguous_stg_reference_fails_closed(self):
        stg = self.stg + (
            'elf_symbol {\n  id: 0x4\n  name: "sk_filter_trim_cap"\n'
            '  is_defined: true\n  crc: 0x9\n}\n'
        )
        data = audit.compare(stg, self.symvers)
        self.assertIn("sk_filter_trim_cap", data["ambiguous_reference_names"])
        self.assertNotIn("sk_filter_trim_cap",
                         [x["symbol"] for x in data["mismatches"]])

    def test_non_vmlinux_provider_not_compared(self):
        symvers = "0x553e24af\tsk_filter_trim_cap\texternal.ko\tEXPORT_SYMBOL\n"
        with self.assertRaisesRegex(ValueError, "empty"):
            audit.compare(self.stg, symvers)

    def test_cli_produces_json_and_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "abi.stg").write_text(self.stg)
            (root / "vmlinux.symvers").write_text(self.symvers)
            rc = audit.main([
                "--stg", str(root / "abi.stg"),
                "--symvers", str(root / "vmlinux.symvers"),
                "--report-json", str(root / "audit.json"),
                "--report-md", str(root / "audit.md"),
            ])
            self.assertEqual(rc, 0)
            self.assertIn("sk_filter_trim_cap", (root / "audit.md").read_text())
            self.assertEqual(json.loads((root / "audit.json").read_text())
                             ["mismatched"], 1)


if __name__ == "__main__":
    unittest.main()
