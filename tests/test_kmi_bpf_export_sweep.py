"""Unit tests for bounded object-level BPF CRC sweep and fail-closed reports."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts import kmi_bpf_export_sweep as sweep


class ExportCRCSweepTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.control = self.root / "control"
        self.variant = self.root / "variant"
        files = {
            "net/core/filter.c": (
                "EXPORT_SYMBOL_GPL(sk_filter_trim_cap);\n"
                "EXPORT_PER_CPU_SYMBOL_GPL(bpf_redirect_info);\n"
            ),
            "net/core/skmsg.c": "EXPORT_SYMBOL_GPL(sk_msg_alloc);\n",
            "net/ipv4/tcp_bpf.c": "EXPORT_SYMBOL_GPL(tcp_bpf_sendmsg_redir);\n",
        }
        for name, value in files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        self.crcs = {
            "sk_filter_trim_cap": (0x553e24af, 0x43eebd89, 0x43eebd89, 0x553e24af),
            "bpf_redirect_info": (0x101, 0x202, 0x202, 0x202),
            "sk_msg_alloc": (0x303, 0x404, 0x404, 0x505),
            "tcp_bpf_sendmsg_redir": (0x606, 0x707, 0x707, 0x606),
        }
        self.stg = "".join(
            'elf_symbol {\n'
            f'  name: "{name}"\n  is_defined: true\n  crc: 0x{values[0]:08x}\n'
            '}\n'
            for name, values in self.crcs.items()
        )
        self.symvers = "".join(
            f"0x{values[1]:08x}\t{name}\tvmlinux\tEXPORT_SYMBOL_GPL\t\n"
            for name, values in self.crcs.items()
        )
        for root, position in [(self.control, 2), (self.variant, 3)]:
            for name, values in self.crcs.items():
                for src, dest in sweep.OBJECTS.items():
                    if name not in (self.source/src).read_text():
                        continue
                    path = root/dest
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("a") as stream:
                        stream.write(f"#SYMVER {name} 0x{values[position]:08x}\n")
                    break

    def report(self):
        return sweep.evaluate(self.stg, self.symvers, self.source,
                              self.control, self.variant)

    def test_restored_unchanged_and_changed_but_not_restored(self):
        result = self.report()
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["changed_bpf_export_count"], 4)
        self.assertEqual(result["status_counts"], {
            "CHANGED_NOT_RESTORED": 1,
            "RESTORED_TO_STG": 2,
            "UNCHANGED_CRC": 1,
        })
        rows = {r["symbol"]: r for r in result["results"]}
        self.assertEqual(rows["bpf_redirect_info"]["source_object"],
                         "net/core/.filter.o.cmd")
        self.assertEqual(rows["sk_filter_trim_cap"]["variant_crc"],
                         "0x553e24af")
        self.assertFalse(result["guaranteed_android_boot_safety"])
        self.assertFalse(result["device_modified"])

    def test_missing_variant_evidence_is_partial(self):
        (self.variant / "net/core/.skmsg.o.cmd").unlink()
        report = self.report()
        self.assertEqual(report["status"], "PARTIAL")
        row = next(x for x in report["results"]
                   if x["symbol"] == "sk_msg_alloc")
        self.assertEqual(row["status"], "UNVERIFIED")

    def test_ambiguous_symver_is_partial(self):
        with (self.variant / "net/core/.filter.o.cmd").open("a") as s:
            s.write("#SYMVER sk_filter_trim_cap 0x98765432\n")
        row = next(x for x in self.report()["results"]
                   if x["symbol"] == "sk_filter_trim_cap")
        self.assertEqual(row["status"], "UNVERIFIED")

    def test_control_mismatch_blocks_claim_of_restoration(self):
        path = self.control / "net/ipv4/.tcp_bpf.o.cmd"
        path.write_text("#SYMVER tcp_bpf_sendmsg_redir 0x12345678\n")
        row = next(x for x in self.report()["results"]
                   if x["symbol"] == "tcp_bpf_sendmsg_redir")
        self.assertEqual(row["status"], "BASELINE_NOT_REPRODUCED")
        self.assertEqual(self.report()["status"], "PARTIAL")

    def test_missing_source_export_mapping_is_partial(self):
        path = self.source / "net/ipv4/tcp_bpf.c"
        path.write_text("no export here\n")
        row = next(x for x in self.report()["results"]
                   if x["symbol"] == "tcp_bpf_sendmsg_redir")
        self.assertEqual(row["status"], "UNVERIFIED")
        self.assertEqual(self.report()["status"], "PARTIAL")

    def test_parse_cmd_symbols_rejects_invalid_and_keeps_conflicts(self):
        result = sweep.extract_cmd_symbols(
            "#SYMVER good 0x12345678\n"
            "#SYMVER good 0xabcdef01\n"
            "#SYMVER bad 0xnothex\n"
        )
        self.assertEqual(len(result["good"]), 2)
        self.assertNotIn("bad", result)

    def test_cli_writes_machine_and_readable_reports(self):
        stg = self.root / "abi.stg"
        symvers = self.root / "vmlinux.symvers"
        stg.write_text(self.stg)
        symvers.write_text(self.symvers)
        jsonout = self.root / "report.json"
        mdout = self.root / "report.md"
        self.assertEqual(sweep.main([
            "--stg", str(stg), "--symvers", str(symvers),
            "--source", str(self.source), "--control", str(self.control),
            "--variant", str(self.variant),
            "--report-json", str(jsonout), "--report-md", str(mdout),
        ]), 0)
        self.assertEqual(json.loads(jsonout.read_text())["status"], "COMPLETE")
        self.assertIn("sk_filter_trim_cap", mdout.read_text())


if __name__ == "__main__":
    unittest.main()
