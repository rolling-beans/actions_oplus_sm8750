"""Genksyms transitive-type capture: only evidence, never CRC suppression."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts import kmi_symtypes_closure as closure


class SymtypesClosureTests(unittest.TestCase):
    def setUp(self):
        self.source = (
            "sk_filter_trim_cap int sk_filter_trim_cap ( s#sock * , s#sk_buff * , unsigned int )\n"
            "s#sock struct sock { t#s64 age ; s#sk_buff * head ; }\n"
            "s#sk_buff struct sk_buff { unsigned int len ; }\n"
            "t#s64 typedef long long s64\n"
            "different unrelated_type ignored\n"
        )

    def test_complete_transitive_graph_without_unrelated_entries(self):
        report = closure.extract(self.source, "sk_filter_trim_cap")
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["transitive_record_count"], 3)
        self.assertEqual(list(report["transitive_declarations"]),
                         ["s#sk_buff", "s#sock", "t#s64"])
        self.assertNotIn("different", report["transitive_declarations"])
        self.assertEqual(report["unresolved_type_references"], [])

    def test_missing_type_is_partial_not_silent_success(self):
        report = closure.extract(self.source.replace(
            "s#sk_buff struct sk_buff { unsigned int len ; }\n", ""),
            "sk_filter_trim_cap")
        self.assertEqual(report["status"], "PARTIAL")
        self.assertIn("s#sk_buff", report["unresolved_type_references"])

    def test_conflicting_repeated_declaration_is_partial(self):
        report = closure.extract(
            self.source + "s#sock struct sock { int different ; }\n",
            "sk_filter_trim_cap")
        self.assertEqual(report["status"], "PARTIAL")
        self.assertIn("s#sock", report["ambiguous_records"])

    def test_identical_duplicate_record_is_harmless(self):
        text = self.source + "t#s64 typedef long long s64\n"
        self.assertEqual(closure.extract(text, "sk_filter_trim_cap")["status"],
                         "COMPLETE")

    def test_source_missing_export_is_unverified(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            closure.extract(self.source, "not_exported")

    def test_malformed_record_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "record"):
            closure.extract("sk_filter_trim_cap\n", "sk_filter_trim_cap")

    def test_cli_emits_json_and_status_on_partial_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.symtypes").write_text(
                "sk_filter_trim_cap int sk_filter_trim_cap ( s#sock * )\n"
            )
            rc = closure.main([
                "--symtypes", str(root / "sample.symtypes"),
                "--symbol", "sk_filter_trim_cap",
                "--output", str(root / "summary.json"),
            ])
            self.assertEqual(rc, 2)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual(summary["status"], "PARTIAL")
            self.assertEqual(summary["unresolved_type_references"], ["s#sock"])


if __name__ == "__main__":
    unittest.main()
