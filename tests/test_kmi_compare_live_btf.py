"""Live booted BTF vs candidate pahole offset comparator tests."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts import kmi_compare_live_btf as compare
from scripts import kmi_layout_diff


def fixtures(shift=None, size_shift=None):
    live = {
        "schema_version": 1, "status": "COMPLETE",
        "capture_kind": "booted-kernel-btf-sysfs",
        "kernel_release": "6.6.144-test",
        "btf_sha256": "a" * 64,
        "structures": {},
    }
    layouts = []
    for name in kmi_layout_diff.MONITORED:
        live["structures"][name] = {
            "size_bytes": 128,
            "fields": [
                {"name": f"field_{i}", "bit_offset": i * 32, "bitfield_size": 0}
                for i in range(6)
            ],
        }
        entries = []
        for i in range(6):
            byte = i * 4 + (8 if shift == name and i == 3 else 0)
            entries.append(f"\tint field_{i}; /* {byte:5d}     4 */")
        size = 128 + (8 if size_shift == name else 0)
        layouts.append(
            f"struct {name} {{\n" + "\n".join(entries) + "\n"
            f"\t/* size: {size}, cachelines: 2, members: 6 */\n"
            "};\n"
        )
    return live, "\n".join(layouts)


class CompareLiveBTFTests(unittest.TestCase):
    def test_matching_monitored_offsets(self):
        live, candidate = fixtures()
        result = compare.compare(live, candidate)
        self.assertEqual(result["status"], "NO_MONITORED_LAYOUT_DIFFERENCE")
        self.assertEqual(result["changed_types"], [])

    def test_shifted_cgroup_member_is_reported(self):
        live, candidate = fixtures(shift="cgroup")
        result = compare.compare(live, candidate)
        self.assertEqual(result["status"], "MONITORED_LAYOUT_DIFFERENCE")
        self.assertEqual(result["changed_types"], ["cgroup"])
        diff = result["type_details"]["cgroup"]["shifted_fields"]
        self.assertEqual(diff[0]["field"], "field_3")
        self.assertEqual(diff[0]["live_bit_offset"], 96)
        self.assertEqual(diff[0]["candidate_bit_offset"], 160)

    def test_changed_outer_size_is_reported(self):
        live, candidate = fixtures(size_shift="task_struct")
        result = compare.compare(live, candidate)
        self.assertEqual(result["changed_types"], ["task_struct"])

    def test_unparsed_candidate_fields_are_not_equivalent_to_full_pass(self):
        live, candidate = fixtures()
        candidate = candidate.replace(
            "\tint field_1; /*     4     4 */",
            "\t??? custom field_1; /*     4     4 */"
        )
        result = compare.compare(live, candidate)
        self.assertNotEqual(result["status"], "MONITORED_LAYOUT_DIFFERENCE")
        # Unknown field types are not by themselves proof of layout change.
        self.assertFalse(result["guaranteed_android_boot_failure"])

    def test_reference_must_be_live_sysfs(self):
        live, candidate = fixtures()
        live["capture_kind"] = "raw-btf"
        with self.assertRaisesRegex(ValueError, "running kernel"):
            compare.compare(live, candidate)

    def test_missing_type_fails_closed(self):
        live, candidate = fixtures()
        del live["structures"]["rq"]
        with self.assertRaisesRegex(ValueError, "missing struct rq"):
            compare.compare(live, candidate)

    def test_cli_emits_unverified_on_bad_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "live").write_text(json.dumps({"status": "PARTIAL"}))
            (root / "candidate").write_text("UNAVAILABLE")
            rc = compare.main([
                "--live-json", str(root / "live"),
                "--candidate-layouts", str(root / "candidate"),
                "--report-json", str(root / "report.json"),
                "--report-md", str(root / "report.md"),
            ])
            self.assertEqual(rc, 2)
            self.assertEqual(json.loads((root / "report.json").read_text())["status"],
                             "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
