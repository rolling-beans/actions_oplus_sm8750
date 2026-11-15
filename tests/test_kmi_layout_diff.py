"""Tests for advisory KMI type-layout comparison."""
import json
import tempfile
import unittest
from pathlib import Path
from scripts import kmi_layout_diff as layout


def fixture(cgroup_offset=0, cgroup_size=128):
    result = []
    for name in layout.MONITORED:
        offset = cgroup_offset if name == "cgroup" else 0
        size = cgroup_size if name == "cgroup" else 256
        result.append(
            f"struct {name} {{\n"
            f"\tint field; /* {offset:5d}     4 */\n"
            f"\t/* size: {size}, cachelines: 4, members: 1 */\n"
            "};\n")
    return "\n".join(result)


class LayoutDiffTests(unittest.TestCase):
    def test_no_difference(self):
        r = layout.compare(fixture(), fixture())
        self.assertEqual(r["status"], "NO_DIFFERENCE")
        self.assertFalse(r["type_changes"])
        self.assertFalse(r["guaranteed_android_boot_failure"])

    def test_cgroup_changed_size_and_offset(self):
        r = layout.compare(fixture(), fixture(8, 136))
        self.assertEqual(r["status"], "TYPE_LAYOUT_CHANGED")
        self.assertEqual(len(r["type_changes"]), 1)
        x = r["type_changes"][0]
        self.assertEqual(x["type"], "cgroup")
        self.assertEqual((x["before_size"], x["after_size"]), (128, 136))
        self.assertTrue(any("field" in line for line in x["unified_diff"]))
        self.assertFalse(r["guaranteed_module_load_failure"])

    def test_all_types_must_be_present(self):
        with self.assertRaisesRegex(ValueError, "missing monitored types"):
            layout.compare(fixture().split("struct rq {")[0], fixture())

    def test_unavailable_does_not_look_like_compatibility(self):
        with self.assertRaisesRegex(ValueError, "unavailable"):
            layout.compare("BTF type layout snapshot UNAVAILABLE", fixture())

    def test_cli_reports_unverified_and_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "before").write_text("UNAVAILABLE")
            (root / "after").write_text(fixture())
            rc = layout.main([
                "--reference", str(root / "before"),
                "--candidate", str(root / "after"),
                "--report-json", str(root / "out.json"),
                "--report-md", str(root / "out.md")])
            self.assertEqual(rc, 2)
            report = json.loads((root / "out.json").read_text())
            self.assertEqual(report["status"], "UNVERIFIED")

    def test_cli_reports_changed_layout_without_claiming_bootloop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "before").write_text(fixture())
            (root / "after").write_text(fixture(8, 136))
            rc = layout.main([
                "--reference", str(root / "before"),
                "--candidate", str(root / "after"),
                "--report-json", str(root / "out.json"),
                "--report-md", str(root / "out.md")])
            self.assertEqual(rc, 0)
            report = json.loads((root / "out.json").read_text())
            self.assertEqual(report["status"], "TYPE_LAYOUT_CHANGED")
            self.assertIn("struct cgroup", (root / "out.md").read_text())


if __name__ == "__main__":
    unittest.main()
