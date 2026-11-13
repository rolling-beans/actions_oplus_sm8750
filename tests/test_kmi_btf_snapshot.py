"""Synthetic BTF fixtures; validate fail-closed behavior and stable layout output."""
import json
import struct
import tempfile
import unittest
from pathlib import Path

from scripts import kmi_btf_snapshot as snap


def simple_btf(names=None, duplicate=False, member_bit=16,
               duplicate_size_delta=0):
    names = list(names or snap.MONITORED)
    strings = b"\0"
    offsets = {}
    for text in ["int", "field_a", *names]:
        if text not in offsets:
            offsets[text] = len(strings)
            strings += text.encode() + b"\0"
    types = bytearray()
    def rec(name, kind, size, vlen=0, rest=b"", flag=False):
        info = (kind << 24) | vlen | (0x80000000 if flag else 0)
        types.extend(struct.pack("<III", offsets.get(name, 0), info, size))
        types.extend(rest)
    rec("int", 1, 4, rest=struct.pack("<I", 0x01000020))
    original_names = names + ([names[0]] if duplicate else [])
    for i, name in enumerate(original_names):
        size = 64 + (duplicate_size_delta if duplicate and i == len(names) else 0)
        rec(name, 4, size, 1,
            struct.pack("<III", offsets["field_a"], 1, member_bit))
    header = struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24,
                         0, len(types), len(types), len(strings))
    return header + types + strings


class BTFSnapshotTests(unittest.TestCase):
    def test_reads_all_monitored_types_and_offsets(self):
        tree, warnings = snap.BTF(simple_btf()).snapshot()
        self.assertEqual(warnings, [])
        self.assertEqual(list(tree), list(snap.MONITORED))
        self.assertEqual(tree["task_struct"]["size_bytes"], 64)
        self.assertEqual(tree["task_struct"]["fields"], [{
            "name": "field_a", "bit_offset": 16, "bitfield_size": 0,
            "type": "int int(4)",
        }])

    def test_missing_type_does_not_pass(self):
        tree, warnings = snap.BTF(simple_btf(names=["cgroup"])).snapshot()
        self.assertEqual(list(tree), ["cgroup"])
        self.assertEqual(len(warnings), len(snap.MONITORED) - 1)

    def test_duplicate_equal_surface_layout_is_allowed_with_diagnostics(self):
        tree, warnings, variants = snap.BTF(simple_btf(duplicate=True)).snapshot(
            include_variants=True)
        self.assertEqual(warnings, [])
        self.assertIn("task_struct", tree)
        self.assertEqual(variants["task_struct"]["definition_count"], 2)
        self.assertEqual(variants["task_struct"]["distinct_top_level_layouts"], 1)
        self.assertEqual(len({c["layout_sha256"] for c in
                              variants["task_struct"]["candidates"]}), 1)

    def test_duplicate_divergent_surface_layout_is_not_silently_selected(self):
        raw = simple_btf(duplicate=True, duplicate_size_delta=8)
        tree, warnings, variants = snap.BTF(raw).snapshot(include_variants=True)
        self.assertNotIn("task_struct", tree)
        self.assertTrue(any("distinct top-level layouts" in text for text in warnings))
        self.assertEqual(variants["task_struct"]["definition_count"], 2)
        self.assertEqual(variants["task_struct"]["distinct_top_level_layouts"], 2)
        self.assertEqual(sorted(x["layout"]["size_bytes"]
                                for x in variants["task_struct"]["candidates"]),
                         [64, 72])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kernel.btf"
            path.write_bytes(raw)
            report = snap.capture_file(path)
            self.assertEqual(report["status"], "PARTIAL")
            self.assertIn("task_struct", report["duplicate_type_diagnostics"])
            self.assertEqual(len(report["structures"]), len(snap.MONITORED) - 1)

    def test_truncated_btf_does_not_pass(self):
        with self.assertRaises(snap.BTFError):
            snap.BTF(simple_btf()[:-10])

    def test_unsupported_kind_does_not_pass(self):
        data = bytearray(simple_btf())
        struct.pack_into("<I", data, 24 + 16 + 4, 31 << 24)
        with self.assertRaises(snap.BTFError):
            snap.BTF(bytes(data))

    def test_capture_to_stdout_writes_only_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "live.btf"
            file.write_bytes(simple_btf())
            result = snap.capture_file(file)
            self.assertEqual(result["status"], "COMPLETE")
            self.assertEqual(result["btf_size_bytes"], len(file.read_bytes()))
            self.assertIn("task_struct", json.loads(json.dumps(result))["structures"])

    def test_bitfield_offset(self):
        data = bytearray(simple_btf())
        # Struct type 2 follows a 16-byte INT record.
        struct_info_at = 24 + 16 + 4
        struct.pack_into("<I", data, struct_info_at, (1 << 31) | (4 << 24) | 1)
        member_at = 24 + 16 + 12 + 8
        struct.pack_into("<I", data, member_at, (3 << 24) | 19)
        tree, warnings = snap.BTF(bytes(data)).snapshot()
        self.assertEqual(warnings, [])
        self.assertEqual(tree["task_struct"]["fields"][0]["bit_offset"], 19)
        self.assertEqual(tree["task_struct"]["fields"][0]["bitfield_size"], 3)


if __name__ == "__main__":
    unittest.main()
