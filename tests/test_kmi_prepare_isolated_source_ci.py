"""Verify source snapshot removes Kbuild-generated paths without mutating source."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("rsync") and shutil.which("timeout"),
                     "rsync and timeout are required for snapshot tests")
class PatchedSnapshotTests(unittest.TestCase):
    def test_source_copy_skips_generated_files_and_keeps_patches(self):
        with tempfile.TemporaryDirectory() as dirname:
            w = Path(dirname)
            src = w / "kernel_workspace/common"
            for name, value in {
                "Makefile": "all:\n\t@true\n",
                "net/core/filter.c": "int new_patched_function;\n",
                "include/linux/skmsg.h": "struct sk_psock { int patched; };\n",
                "net/Kconfig": "config BPF_STREAM_PARSER\n\tbool\n",
                "android/abi_gki_aarch64.stg": "version: 0x2\n",
                ".config": "DIRTY_IN_TREE_CONFIG\n",
                "include/config/auto.conf": "DIRTY_IN_TREE_AUTOCONF\n",
                "include/generated/autoconf.h": "#define DIRTY 1\n",
                "arch/arm64/include/generated/asm-offsets.h": "#define X 2\n",
                "scripts/patched.txt": "UNCOMMITTED_PATCHES_RETAINED\n",
            }.items():
                path = src / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
            primary = w / "kout"
            primary.mkdir()
            (primary / ".config").write_text("CONFIG_MODVERSIONS=y\n")
            (primary / "vmlinux.symvers").write_text(
                "0x43eebd89\tsk_filter_trim_cap\tvmlinux\tEXPORT_SYMBOL\n"
            )
            (primary / "Image").write_bytes(b"UNCHANGED_KERNEL_IMAGE")
            before = hashlib.sha256((primary / "Image").read_bytes()).hexdigest()
            env = dict(os.environ, GITHUB_WORKSPACE=str(w))
            r = subprocess.run(
                ["bash", str(REPO / "scripts/kmi_prepare_isolated_source_ci.sh")],
                env=env, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            evidence = json.loads(
                (w / "kmi-evidence/kmi-isolated-source.json").read_text())
            self.assertEqual(evidence["status"], "COMPLETE", r.stdout + r.stderr)
            isolated = w / "kernel_workspace/kmi-isolated-common"
            self.assertEqual((isolated / "scripts/patched.txt").read_text(),
                             "UNCOMMITTED_PATCHES_RETAINED\n")
            for bad in [".config", "include/config", "include/generated",
                        "arch/arm64/include/generated"]:
                self.assertFalse((isolated / bad).exists(), bad)
                self.assertTrue((src / bad).exists(), bad)
            self.assertEqual(
                hashlib.sha256((primary / "Image").read_bytes()).hexdigest(),
                before)
            self.assertEqual((primary / ".config").read_text(),
                             "CONFIG_MODVERSIONS=y\n")

    def test_snapshot_never_overwrites_existing_destination(self):
        with tempfile.TemporaryDirectory() as dirname:
            w = Path(dirname)
            (w / "kernel_workspace/common/net/core").mkdir(parents=True)
            (w / "kernel_workspace/common/Makefile").write_text("all:\n")
            (w / "kernel_workspace/common/net/core/filter.c").write_text("x")
            (w / "kout").mkdir()
            (w / "kout/.config").write_text("CONFIG_MODVERSIONS=y\n")
            (w / "kout/vmlinux.symvers").write_text("export\n")
            isolated = w / "kernel_workspace/kmi-isolated-common"
            isolated.mkdir()
            (isolated / "SENTINEL").write_text("don't overwrite")
            r = subprocess.run(
                ["bash", str(REPO / "scripts/kmi_prepare_isolated_source_ci.sh")],
                env=dict(os.environ, GITHUB_WORKSPACE=str(w)),
                capture_output=True, text=True, timeout=20)
            self.assertEqual(r.returncode, 0)
            self.assertEqual((isolated / "SENTINEL").read_text(),
                             "don't overwrite")
            self.assertEqual(json.loads(
                (w / "kmi-evidence/kmi-isolated-source.json").read_text()
            )["status"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
