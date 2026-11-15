"""Check the Termux BTF wrapper keeps useful PARTIAL evidence in shared storage.

The collector is mocked; no device, root access or sysfs modifications.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class BTFSafWrapperTests(unittest.TestCase):
    def run_wrapper(self, payload):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            prefix = root / "prefix"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "python3").symlink_to(sys.executable)
            # A dummy sudo that runs only our deliberately harmless fake
            # collector: it does not invoke a real root helper.
            (prefix / "bin" / "sudo").write_text("#!/bin/sh\nexec \"$@\"\n")
            (prefix / "bin" / "sudo").chmod(0o755)
            source = (Path(__file__).resolve().parents[1] / "scripts" /
                      "kmi_capture_btf_termux.sh")
            shutil.copyfile(source, scripts / source.name)
            stub = scripts / "kmi_btf_snapshot.py"
            stub.write_text(
                "import json,sys\n"
                "print(json.dumps(" + repr(payload) + "))\n"
                "sys.exit(2)\n"
            )
            output = root / "SAF"
            output.mkdir()
            env = {
                **os.environ,
                "PREFIX": str(prefix),
                "KMI_GUARD_SAF_DIR": str(output),
                "PATH": str(prefix / "bin") + ":" + os.environ.get("PATH", ""),
            }
            process = subprocess.run(["bash", str(scripts / source.name)],
                                     env=env, capture_output=True, text=True,
                                     timeout=20)
            files = list(output.glob("live-kernel-btf-*.json"))
            actual = json.loads(files[0].read_text()) if files else None
            return process, files, actual

    def test_partial_snapshot_is_retained_even_on_nonzero_parser_exit(self):
        sample = {
            "schema_version": 1,
            "capture_kind": "booted-kernel-btf-sysfs",
            "status": "PARTIAL",
            "structures": {"task_struct": {}, "cgroup": {}, "task_group": {}},
            "warnings": ["rq: got 0", "cfs_rq: got 0"],
        }
        process, files, actual = self.run_wrapper(sample)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(len(files), 1)
        self.assertEqual(actual, sample)
        self.assertIn("BTF warning: rq: got 0", process.stdout)
        self.assertIn("SAF-accessible live BTF structure snapshot", process.stdout)
        self.assertIn("BTF is partial", process.stderr)

    def test_invalid_snapshot_removed(self):
        process, files, actual = self.run_wrapper({"status": "PARTIAL"})
        self.assertEqual(process.returncode, 2)
        self.assertEqual(files, [])
        self.assertIsNone(actual)


if __name__ == "__main__":
    unittest.main()
