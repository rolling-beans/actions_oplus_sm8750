"""Mocked read-only A/B runner tests; never compiles or flashes any kernel."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class BPFParserABTests(unittest.TestCase):
    def create_workspace(self, root, with_input=True):
        w = Path(root)
        main = w / "kout"
        main.mkdir()
        (main / "vmlinux.symvers").write_text(
            "0x43eebd89\tsk_filter_trim_cap\tvmlinux\tEXPORT_SYMBOL\t\n"
        )
        if with_input:
            (main / ".config").write_text("CONFIG_BPF_STREAM_PARSER=y\n")
        (main / "Image").write_bytes(b"original-kernel-image")
        common_scripts = w / "kernel_workspace/common/scripts"
        common_scripts.mkdir(parents=True)
        config = common_scripts / "config"
        config.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" != \"--file\" ]; then exit 1; fi\n"
            "sed -i 's/^CONFIG_BPF_STREAM_PARSER=y$/"
            "# CONFIG_BPF_STREAM_PARSER is not set/' \"$2\"\n"
        )
        config.chmod(0o755)
        abi = common_scripts.parent / "android"
        abi.mkdir()
        (abi / "abi_gki_aarch64.stg").write_text(
            'elf_symbol {\n name: "sk_filter_trim_cap"\n'
            ' is_defined: true\n crc: 0x553e24af\n}\n'
        )
        tool = w / "kmi-tools/scripts"
        tool.mkdir(parents=True)
        shutil.copyfile(REPO / "scripts/kmi_stg_crc_diff.py",
                        tool / "kmi_stg_crc_diff.py")
        mockbin = w / "mockbin"
        mockbin.mkdir()
        make = mockbin / "make"
        make.write_text(
            "#!/bin/sh\n"
            "for x in \"$@\"; do\n"
            " if [ \"$x\" = \"net/core/filter.o\" ]; then\n"
            "  mkdir -p \"$GITHUB_WORKSPACE/kmi-bpf-parser-off-output/net/core\"\n"
            "  echo '#SYMVER sk_filter_trim_cap 0x553e24af' > "
            "\"$GITHUB_WORKSPACE/kmi-bpf-parser-off-output/net/core/.filter.o.cmd\"\n"
            " fi\n"
            "done\n"
            "exit 0\n"
        )
        make.chmod(0o755)
        return mockbin

    def run_script(self, root, mockbin):
        env = {**os.environ,
               "GITHUB_WORKSPACE": str(root),
               "PATH": str(mockbin) + ":" + os.environ.get("PATH", "")}
        return subprocess.run(
            ["bash", str(REPO / "scripts/kmi_bpf_stream_parser_ab_ci.sh")],
            env=env, capture_output=True, text=True, timeout=15,
        )

    def test_toggle_can_restore_reference_crc_without_changing_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mockbin = self.create_workspace(root)
            result = self.run_script(root, mockbin)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((root / "kmi-evidence/bpf-stream-parser-ab.json")
                              .read_text())
            self.assertEqual(data["status"], "CRC_RESTORED_TO_REFERENCE")
            self.assertEqual(data["experimental_parser_off_crc"], "0x553e24af")
            self.assertEqual((root / "kout/Image").read_bytes(),
                             b"original-kernel-image")
            self.assertIn("CONFIG_BPF_STREAM_PARSER=y",
                          (root / "kout/.config").read_text())
            self.assertIn("# CONFIG_BPF_STREAM_PARSER is not set",
                          (root / "kmi-bpf-parser-off-output/.config").read_text())
            self.assertFalse(data["image_modified"])

    def test_additional_effective_config_change_is_confounder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mockbin = self.create_workspace(root)
            with (root / "kout/.config").open("a") as stream:
                stream.write("CONFIG_CGROUPS=y\n")
            # Simulate olddefconfig changing a second config option.
            make = mockbin / "make"
            script = make.read_text()
            script = script.replace(
                " if [ \"$x\" = \"net/core/filter.o\" ]; then",
                " if [ \"$x\" = \"olddefconfig\" ]; then\n"
                "  sed -i 's/^CONFIG_CGROUPS=y$/# CONFIG_CGROUPS is not set/' "
                "\"$GITHUB_WORKSPACE/kmi-bpf-parser-off-output/.config\"\n"
                " fi\n"
                " if [ \"$x\" = \"net/core/filter.o\" ]; then"
            )
            make.write_text(script)
            result = self.run_script(root, mockbin)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((root / "kmi-evidence/bpf-stream-parser-ab.json")
                                .read_text())
            self.assertEqual(report["status"],
                             "CONFOUNDED_ADDITIONAL_KCONFIG_CHANGES")
            self.assertFalse(report["only_requested_kconfig_changed"])
            self.assertIn("CONFIG_CGROUPS", report["effective_kconfig_changes"])
            self.assertEqual((root / "kout/Image").read_bytes(),
                             b"original-kernel-image")

    def test_missing_primary_config_stays_unverified_and_nonblocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mockbin = self.create_workspace(root, with_input=False)
            result = self.run_script(root, mockbin)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((root / "kmi-evidence/bpf-stream-parser-ab.json")
                                .read_text())
            self.assertEqual(report["status"], "UNVERIFIED")
            self.assertFalse(report["device_modified"])
            self.assertEqual((root / "kout/Image").read_bytes(),
                             b"original-kernel-image")


if __name__ == "__main__":
    unittest.main()
