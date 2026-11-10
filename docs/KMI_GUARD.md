# KMI Guard for OnePlus 13 (AOSP GKI 6.6)

## Purpose and limits

The goal is to detect **definite normal module-loading incompatibilities before flashing**. These are not equivalent to a guaranteed Android boot failure. Even a module listed in modules.load might be optional, and a module whose CRC matches can still be incompatible because of structure layout changes outside the CRC's coverage.

Android uses CONFIG_MODVERSIONS to compare the CRC of imported/exported kernel symbols at module load. A candidate kernel exporting symbol X with a CRC different from the installed vendor .ko's recorded requirement for X will normally reject that module. For missing symbols, we only make a definite finding when the reference symbol table proves X was provided by vmlinux, or for module_layout.

References:
- https://source.android.com/docs/core/architecture/kernel/loadable-kernel-modules
- https://source.android.com/docs/core/architecture/kernel/abi-monitor
- https://www.kernel.org/doc/html/latest/kbuild/modules.html

## Integration and operation

- A manual kernel build now collects full vmlinux.symvers, kernel .config, selected DWARF type layouts (if vmlinux/DWARF are available), and machine-readable and Markdown audit reports in a separate GitHub Actions artifact named kmi-guard-DATE.
- GitHub Actions choice kmi_guard_mode has two values:
  - audit (initial default): produce report and allow packaging even if the device vendor data is missing. Status UNVERIFIED is **not a pass**.
  - enforce: abort the build before AnyKernel3 ZIP packaging if any definite module rejection or any coverage gap is found (including missing vendor manifest). Type layout risks remain report-only and require expert review.
- A full ABI graph comparison by Android STG, and complete vendor-module loading policy analysis, are **not yet implemented**. Do not infer compatibility from a clean CRC comparison.
- No proprietary .ko binaries need to be committed to the public repository. Only metadata is used.

## One-time device input (needed for strict enforcement)

The GitHub repository intentionally does not include vendor modules. Collect the .ko files from the **exact active system firmware** (vendor_dlkm/odm_dlkm and any separately supplied vendor modules) without editing or flashing the device, and copy them to a trusted Linux environment. Preserve module paths and firmware/build fingerprint. If the module list has not been collected yet, **stay in audit mode**.

On a Linux machine with kmod's modprobe and modinfo (run the command from the repository checkout):

    python3 scripts/kmi_guard.py capture \
      --modules-root /path/to/collected-modules \
      --modules-load /path/to/modules.load \
      --fingerprint 'verified-device-build-fingerprint' \
      --output kmi/vendor-manifest.json

Repeat --modules-load for each *verified* loading list. Optionally mark a separately reviewed list with --critical-list; this label only changes reporting. Do not assert every modules.load entry is boot-critical without evidence.

Inspect the generated manifest. Capture errors and absent imports prevent an enforce PASS. Confirm the device build fingerprint and the full set of needed modules. Version the approved vendor-manifest.json in kmi/ on a separate PR (or use another secured repository/workflow mechanism if required); it contains hashes, symbol names, CRCs, and module names, **not binary files**. Changes to the device firmware invalidate the manifest until reviewed.

To audit a candidate outside GitHub Actions:

    python3 scripts/kmi_guard.py audit \
      --config /path/to/kout/.config \
      --symvers /path/to/kout/vmlinux.symvers \
      --vendor-manifest kmi/vendor-manifest.json \
      --report-json /tmp/kmi-report.json \
      --report-md /tmp/kmi-report.md \
      --mode enforce

Optionally compare with a verified, reproducible reference's vmlinux.symvers using --baseline-symvers and type layouts via --baseline-layouts and --candidate-layouts. Never declare an automatically rebuilt kernel to be a device-verified reference merely because its .config matches.

## Report semantics

- MODULE_LOAD_REJECTION: at least one CRC mismatch (or a proven required vmlinux export is missing). **Deterministic rejection of the module with normal MODVERSIONS loading, not deterministic boot failure.**
- NO_CHECKED_MISMATCH: no checked imported-vmlinux CRC conflicts; does not establish that all ABI structures and runtime behaviors are compatible.
- UNVERIFIED: insufficient data to reach even the above narrow conclusion.
- Potential-risk findings: e.g. CFS_BANDWIDTH/CGROUP_PIDS enabled, base CRC drift, selected type layout changes. These are not promoted to deterministic module failures without module-specific proof.

Known OnePlus 13 issue: CONFIG_CGROUP_PIDS=y correlated with a boot hang in the Nov 2026 tests; CONFIG_CFS_BANDWIDTH has separately documented GKI KMI risk and has not been isolated as a single enabled feature. A successful build, even with no KMI guard findings, still needs careful boot testing and a known-good recovery path.

## Next phases

1. Capture and independently validate the firmware's exact vendor-module CRC manifest and startup load lists; move KMI Guard into enforce mode only when coverage is defensible.
2. Record immutable SHAs for kernel sources, third-party patches, toolchains and packaging inputs. The current workflow's branch-based downloads prevent fully reproducible baselines.
3. Establish a verified working reference ABI with DWARF + STG, then integrate Android stgdiff for type-level KMI tracking. Type differences should be reviewed in the context of vendor imports, not turned into blanket boot-failure assertions.
4. Determine which modules are indispensable to early boot based on observed init/module-load behavior. Only then classify a definite module rejection as a **high-confidence boot blocker**.
