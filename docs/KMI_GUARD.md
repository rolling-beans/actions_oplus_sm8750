# KMI Guard for OnePlus 13 (AOSP GKI 6.6)

## Purpose and limits

The goal is to detect **definite normal module-loading incompatibilities before flashing**. These are not equivalent to a guaranteed Android boot failure. Even a module listed in modules.load might be optional, and a module whose CRC matches can still be incompatible because of structure layout changes outside the CRC's coverage.

Android uses CONFIG_MODVERSIONS to compare the CRC of imported/exported kernel symbols at module load. A candidate kernel exporting symbol X with a CRC different from the installed vendor .ko's recorded requirement for X will normally reject that module. For missing symbols, we only make a definite finding when the reference symbol table proves X was provided by vmlinux, or for module_layout.

References:
- https://source.android.com/docs/core/architecture/kernel/loadable-kernel-modules
- https://source.android.com/docs/core/architecture/kernel/abi-monitor
- https://www.kernel.org/doc/html/latest/kbuild/modules.html

## Integration and operation

- A manual kernel build now collects full vmlinux.symvers, kernel .config, selected DWARF type layouts (if vmlinux/DWARF are available), and machine-readable and Markdown audit reports in a separate GitHub Actions artifact named kmi-guard-RUN_ID.
- Repository Actions variable **KMI_GUARD_MODE** (Settings → Secrets and variables → Actions → Variables) has two supported values:
  - audit (default when unset): produce report and allow packaging even if device vendor evidence is missing. Status UNVERIFIED is **not a pass**.
  - enforce: abort before AnyKernel3 ZIP packaging on a definite module rejection or unverified module evidence (including missing vendor manifest or missing independent approval). Type layout risks remain report-only and require expert review.
- A separate workflow_dispatch input cannot be added without removing another: this kernel workflow already uses GitHub's limit of 25 manual inputs.
- A full ABI graph comparison by Android STG, and complete vendor-module loading policy analysis, are **not yet implemented**. Do not infer compatibility from a clean CRC comparison.
- No proprietary .ko binaries need to be committed to the public repository. Only metadata is used.

## One-time device input (needed for strict enforcement)

The GitHub repository intentionally does not include vendor modules. Collect the .ko files from the **exact active system firmware** (vendor_dlkm/odm_dlkm and any separately supplied vendor modules) without editing or flashing the device, and copy them to a trusted Linux environment. Preserve module paths and firmware/build fingerprint. If the module list has not been collected yet, **stay in audit mode**.

On a Linux machine with kmod's modprobe and modinfo (run the command from the repository checkout):

    python3 scripts/kmi_guard.py capture \
      --modules-root vendor=/path/to/extracted-vendor-lib-modules \
      --modules-root odm=/path/to/extracted-odm-lib-modules \
      --modules-root vendor_boot=/path/to/extracted-vendor_boot-lib-modules \
      --modules-load /path/to/verified-vendor_boot.modules.load \
      --fingerprint 'verified-device-build-fingerprint' \
      --output kmi/vendor-manifest.json

Repeat --modules-load for each *verified* loading list. Optionally mark a separately reviewed list with --critical-list; this label only changes reporting. Do not assert every modules.load entry is boot-critical without evidence.

Inspect the generated manifest. Capture errors and absent imports prevent an enforce PASS. Confirm the device build fingerprint, all required roots (including first-stage vendor_boot ramdisk), and the full module and modules.load inventories. A manually curated *separate approval* at kmi/approved-vendor-manifest.json is required to prevent mistaking partial coverage for compatibility. Example approval schema:

    {
      "schema_version": 1,
      "manifest_sha256": "<sha256sum kmi/vendor-manifest.json>",
      "device_build_fingerprint": "<verified value from the device>",
      "verified_sources": ["vendor", "odm", "vendor_boot"],
      "startup_load_lists_verified": true
    }

Only set startup_load_lists_verified=true after reviewing each relevant modules.load file and first-stage init sequence against the current firmware. Source labels/order must match the manifest. This file must be reviewed independently, not generated automatically as part of the same capture. **An approval is an evidence record, not proof of bootability.**

Version the reviewed metadata files in kmi/ as a separate PR (or use a secured workflow if the metadata itself is sensitive). They contain hashes, imported symbols, CRCs, module names and startup flags, **not module binaries**. Firmware changes invalidate the approval until reviewed.

To audit a candidate outside GitHub Actions:

    python3 scripts/kmi_guard.py audit \
      --config /path/to/kout/.config \
      --symvers /path/to/kout/vmlinux.symvers \
      --vendor-manifest kmi/vendor-manifest.json \
      --approved-manifest kmi/approved-vendor-manifest.json \
      --report-json /tmp/kmi-report.json \
      --report-md /tmp/kmi-report.md \
      --mode enforce

Optionally compare with a verified, reproducible reference's vmlinux.symvers using --baseline-symvers and type layouts via --baseline-layouts and --candidate-layouts. Never declare an automatically rebuilt kernel to be a device-verified reference merely because its .config matches.

## Report semantics

- MODULE_LOAD_REJECTION: at least one CRC mismatch (or a proven required vmlinux export is missing). **Deterministic rejection of the module with normal MODVERSIONS loading, not deterministic boot failure.**
- NO_CHECKED_MISMATCH: no checked imported-vmlinux CRC conflicts and evidence coverage was explicitly approved; does not establish that all ABI structures and runtime behaviors are compatible.
- UNVERIFIED: insufficient data to reach even the above narrow conclusion.
- Potential-risk findings: e.g. CFS_BANDWIDTH/CGROUP_PIDS enabled, base CRC drift, selected type layout changes. These are not promoted to deterministic module failures without module-specific proof.

Known OnePlus 13 issue: CONFIG_CGROUP_PIDS=y correlated with a boot hang in the Nov 2026 tests; CONFIG_CFS_BANDWIDTH has separately documented GKI KMI risk and has not been isolated as a single enabled feature. A successful build, even with no KMI guard findings, still needs careful boot testing and a known-good recovery path.

## Next phases

1. Capture and independently validate the firmware's exact vendor-module CRC manifest and startup load lists, including first-stage vendor_boot ramdisk; move KMI Guard into enforce mode only when coverage is defensible.
2. Record immutable SHAs for kernel sources, third-party patches, toolchains and packaging inputs. The current workflow's branch-based downloads prevent fully reproducible baselines.
3. Establish a verified working reference ABI with DWARF + STG, then integrate Android stgdiff for type-level KMI tracking. Type differences should be reviewed in the context of vendor imports, not turned into blanket boot-failure assertions.
4. Determine which modules are indispensable to early boot based on observed init/module-load behavior. Only then classify a definite module rejection as a **high-confidence boot blocker**.
