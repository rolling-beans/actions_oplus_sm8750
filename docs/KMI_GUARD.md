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

## Rooted Android / Termux: metadata-only capture

The Python standard-library collector can run **on the device**, avoiding
transporting proprietary .ko files to a computer. It never calls insmod,
modprobe, dd, mount, flashing tools, or any network API.

On the phone, after reviewing `scripts/kmi_collect_android.py`
and `scripts/kmi_capture_termux.sh`, grant Termux ordinary
shared-storage access, then use the wrapper:

    bash scripts/kmi_capture_termux.sh

The wrapper checks that `/sdcard/Documents/KMI-Guard/` is writable by
the **regular Termux user**, runs the collector with `sudo` to read
protected modules into a private temporary file, returns ownership and
copies the metadata-only JSON into the SAF-accessible Documents folder.
This avoids relying on root's separate Android emulated-storage mount
namespace for the final write. The temporary file is removed after the
copy. Pass additional collector arguments to the wrapper if needed, for
example `--root system_dlkm=/system/lib/modules`.

The underlying Python collector also defaults to a timestamped
`/sdcard/Documents/KMI-Guard/android-kmi-vendor-YYYYMMDD-HHMMSS.json`
when called directly, but direct root writes to shared storage may fail
in some root mount namespaces. **The wrapper is preferred.**

If the Documents folder is not writable in the current scoped-storage
configuration, first use the normal Termux account to create/access the
directory via `termux-setup-storage`. Do not change SELinux or remount
vendor partitions to repair an output-path permission problem.

The script scans `/vendor/lib/modules`, `/odm/lib/modules` and
`/lib/modules` where accessible, and checks `modules.load*` both
alongside modules and in known `/vendor/etc`,
`/vendor_dlkm/etc`, `/odm/etc` and `/odm_dlkm/etc`
locations. It records SHA-256, required and exported MODVERSIONS CRCs,
vermagic, build fingerprints and inventory. It never includes .ko
binary bytes and does not upload data.

### Device diagnostic when all modules return Permission denied

AOSP may expose `.ko` filenames to an unprivileged process while
denying read access to their bytes. An EACCES-only manifest is a
discovery artifact, not ABI evidence. A read-only 4-byte ELF probe
under Termux `sudo` verified the OnePlus 13 module read permission
without changing SELinux or mounts. Do not disable SELinux to
circumvent a denied read.

Raw kernel versions from `os.uname().release` and
`/proc/sys/kernel/osrelease` are stored because
`platform.uname().release` can be incorrect in Termux (reported
Android version 17 instead of kernel 6.6.144).

For direct access to additional extracted ramdisk directories use repeated
--root LABEL=PATH (the explicit roots then replace defaults). This script
parses 64-bit little-endian ELF and both 64-byte basic and modern extended
modversion formats. A mismatched/unsupported format is reported, not guessed.

IMPORTANT: after boot, vendor_boot's first-stage /lib/modules directory may
be inaccessible. An unavailable source is **not** evidence that it contains
zero modules. In that case, obtain the exact matching vendor_boot ramdisk
metadata separately before approving full coverage.

The direct Android collector now extracts vendor-to-vendor exported CRCs
from `__crc_*` symbols, `__ksymtab_*` markers and `__kcrctab*` sections.
Only unambiguous CRCs are recorded; unresolved exports are annotated and must
not be treated as confirmed KMI compatibility. The Linux-host collector
using kmod `--show-modversions` and `--show-exports` remains an independent
validation path. The ELF extractor has been cross-checked against 40
real Linux modules, including modules exporting hundreds of symbols, with
zero CRC disagreements. Full device-specific coverage still requires
the matching vendor_boot and ODM data, if present.

## Empirical OnePlus 13 ABI evidence (12 Nov 2026)

The complete on-device v2 capture contains **498 decoded .ko files**,
**5,858 provider CRC entries** and a verified 362-name vendor
`modules.load` inventory. The private manifest itself is not committed.

Comparing against `vmlinux.symvers` from the successful GitHub Actions
run **#233 / 42877326850**:

- **25,309** module imports matched the candidate `vmlinux` CRC.
- **3,958** more imports matched the CRC of a **unique vendor .ko provider**.
- **0** compared imports had mismatched CRC.
- **14** imports have no provider in the scanned inventory:
  `rfkill_*` (btpower/cfg80211) and `arc4_*` (mac80211).
  Candidate kernel Kconfig has `CONFIG_RFKILL=m` and
  `CONFIG_CRYPTO_LIB_ARC4=m`; the matching module provider may
  be in a different Android DLKM partition.
- **990** exported names occur in multiple vendor modules, including
  **403** names for which alternate providers expose different CRCs.
  None of the captured imported names in the inventory depends on
  one of these ambiguous exported names. These provider conflicts
  require loading-order review rather than automatic bootloop claims.

The successful Actions #233 provides a full end-to-end smoke test of
KMI Guard in `audit` mode: artifact generated, no vendor manifest
included, correctly marked `UNVERIFIED`. The `vmlinux.symvers`
and `kernel.config` bytes from #233 and the earlier #184 are identical.

**Limit:** Vendor_boot, ODM and other module roots remain unavailable
in the device post-boot namespace, so neither complete compatibility
nor guaranteed Android bootability can be claimed. CRC equality
does not replace Android STG/DWARF ABI type comparison.

## Provisional BTF structure comparison (not boot verified)

The workflow stores `type-layouts.txt` from `pahole -F btf` and now
runs `scripts/kmi_layout_diff.py` against the checked-in
`kmi/provisional-reference-type-layouts-42877326850.txt`.

- Reference: GitHub Actions kernel build #233 / 42877326850.
- SHA-256: `8396b94724d7cbd20abc7f7ab0dbb1387119fa345b0f4159967e2f188e59b778`.
- Types: `task_struct`, `cgroup`, `cfs_rq`, `rq`, `task_group`.
- It records `layout-diff.json` and `layout-diff.md` in the
  `kmi-guard-RUN_ID` artifact.
- Findings: `NO_DIFFERENCE`, `TYPE_LAYOUT_CHANGED` or `UNVERIFIED`.
  Layout changes are **advisory only**; they are not promoted to proof
  of a module-load rejection, and certainly not guaranteed boot failure.
- A **synthetic** test changed `struct cgroup` from 1920 to 1928
  bytes; it was correctly flagged. Tests against the same baseline
  return `NO_DIFFERENCE`.
- This reference is **not confirmed booted** on the device, even though
  it came from a successful kernel build. It must not be labeled
  an approved GKI KMI baseline. A future boot-verified reference
  plus the official `stg`/`stgdiff` graph comparison are still needed.

### GitHub Actions availability (verified 12 November 2026)

Although the repository setting reports `enabled=true`,
`allowed_actions=all`, and the build workflow is `active`,
attempted manual dispatch returned HTTP 422:
"Actions has been disabled for this repository." The latest
pushes on this branch do not create new runs. Thus the **current
HEAD has not passed an Actions build**; the last fully successful
kernel smoke run #233 predates these additions.

The official GitHub documentation says this combination can be
a GitHub-controlled disabled state that ordinary settings cannot
resolve:
https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository

Do not toggle permissions blindly or treat local unit tests as
equivalent to a complete kernel build. A review by GitHub Support
may be necessary. Local checks of the latest HEAD completed:
35 unit tests PASS, Bash syntax PASS, baseline self-compare PASS,
and synthetic cgroup drift detection PASS.

## Running-device BTF snapshot (boot-verified reference candidate)

The previous reference from Actions #233 was **build-verified, not boot-verified**.
A running kernel may expose its actual BTF as the read-only sysfs file
`/sys/kernel/btf/vmlinux`. This enables an independent comparison against
the kernel build's candidate `type-layouts.txt` **without flashing anything**.

The standard-library collector `scripts/kmi_btf_snapshot.py` extracts only
five named structures (`task_struct`, `cgroup`, `cfs_rq`, `rq`,
`task_group`), each structure's size and its named member offsets,
bitfield widths and type names. It records a SHA-256 of the raw input but
**does not store or transmit the raw BTF binary**.

From a cloned repository in Termux, run:

    bash scripts/kmi_next_stage_termux.sh

This orchestrates the live BTF snapshot and a **targeted** scan of
`/system/lib/modules` (or `/system_dlkm/lib/modules`) without re-reading
the 498 vendor modules. It reports unavailable roots without treating them
as proof that the corresponding partition contains no modules. To collect
BTF alone, run `bash scripts/kmi_capture_btf_termux.sh`.

The BTF wrapper creates `/sdcard/Documents/KMI-Guard/live-kernel-btf-*.json`
with the regular Termux user's storage permission. It only uses `sudo`
when reading the sysfs BTF requires it; a root process never writes
the output file. No SELinux changes or kernel/device writes are made.

A complete snapshot captured from the running device has the
`capture_kind=booted-kernel-btf-sysfs` marker and can be reviewed as a
candidate boot-verified baseline. Review the device kernel release and
vendor firmware fingerprint independently before blessing it as the
reference for the appropriate firmware/build.

A local comparison can then be run (Linux/Python 3):

    python3 scripts/kmi_compare_live_btf.py \
      --live-json /path/to/approved-live-kernel-btf.json \
      --candidate-layouts /path/to/kmi-guard/type-layouts.txt \
      --report-json /tmp/live-btf-diff.json \
      --report-md /tmp/live-btf-diff.md

The comparison reports outer structure size changes, changed bit offsets
of the same named top-level fields, and incomplete field coverage.
It **does not** establish whether a vendor module accesses those fields,
nor check all nested types and function ABI. Changes are advisory risks.
A candidate that matches these five structures has not passed full KMI.

The workflow automatically runs this comparison if a reviewed
`kmi/booted-kernel-btf.json` is present. When absent,
`live-btf-diff.json` is explicitly `UNVERIFIED`; it never silently
treats the provisional Actions baseline as boot-verified.
No live BTF reference is committed yet, pending manual review.

For a full structural ABI graph, Android's official
`stg`/`stgdiff` analysis using reproducible vmlinux + DWARF and a
reference `.stg` is still necessary:
https://source.android.com/docs/core/architecture/kernel/abi-monitor

## Diagnosing missing BTF or system_dlkm on rooted Android

A normal Termux test reported both `/sys/kernel/btf/vmlinux` and
`/system_dlkm/lib/modules` as missing. **This alone does not
establish that root cannot see them.**

The previous BTF wrapper contained an early unprivileged
`-e /sys/kernel/btf/vmlinux` test that exited before considering
`sudo`. This is fixed. To avoid masking the real cause, run a
read-only dual-context diagnostic **before another BTF capture**:

    bash scripts/kmi_probe_runtime_termux.sh

It compares ordinary Termux and `sudo` process visibility, checks
`/proc/1/root` for init's mount namespace, examines sysfs and
system/ODM DLKM mount information, queries `/proc/config.gz` if
present, and records loaded rfkill/ARC4-related module names.
Two JSON outputs are created directly in the user's writable SAF
`/sdcard/Documents/KMI-Guard/` directory.

No tool attempts to mount a partition, enable BTF, alter SELinux,
insert modules or flash anything. If **both root and init namespaces**
lack vmlinux BTF, check the *running kernel's* Kconfig/build artifact
before selecting a different reference source. A BTF-enabled `vmlinux`
from a CI build is **not automatically boot-verified**.

## Combined vendor + system_dlkm CRC result (13 Nov 2026)

A second device-owned, read-only metadata capture successfully decoded
**95/95** `system_dlkm` modules, including the `rfkill` and `libarc4`
providers and 77 entries in its `modules.load`. All input modules
were decoded without warnings. The raw private manifest is **not** committed.

Independent off-device analysis used:
- 498 vendor modules from the earlier private v2 inventory;
- 95 system_dlkm modules from the new capture;
- the actual `vmlinux.symvers` emitted by Actions #233.

Results for **34,353 imported CRCs**:

| Resolution | Import count |
|---|---:|
| CRC matches candidate `vmlinux` | 29,892 |
| CRC matches an unambiguous .ko provider | 4,460 |
| Unknown provider | 0 |
| **CRC mismatch** | **1** |

The mismatch is **`system_dlkm/bluetooth.ko`** importing
`sk_filter_trim_cap`:

- module requirement: `0x553e24af`
- candidate vmlinux export: `0x43eebd89`
- listed in system_dlkm `modules.load`: yes
- proved indispensable for Android boot: **no**

With ordinary `CONFIG_MODVERSIONS=y` loading, this mismatch predicts
rejection of `bluetooth.ko` **if it is loaded against the candidate
kernel**. It does **not** prove a guaranteed Android bootloop. The
kernel currently running on the phone has not been demonstrated to
have identical CRCs to candidate #233; matching `uname -r` strings
cannot establish that.

All 14 previously unresolved `rfkill_*` and `arc4_*` imports were
accounted for with matching CRCs by the new `system_dlkm` providers.

The BTF capture from the running kernel parsed **163,643** BTF
types but resolved only **3/5** monitored structs (status `PARTIAL`).
The earlier shell wrapper deleted the valid JSON whenever the
collector returned 2. This is now fixed: valid partial JSON is
**retained in SAF**, with named warnings, remains non-PASS, and the
live comparator can analyze only the available structs without
claiming full coverage.

**Actionability:** A known module-level CRC failure now exists. Before
calling it an Android boot blocker, validate the real boot-time loading
policy, whether Bluetooth is actually loaded with stock vendor
modules, and which exact kernel binary is running. A future BTF
or STG layout match still cannot override this deterministic CRC result.

## Confirmed OnePlus 13 root visibility (13 Nov 2026)

Two read-only Android probe JSON files were provided by the device owner.
The diagnosis is **EACCES**, not missing BTF or missing system_dlkm.

- Normal Termux UID **10435** and sudo UID **0** both used mount
  namespace `mnt:[4026535912]`. Init used `mnt:[4026532717]`.
  A namespace switch is unnecessary for the inspected files.
- Normal Termux `/sys/kernel/btf/vmlinux` and
  `/system_dlkm/lib/modules` checks returned **EACCES (13)**.
- Root **successfully read** running-kernel `/sys/kernel/btf/vmlinux`:
  **7,120,322 bytes**, magic `9f eb 01 00` (little-endian BTF).
- Root found `/system_dlkm/lib/modules` mounted from EROFS,
  with **95 .ko** files. The alternate `/system/lib/modules`
  resolves to the same number; do not double-count.
- Root read `/proc/config.gz`, confirming
  `CONFIG_DEBUG_INFO_BTF=y`,
  `CONFIG_DEBUG_INFO_BTF_MODULES=y`,
  `CONFIG_MODVERSIONS=y`,
  `CONFIG_RFKILL=m`, and
  `CONFIG_CRYPTO_LIB_ARC4=m`.
- Loaded module names already include `rfkill`, `libarc4`,
  `btpower`, `cfg80211` and `mac80211`. Thus providers for
  the **14 previously unresolved** imports are present at runtime.
  Their *CRC compatibility against the candidate kernel* still
  needs the 95-module `system_dlkm` manifest.

Fixed a second early-exit bug: `kmi_next_stage_termux.sh`
previously tested `[[ -d "$dir" ]]` from ordinary Termux, which
returns false on **EACCES** and incorrectly classified system_dlkm
as absent. The stage now attempts root-based capture directly,
trying `/system_dlkm/lib/modules` followed by `/system/lib/modules`.
No mount changes are needed.

The BTF wrapper also no longer refuses the file based only on
ordinary Termux's `-e` check. Root may read BTF while an
unprivileged process cannot even `stat` it.

**Next action:** capture the booted kernel BTF JSON and 95-module
system_dlkm manifest directly to
`/sdcard/Documents/KMI-Guard` via the corrected wrapper.
These results are not yet available, so do not mark the structural
ABI or the remaining 14 CRC checks as passed.

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
