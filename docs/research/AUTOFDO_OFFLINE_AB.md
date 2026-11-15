# AutoFDO + ThinLTO: isolated static A/B research

Branch: `research/autofdo-thinlto-a-b-20261115`.

This research experiment **does not flash, boot, modify, or benchmark a device**. It does not publish releases, merge PRs, or change the production `master` workflow. The only trigger is a push affecting the experiment workflow or its metrics script in the dedicated research branch.

## Design

- The build workflow starts from production `Build Kernel AOSP.yml` setup and patch steps, but stops before packaging / Telegram / release steps.
- Pin the baseline kernel source archive to upstream commit `7c4d3772a8db0a7ba1f010ffe87fa9e5cfbd237b` (6.6.144 OnePlus 13).
- Run two independent jobs with **the same `CONFIG_AUTOFDO_CLANG=y` and `CONFIG_LTO_CLANG_THIN=y`**.
  - `baseline`: pass **no** `CLANG_AUTOFDO_PROFILE`; kernel Kbuild retains profile-collection-related flags.
  - `profiled`: pass `CLANG_AUTOFDO_PROFILE=$GITHUB_WORKSPACE/kernel.afdo`, triggering sample profile flags at both compile and ThinLTO link stages.
- Each run downloads and validates the same Google GKI 6.6 AutoFDO profile (the compiler/toolchain must recognize it).
- Disable ccache hits in both jobs and disable restore of LTO cache to avoid comparing stale compiled objects. Toolchain caches may still be used.
- Fingerprint all patched kernel source files, record toolchain versions, compare effective `.config` SHA256 and profile SHA256. The final report **rejects** an uncontrolled comparison.
- Require linker evidence for `--lto-sample-profile=` only in the profiled job; require its absence in baseline.

## Measurements

The jobs collect:
- `vmlinux` and `Image` sizes and SHA256 hashes.
- LLVM ELF section sizes (including `.text` and `.rodata`), file and section metadata.
- Text symbol count, aggregate text-symbol sizes and largest 200 symbols (symbol sizes are *not* dynamic instruction counts).
- Build wall time (informational only: the GitHub runners may differ in load).
- Profile SHA256, `llvm-profdata show --sample --topn=100`, whether symbol-list metadata is present, and sample-related compiler output.
- An aggregate `summary.md` and `comparison.csv` downloaded from job artifacts.

**Limitations:** A smaller `Image` or different `vmlinux` does not demonstrate a runtime speedup. Top function sample counts are profile-side data, not evidence that the compiler successfully matched source lines or optimized those paths. Even matching symbol names does not prove profile coverage. Google/Pixel samples may be stale for OnePlus 13 patches and workloads. Proving performance would require controlled on-device A/B measurements, currently out of scope.

## Sources

- [Linux AutoFDO documentation](https://docs.kernel.org/dev-tools/autofdo.html)
- [LLVM llvm-profdata command guide](https://llvm.org/docs/CommandGuide/llvm-profdata.html)
- [Android GKI 6.6 sample profiles](https://android.googlesource.com/kernel/common/+/refs/heads/android15-6.6/android/gki/aarch64/afdo/)
- [Source AOSP kernel workflow](../.github/workflows/Build%20Kernel%20AOSP.yml)

## Safety

Do **not** boot-test experimental images from this branch automatically. No GitHub release or Telegram publication is part of this experiment. After collecting reproducible evidence, review the findings before deciding whether any changes should land in `master`.

## Reproducibility

The experimental workflow is auto-triggered only by a push affecting `.github/workflows/AutoFDO Offline Compare.yml` or `tools/autofdo_offline_metrics.py` in the research branch. The kernel source archive is pinned, while other externally fetched patch/script repositories are not all pinned; the source-tree fingerprint detects source drift and causes comparison rejection instead of implying identical inputs. The profile URL is a mutable Android GKI branch ref; the captured SHA256 ensures both jobs used the same profile bytes.

The findings are *offline measurements only*; the research is not a formal end-to-end validation of the production kernel or its boot properties.
