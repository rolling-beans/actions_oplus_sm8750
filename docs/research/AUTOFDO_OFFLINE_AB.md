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


## Stage 2: ELF function-size correction and profile name matching

The first comparison (Actions run 43659919568, PASS) found +2.674% in
\`.text\`, +1.666% in \`Image\` and +1.744% in \`vmlinux\` for the profiled
build. The observed -20.640% build-time difference is **not a valid causal
estimate**: the builds ran on independent GitHub runners, once each.

**Correction:** the v1 \`llvm-nm\` parser yielded 2,877 size-zero symbols
such as \`__kcfi_typeid_*\`. Its \`text_symbol_count\`,
\`text_symbol_size_sum\`, \`top_text_symbols\` and the generated
\`top-text-symbols.tsv\` must NOT be used as function-size evidence.

Stage 2 adds \`tools/autofdo_profile_match.py\`. It parses
\`llvm-readelf --symbols --wide\` for defined \`STT_FUNC\` records with
positive \`st_size\`, then replaces the misleading count/sum in the
metrics JSON. \`elf-function-sizes.json\` contains the corrected data;
the old top-text-symbols TSV is still produced by the v1 collector and
should be ignored. Duplicate local names are deduplicated using their
largest size. A \`STT_FUNC\` size is not necessarily disjoint or a
complete count of executable bytes.

The analyzer also streams the \`llvm-profdata show --sample\` function
headers and reports conservative *exact-name intersection* of sampled
functions with ELF symbols, along with a TotalSamples-weighted **proxy**.
This is NOT the percentage of profile records or samples applied by LLVM:
ThinLTO may inline, rename, clone, fold, or eliminate functions before
ELF emission. TotalSamples can include inlined nested samples, so
summing function weights can overcount. A function absent from the final
ELF can nevertheless have informed successful inlining.

The profile summary now uses \`--show-sec-info-only\`, avoiding accidental
archival of multiple ~45 MB full profile dumps.

Next research criterion: quantify actual sample-to-IR coverage from LLVM
diagnostics when a compatible, aggregation-safe measurement method is
validated. Do not report static name overlap as compiler coverage or
runtime improvement.

Existing successful Android boot of the profiled kernel is separate
from this offline analysis. This stage never touches any device.
