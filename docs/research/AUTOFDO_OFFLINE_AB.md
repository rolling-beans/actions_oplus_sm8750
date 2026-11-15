# AutoFDO + ThinLTO: isolated static A/B research

Branch: `research/autofdo-thinlto-a-b-20261115`.

This research experiment **does not flash, boot, modify, or benchmark a device**. It does not publish releases, merge PRs, or change the production `master` workflow. Automatic builds are restricted to the experiment's research-branch `on.push.paths` filter; documentation-only commits do not trigger a rebuild.

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

The experimental workflow is auto-triggered only by a research-branch push affecting `.github/workflows/AutoFDO Offline Compare.yml`, `tools/autofdo_offline_metrics.py`, or `tools/autofdo_loader_diagnostics.py`. The kernel source archive is pinned, while other externally fetched patch/script repositories are not all pinned; the source-tree fingerprint detects source drift and causes comparison rejection instead of implying identical inputs. The profile URL is a mutable Android GKI branch ref; the captured SHA256 ensures both jobs used the same profile bytes.

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


## Stage 3: LLVM sample loader and ThinLTO inline remarks

Added \`tools/autofdo_loader_diagnostics.py\` and a profiled-vs-baseline
instrumented build in Actions run
[43703841188](https://github.com/rolling-beans/actions_oplus_sm8750/actions/runs/43703841188).

This branch-only research adds no patches to the kernel itself and does
not touch the production \`master\` workflow.

**Direct LLVM source evidence**:

- \`-sample-profile-check-record-coverage=101\`
- \`-sample-profile-check-sample-coverage=101\`

LLVM's SampleCoverageTracker reports per-function counts of profile records
and sample weights applied to LLVM IR. Threshold 101 requests diagnostics
even at 100% matching, as documented by LLVM's coverage-warning tests. These
options are passed to kernel Clang through \`KCFLAGS\` **only** for the
profiled job and to its vmlinux LLD ThinLTO passes.

**Important aggregation limitation:** LLVM may process the same function
multiple times in separate translation units and ThinLTO stages. A sum
of "X of Y available samples" warnings is NOT a global percentage of
the profile consumed by the kernel. The parser reports warning instance
counts, unique diagnostic tuples and illustrative cases, without a false
"whole kernel profile coverage" number. It also cannot prove whether
profile information improves hardware execution time.

At the link stage, the \`ld-wrapper\` requests serialized YAML optimization
remarks filtered to \`inline|sample-profile\` for outputs whose basename
begins with \`vmlinux\`. The parser counts remark types and named functions
for each A/B build. This covers only passes with emitted remarks in the LLD
ThinLTO phase; earlier per-object inlining can be missed. Missing YAML
files must be reported as absence of evidence, **not** as zero inlining.

The full raw LLD YAML and compiler logs remain ephemeral on the runner,
while compact JSON samples and comparison Markdown are uploaded to the
experiment's GitHub Actions artifacts. The profile bytes and Kconfig
remain identical across both builds.

Primary references:
- https://llvm.org/docs/Remarks.html
- https://clang.llvm.org/docs/UsersManual.html
- https://llvm.org/doxygen/SampleProfileLoaderBaseUtil_8cpp_source.html
- https://kernel.org/doc/html/latest/dev-tools/autofdo.html

Stage-3 results and any blocked diagnostics must be recorded after
the Actions run finishes. A successful compile with no parsed warnings
does not establish complete profile coverage.

## Stage 3 initial failure and corrective change

- Run [43703841188](https://github.com/rolling-beans/actions_oplus_sm8750/actions/runs/43703841188) **FAILED** in both variants at `vmlinux.o` link, due to joined `--opt-remarks-filename=...`, `--opt-remarks-passes=...`, and `--opt-remarks-format=...` flags rejected by the bundled Android LLD. The `comparison` job failed consequentially because the build did not produce complete metrics.
- Diagnostic root cause is **argument syntax**, not proof of an AutoFDO or kernel compilation regression. Earlier A/B runs succeeded without linker remark options.
- Fix in commit `ee8375c5c4b078b7936e739404ae36c885f6eb90`: use separate option/value argv pairs for these LLD options. Perform an AArch64 relocatable smoke link using **the exact arguments** during preflight rather than merely grepping `ld.lld --help`. Use process-specific remark filenames and skip dependent comparison when builds fail.
- Verify the **new** run [43706179572](https://github.com/rolling-beans/actions_oplus_sm8750/actions/runs/43706179572) before claiming all diagnostics work.

## Stage 3 completed: run 43706179572 (15 November 2026)

**Status:** [run 43706179572](https://github.com/rolling-beans/actions_oplus_sm8750/actions/runs/43706179572) completed `SUCCESS` for `compare-build (baseline)`, `compare-build (profiled)`, and `comparison`. All build, preflight, collection, parser, and upload steps passed. Run head is **`ee8375c5c4b078b7936e739404ae36c885f6eb90`** (not the subsequent documentation-only branch commit). No further build was launched for this analysis.

Verified saved artifacts:

- [baseline #14159690458](https://github.com/rolling-beans/actions_oplus_sm8750/actions/runs/43706179572/artifacts/14159690458), SHA256 `593bd6aa5ddf363ed9d3c65f3744ad9563e5b28648c8bc9b6a771c48db9385f7`;
- [profiled #14159650917](https://github.com/rolling-beans/actions_oplus_sm8750/actions/runs/43706179572/artifacts/14159650917), SHA256 `8a250457f1054855e90fe8ab064c37e273c9bc1a26c221a6e7a6597105514de3`;
- [comparison #14159452322](https://github.com/rolling-beans/actions_oplus_sm8750/actions/runs/43706179572/artifacts/14159452322), SHA256 `d5bf3e8bb907df8dda5435e591977128283050670472689c4217de53cb0d0bae`.

Downloaded ZIP byte hashes matched their GitHub artifact digests. Baseline and profiled source-tree fingerprints agree:
`e020d345a1ccc3aaf8a0e300ab73de8de10816a76ded8cdc50a1b849f2e94f83`.
The effective `.config` SHA256 is identical:
`6e94f3ea34e1dcba3ed56356769e2c0783c4283cc17d09b17960981a195e32cd`.
Google profile SHA256 is identical:
`b27ba364e664c5d83daae4cece90dffe95b6388bc2c214c2b2e1a5f35b0654b2`.
Both Kconfigs have `CONFIG_AUTOFDO_CLANG=y` and ThinLTO. Linker evidence confirms `--lto-sample-profile` present **only** in profiled. Toolchain: AOSP Clang 21.0.0 r563880c. These checks support controlled static A/B inputs, not identical compilation environments or hardware runtimes.

### ELF and code sizes (confirmed in run 43706179572)

| Quantity | Baseline | Profiled | Difference |
|---|---:|---:|---:|
| `.text` bytes | 20,529,152 | 21,078,016 | +548,864 (+2.674%) |
| `Image` bytes | 43,768,320 | 44,497,408 | +1.666% |
| `vmlinux` bytes | 292,532,712 | 297,662,488 | +1.754% |
| Defined, positive-sized ELF function names | 71,283 | 71,500 | +217 |
| Exact-name intersection with 8,851 profile functions | 8,437 | 8,139 | -298 |
| TotalSamples-weighted exact-name proxy | 95.072% | 89.306% | -5.766 pp |
| Build wall seconds | 1,207 | 1,394 | not a causal speed comparison |

The exact-name change may result from inlining, code elimination, renaming, and cloning: it is **not** sample-to-IR coverage. The 10,695 common named functions with differing STT_FUNC sizes include `binder_ioctl_write_read` (+19,460 B), `binder_transaction` (+16,508 B), `run_state_machine` (+17,092 B), and `__f2fs_ioctl` (-12,772 B). Section/symbol sizes alone cannot identify which inline calls caused those changes.

### Actual observed LLVM loader and optimization diagnostics

These counts describe **warning and remark instances**, not unique function optimizations and not a globally additive sample coverage rate.

| Kind | Baseline | Profiled |
|---|---:|---:|
| Parsed profile-record warning instances | 0 | 52,651 |
| Distinct source/kind/used/available tuples (records) | 0 | 25,863 |
| Parsed profile-sample warning instances | 0 | 47,068 |
| Distinct source/kind/used/available tuples (samples) | 0 | 31,332 |
| Records warnings with recomputed ratio below 50% | 0 | 1,029 |
| Samples warnings with recomputed ratio below 50% | 0 | 1,293 |
| LLD remark YAML files found | 3,089 | 3,091 |
| Oversized remark files omitted | 0 | 0 |
| `inline` / Passed | 14,402 | 16,515 |
| `inline` / Missed | 325,766 | 324,021 |
| `sample-profile` / Passed | 0 | 5,621 |
| `sample-profile-impl` / Analysis | 0 | 763,526 |
| `sample-profile-inline` / Analysis | 0 | 2,999 |
| `sample-profile-inline` / Passed | 0 | 22 |

The `inline / Passed` remark count increased by 2,113 (~14.7%) in this observed ThinLTO set, but a remark is a logged pass decision, not a guaranteed unique machine-code transformation. Multiple link stages, per-module processing, repeated function contexts, and large profile-analysis remark volumes prevent direct causal attribution of `.text` growth to individual calls. The compact `lto-remark-cases.json` files are truncated to the first 2,000 inline cases per variant; they omit nested `Args` and `DebugLoc`, so they **cannot** establish callee/callsite/threshold for the large Binder, scheduler, or F2FS changes. The complete YAML and /tmp build log were not archived.

### Important newly diagnosed bug in LLVM's own displayed coverage percentage

Audit of the 500 retained sample-warning lines in profiled `profile-build-notes.txt`:

- All **500/500** displayed LLVM percentages reproduce the expression
  `((uint32_t(used) * 100) mod 2^32) / uint32_t(available)` (integer quotient, with a zero denominator treated as 100).
- **105/500** disagree with the 64-bit/exact `100 * used / available` ratio by at least 2 percentage points.
- **28/500** have `used > available`, including some cases with `available = 0`; they cannot be treated as conventional coverage percentages.
- Example: `140707870 of 178186899 ... (6%)` is **78.966%** when computed without overflow, but `6%` with the 32-bit product. Similarly `462125020 / 585760562` is **78.893%**, displayed as `5%`. There are also cases where equal `used` and `available` values print a very low percentage.

The upstream LLVM `SampleCoverageTracker::computeCoverage(unsigned Used, unsigned Total)` implementation uses `Used * 100 / Total`, and `emitCoverageRemarks` feeds it 64-bit sample values. This exactly explains the observed 32-bit overflow and argument narrowing in the r563880c diagnostic output. Upstream references:
[LLVM computeCoverage](https://llvm.org/doxygen/SampleProfileLoaderBaseUtil_8cpp_source.html),
[LLVM emitCoverageRemarks](https://llvm.org/doxygen/SampleProfileLoaderBaseImpl_8h_source.html).
The exact Android LLVM source revision was not directly inspected, so source-level identity is inferred from the perfectly matching observed behavior, not asserted.

**Crucial distinction:** this proves that the *warning's displayed percentage is unreliable* for large sample counts. It does **not** establish corruption of LLVM profile application, inlining decisions, or generated code. Do not patch production Clang based only on these diagnostics.

The current Python diagnostics parser independently recomputes `percent_exact` for admitted tuples, which protects its `below_50_pct`/`below_80_pct` counts against this integer-overflow presentation error. However, it discards `used > available` and zero-denominator rows, with no anomaly tally; this is an **observability gap**. Its first-1,500 saved coverage cases are sorted toward low ratios and therefore are not a representative random sample. Neither the parser nor the LLVM warnings provide a defensible global profile-use percentage.

### Evidence-based status and smallest next stage

1. Stage 3 build, collection, comparison, profile loading, and ThinLTO optimization remarks **PASS**. Both control inputs and ZIP integrity checked.
2. There is direct evidence of real loader warnings and profile-related LTO passes, plus additional observed `inline / Passed` remarks in the profiled condition.
3. The relationship between specific changed ELF functions, individual `inline` decisions, and their callsites remains **unresolved**, because nested YAML `Args`/`DebugLoc` were discarded.
4. Before spending another pair of kernel builds, use the saved compact artifacts to validate formatting and design a bounded, streaming remarks extractor. For a later *single justified* instrumented A/B pair, preserve `Function`, `Name`, `Pass`, `DebugLoc`, nested callee/callsite/cost/threshold `Args`, and summaries keyed by explicit high-impact functions (`binder_ioctl_write_read`, `binder_transaction`, `run_state_machine`, `pick_next_task_fair`, `__f2fs_ioctl`, etc.).
5. Update loader diagnostics to track inconsistent/zero-denominator/`used > available` rows separately and compute the reported ratio with at least 64-bit-safe arithmetic **for reporting**; do not silently fold anomalies into 0–100% coverage.
6. Editing the existing `tools/autofdo_loader_diagnostics.py` or experimental workflow triggers an automatic full A/B run via `on.push.paths`. Prototype/test fixes without touching those paths until another expensive pair is explicitly warranted. A documentation-only commit is safe.
7. No changes to production workflow, no device flashes, no claim of actual OnePlus 13 performance improvement.
