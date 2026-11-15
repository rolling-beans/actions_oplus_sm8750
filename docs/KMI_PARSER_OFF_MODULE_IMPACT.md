# Parser-off KMI: real module import impact (research stage)

## Input provenance and current findings

The complete linked control and parser-off experiment:
GitHub Actions Run 43665975076, SHA 8b740db7582d1bc29449443bb43cd5e5a285f507.

This run compared both full vmlinux.symvers files and showed:
- 43 -> 24 original STG CRC mismatches; all 19 initial BPF/socket/XDP
  STG mismatches were restored.
- 45 changed common kernel export CRCs, not just the 19 STG mismatches.
- 26 additional changing CRCs are **not initial STG mismatch symbols**.
- Eight removed kernel exports: __strp_unpause, strp_check_rcv,
  strp_data_ready, strp_done, strp_init, strp_process, strp_stop,
  strp_unpause.
- Zero newly exported symbols.
- Both .config files differ solely by BPF_STREAM_PARSER=y->n and its
  STREAM_PARSER=y->absent dependency.

The original 593-module inventory (498 vendor, 95 system_dlkm; 34,353
imports) had exactly one direct kernel CRC mismatch with the earlier
kernel Image: system_dlkm/bluetooth.ko importing sk_filter_trim_cap.
The parser-off Image restored the STG CRC for sk_filter_trim_cap.
**It has NOT yet been checked against the private 593-module inventory.**
In particular, none of the 26 additional CRC changes or eight removed
exports may be assumed irrelevant merely because the 19 STG CRCs match.

The remaining 24 STG CRC deviations fall into LZ4 (10), ZSTD (5),
interconnect (7), and other (2: add_disk_randomness and
sysctl_sched_base_slice). The workflow deliberately patches LZ4 1.10.0,
ZSTD 1.5.7, LRNG and BORE. These are research leads, NOT demonstrated
causal assignments to individual CRCs. Revert/disable none until
controlled checks and module-import relevance are established.

## Read-only local comparison

Use scripts/kmi_compare_module_imports.py against two authentic,
separately collected manifest JSON files, **not public GitHub CI**.

Inputs:
- Baseline: parser-on-vmlinux.symvers from Run 43665975076.
- Variant: parser-off-vmlinux.symvers from the *same* run.
- Private vendor and system_dlkm manifests from the same phone capture.

The CLI takes two --manifest options, merges exported .ko providers
across manifests, and checks every required CRC separately against
both complete vmlinux exports and uniquely identified .ko providers.

Example, **on a trusted computer**, with appropriate real private paths:

    umask 077
    python3 -m scripts.kmi_compare_module_imports \
      --baseline-symvers /private/run/parser-on-vmlinux.symvers \
      --variant-symvers /private/run/parser-off-vmlinux.symvers \
      --manifest /private/vendor.json \
      --manifest /private/system_dlkm.json \
      --expected-modules 593 --expected-imports 34353 \
      --private-report /private/new-unique-report.json \
      --public-report /private/reviewed-aggregate.json

The private report is newly created mode 0600 (pre-existing target
is refused). It contains module paths and exact unmatched imports.
The separate public report provides aggregate verdicts and
symbol-level affected-importer counts, without module paths,
device identifiers, fingerprints, module hashes, or raw manifests.

Do not commit the private report or manifests. Do not publish a
public aggregate without checking that its source count and capture
status are satisfactory. First-stage vendor_boot/odm coverage,
full structural KMI and Android boot safety remain UNVERIFIED
even when this inventory comparison passes.

The report separately counts CRC mismatches, removed exports,
ambiguous or unknown module providers, insufficient capture,
and startup-list module rejections. Exact import numbers and the
original singleton mismatch must be re-established from authentic
input, not inferred from STG. Test fixtures intentionally model a
case where fixing sk_filter_trim_cap causes *new* failures on other
exports; do not mistake a passing parser-off STG comparison for a
passing vendor-module comparison.

## Bluetooth functional interpretation

Linux net/bluetooth/bluetooth.ko is a kernel AF_BLUETOOTH protocol
stack. Android's own userspace Bluetooth stack communicates via
the vendor Bluetooth HCI HAL and does not inherently require the
Linux AF_BLUETOOTH module. Historical phone snapshots recorded
Android Bluetooth working and the smartwatch connected while
Linux bluetooth.ko was absent from loaded modules. This proves
the latter was not required for those *observed* functions,
not that every future Bluetooth workload is unaffected.

Module loading was not forced and the exact historical loader
error was not observed. With MODVERSIONS enabled, the known
sk_filter_trim_cap CRC mismatch predicts ordinary load rejection,
but does not predict an Android bootloop. The parser-off kernel
fixes this CRC; until all 593 imports and any lost strp_* symbols
are checked, do not adopt the feature policy or patch around CRCs.
