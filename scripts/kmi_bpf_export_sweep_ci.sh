#!/usr/bin/env bash
# Optional post-build KMI test on cloned/patched source, no primary Image writes.
# Targeted objects map all 19 BPF/socket/XDP reference CRC drifts.
set -euo pipefail
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
W="$GITHUB_WORKSPACE"
SOURCE="$W/kernel_workspace/kmi-isolated-common"
CONTROL="$W/kmi-bpf-parser-on-output"
VARIANT="$W/kmi-bpf-parser-off-output"
EVIDENCE="$W/kmi-evidence"
mkdir -p "$EVIDENCE"
REPORT="$EVIDENCE/bpf-export-sweep.json"
MARKDOWN="$EVIDENCE/bpf-export-sweep.md"
LOG="$EVIDENCE/bpf-export-sweep-build.log"
echo 'Advisory object-level genksyms sweep; primary kout is read-only' > "$LOG"

unverified() {
 python3 - "$REPORT" "$MARKDOWN" "$1" <<'PY'
import json,sys
from pathlib import Path
report={"schema_version":1,"status":"UNVERIFIED",
        "reason":sys.argv[3],
        "device_modified":False,"primary_kout_modified":False}
Path(sys.argv[1]).write_text(json.dumps(report,indent=2)+"\n")
Path(sys.argv[2]).write_text("## BPF export sweep\n\nUNVERIFIED: "+sys.argv[3]+"\n")
PY
 echo "::warning title=BPF sweep unavailable::$1" >&2
 exit 0
}

[[ -s "$SOURCE/net/core/skmsg.c" && -s "$SOURCE/net/ipv4/tcp_bpf.c" ]] ||
 unverified "isolation source unavailable"
[[ -s "$W/kout/vmlinux.symvers" ]] || unverified "compiled kernel CRCs absent"
[[ -s "$CONTROL/.config" && -s "$VARIANT/.config" ]] ||
 unverified "separate preconfigured output trees absent"
python3 - "$EVIDENCE/sk_filter_trim_cap-control.json" \
  "$EVIDENCE/bpf-stream-parser-ab.json" <<'PY' || unverified "A/B control or variant evidence did not pass"
import json,sys
control=json.load(open(sys.argv[1]))
variant=json.load(open(sys.argv[2]))
assert control["status"]=="BASELINE_REPRODUCED"
assert variant["status"]=="CRC_RESTORED_TO_REFERENCE"
assert variant["baseline_reproduced"] is True
assert variant["only_expected_kconfig_changes"] is True
PY

export PATH="$W/kernel_workspace/clang-r563880c/bin:$W/kernel_workspace/build-tools/linux-x86/bin:$PATH"
MAP="-fdebug-prefix-map=${W}=. -fmacro-prefix-map=${W}=. -ffile-prefix-map=${W}=."
FLAGS="-O2 -pipe -Wno-error -Wno-implicit-function-declaration -Wno-implicit-int -Wno-default-const-init-var-unsafe -Wno-format -Wno-unknown-warning-option ${AFDO_CFLAGS:-} ${EXTRA_CFLAGS:-} ${MAP}"

for label in control variant; do
 if [[ "$label" == "control" ]]; then root="$CONTROL"; else root="$VARIANT"; fi
 echo "=== $label: building skmsg.o and tcp_bpf.o in isolated O= ===" >> "$LOG"
 if ! timeout 240s make -C "$SOURCE" -j2 O="$root" ARCH=arm64 \
      LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- \
      CC="ccache clang" KCFLAGS="$FLAGS" KBUILD_SYMTYPES=1 \
      net/core/skmsg.o net/ipv4/tcp_bpf.o >> "$LOG" 2>&1; then
   echo "::warning title=BPF sweep partial::Some $label objects failed; report will mark gaps" >&2
 fi
 for obj in net/core/.filter.o.cmd net/core/.skmsg.o.cmd net/ipv4/.tcp_bpf.o.cmd; do
   if [[ -s "$root/$obj" ]]; then
     name="$(basename "$obj")"
     grep '^#SYMVER ' "$root/$obj" \
       > "$EVIDENCE/bpf-$label-$name.symver" || true
   fi
 done
done

if ! python3 "$W/kmi-tools/scripts/kmi_bpf_export_sweep.py" \
  --stg "$SOURCE/android/abi_gki_aarch64.stg" \
  --symvers "$W/kout/vmlinux.symvers" \
  --source "$SOURCE" \
  --control "$CONTROL" --variant "$VARIANT" \
  --report-json "$REPORT" --report-md "$MARKDOWN"; then
 echo "::warning title=BPF export sweep incomplete::Inspect missing or mismatched objects in report" >&2
fi
cat "$MARKDOWN" >> "$GITHUB_STEP_SUMMARY"
echo "::notice title=BPF sweep::Reported changed BPF exported CRCs separately from module boot risks"
