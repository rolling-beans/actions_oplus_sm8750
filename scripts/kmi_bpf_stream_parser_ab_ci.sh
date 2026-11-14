#!/usr/bin/env bash
# Optional, non-destructive KMI experiment after a full kernel Image build.
# Build only net/core/filter.o under an ISOLATED output directory with
# CONFIG_BPF_STREAM_PARSER=n, using the exact same source and toolchain.
# Do not modify the primary .config, compiled Image or installed modules.
set -euo pipefail
: "${GITHUB_WORKSPACE:?GitHub workspace is required}"
W="$GITHUB_WORKSPACE"
SOURCE="$W/kernel_workspace/common"
MAIN="$W/kout"
ALT="$W/kmi-bpf-parser-off-output"
EVIDENCE="$W/kmi-evidence"
mkdir -p "$EVIDENCE" "$ALT"

LOG="$EVIDENCE/bpf-stream-parser-ab-build.log"
REPORT="$EVIDENCE/bpf-stream-parser-ab.json"
echo "A/B KMI: isolated parser=n preprocessing and object build" > "$LOG"

fail() {
  echo "::warning title=BPF_STREAM_PARSER A/B unavailable::$1; see diagnostic artifact" >&2
  python3 - "$REPORT" "$1" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps(
    {"schema_version":1,"status":"UNVERIFIED","reason":sys.argv[2],
     "image_modified":False,"device_modified":False},indent=2)+"\n")
PY
  exit 0
}

[[ -s "$MAIN/.config" && -s "$MAIN/vmlinux.symvers" ]] ||
  fail "original compiled kernel evidence missing"
[[ ! -e "$ALT/.config" ]] || fail "isolated output directory already configured; refusing to overwrite"
cp "$MAIN/.config" "$ALT/.config"
"$SOURCE/scripts/config" --file "$ALT/.config" --disable BPF_STREAM_PARSER

export PATH="$W/kernel_workspace/clang-r563880c/bin:$W/kernel_workspace/build-tools/linux-x86/bin:$PATH"
MAP="-fdebug-prefix-map=${W}=. -fmacro-prefix-map=${W}=. -ffile-prefix-map=${W}=."
CFG="-O2 -pipe -Wno-error -Wno-implicit-function-declaration -Wno-implicit-int -Wno-default-const-init-var-unsafe -Wno-format -Wno-unknown-warning-option ${AFDO_CFLAGS:-} ${EXTRA_CFLAGS:-} ${MAP}"

run_bounded() {
  local limit="$1"
  shift
  timeout "$limit" make -C "$SOURCE" O="$ALT" ARCH=arm64 \
    LLVM=1 LLVM_IAS=1 CC="ccache clang" \
    KCFLAGS="$CFG" "$@" >> "$LOG" 2>&1
}

run_bounded 90s olddefconfig || fail "isolated olddefconfig did not complete"
grep -qx '# CONFIG_BPF_STREAM_PARSER is not set' "$ALT/.config" ||
  fail "Kconfig did not resolve BPF_STREAM_PARSER to n"
run_bounded 120s prepare || fail "isolated kernel prepare did not complete"
run_bounded 180s KBUILD_SYMTYPES=1 net/core/filter.o ||
  fail "isolated net/core/filter.o compilation did not complete"

CMD="$ALT/net/core/.filter.o.cmd"
[[ -s "$CMD" ]] || fail "isolated modversion command log missing"
VARIANT_CRC="$(awk '$1 == "#SYMVER" && $2 == "sk_filter_trim_cap" { print $3 }' "$CMD" | tail -n 1)"
[[ -n "$VARIANT_CRC" ]] || fail "genksyms did not emit sk_filter_trim_cap CRC"
awk '$1 == "#SYMVER" && $2 == "sk_filter_trim_cap" { print }' \
  "$CMD" > "$EVIDENCE/sk_filter_trim_cap-parser-off.symver"
[[ -f "$ALT/net/core/filter.symtypes" ]] &&
  cp "$ALT/net/core/filter.symtypes" "$EVIDENCE/filter-parser-off.symtypes" || true

python3 - "$W" "$VARIANT_CRC" "$REPORT" <<'PY'
import json,sys
from pathlib import Path
w=Path(sys.argv[1]); variant=sys.argv[2].lower()
symvers=(w/'kout/vmlinux.symvers').read_text()
base=None
for row in symvers.splitlines():
    a=row.split()
    if len(a)>2 and a[1]=='sk_filter_trim_cap' and a[2]=='vmlinux':
        base=a[0].lower()
        break
sys.path.insert(0,str(w/'kmi-tools/scripts'))
import kmi_stg_crc_diff
reference=kmi_stg_crc_diff.parse_stg(
    (w/'kernel_workspace/common/android/abi_gki_aarch64.stg').read_text())
original=reference.get('sk_filter_trim_cap',set())
expected=next(iter(original)).to_bytes(4,'big').hex() if len(original)==1 else None
if expected:expected='0x'+expected
result={
    'schema_version':1,
    'status': ('CRC_RESTORED_TO_REFERENCE' if expected and variant==expected
               else 'CRC_DIFFERENCE_PERSISTS'),
    'reference_stg_crc':expected,
    'compiled_kernel_crc':base,
    'experimental_parser_off_crc':variant,
    'experiment':'only CONFIG_BPF_STREAM_PARSER toggled from y to n in isolated Kconfig',
    'image_modified':False,
    'device_modified':False,
    'warning':'A matched CRC does not prove full structural KMI compatibility.',
}
Path(sys.argv[3]).write_text(json.dumps(result,indent=2)+"\n")
print('KMI isolated BPF_STREAM_PARSER AB:',result['status'],base,variant,expected)
PY
exit 0
