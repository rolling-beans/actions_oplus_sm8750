#!/usr/bin/env bash
# Read-only KMI baseline probe: independent patched source and independent O=.
# Never run make against kout or alter the bootable kernel Image.
set -euo pipefail
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE required}"
W="$GITHUB_WORKSPACE"
EVIDENCE="$W/kmi-evidence"
COMMON="$W/kernel_workspace/kmi-isolated-common"
OUTPUT="$W/kmi-bpf-parser-on-output"
PRIMARY="$W/kout"
CLOSURE="$W/kmi-tools/scripts/kmi_symtypes_closure.py"
mkdir -p "$EVIDENCE"
LOG="$EVIDENCE/filter-symtypes-build.log"
printf 'KMI independent baseline: clone of patched sources, untouched kout\n' > "$LOG"

fail() {
 echo "::warning title=KMI baseline probe unavailable::$1" >&2
 python3 - "$EVIDENCE/sk_filter_trim_cap-control.json" \
           "$EVIDENCE/sk_filter_trim_cap-symtypes.json" "$1" <<'PY'
import json,sys
from pathlib import Path
report={"schema_version":1,"status":"UNVERIFIED","reason":sys.argv[3],
        "primary_kout_modified":False,"device_modified":False}
for x in sys.argv[1:3]:
    Path(x).write_text(json.dumps(report,indent=2)+"\n")
PY
 exit 0
}
[[ -s "$COMMON/Makefile" && -s "$EVIDENCE/kmi-isolated-source.json" ]] ||
 fail "verified isolated source unavailable"
python3 - "$EVIDENCE/kmi-isolated-source.json" <<'PY' || fail "isolated source did not pass integrity check"
import json,sys
assert json.load(open(sys.argv[1]))["status"]=="COMPLETE"
PY
[[ -s "$PRIMARY/.config" && -s "$PRIMARY/vmlinux.symvers" ]] ||
 fail "original built kernel config/exports unavailable"
[[ ! -e "$OUTPUT/.config" ]] || fail "refusing to overwrite existing baseline output"
mkdir -p "$OUTPUT"
cp "$PRIMARY/.config" "$OUTPUT/.config"
export PATH="$W/kernel_workspace/clang-r563880c/bin:$W/kernel_workspace/build-tools/linux-x86/bin:$PATH"
MAP="-fdebug-prefix-map=${W}=. -fmacro-prefix-map=${W}=. -ffile-prefix-map=${W}=."
CFG="-O2 -pipe -Wno-error -Wno-implicit-function-declaration -Wno-implicit-int -Wno-default-const-init-var-unsafe -Wno-format -Wno-unknown-warning-option ${AFDO_CFLAGS:-} ${EXTRA_CFLAGS:-} ${MAP}"
bounded() {
 local limit="$1"; shift
 timeout "$limit" make -C "$COMMON" O="$OUTPUT" -j2 ARCH=arm64 \
   LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- \
   CC="ccache clang" KCFLAGS="$CFG" "$@" >> "$LOG" 2>&1
}
bounded 100s olddefconfig || fail "baseline olddefconfig failed"
bounded 150s prepare scripts || fail "baseline prepare scripts failed"
bounded 180s KBUILD_SYMTYPES=1 net/core/filter.symtypes ||
 fail "baseline genksyms types failed"
bounded 180s KBUILD_SYMTYPES=1 net/core/filter.o ||
 fail "baseline filter object build failed"
[[ -s "$OUTPUT/net/core/filter.symtypes" && -s "$OUTPUT/net/core/.filter.o.cmd" ]] ||
 fail "baseline genksyms outputs missing"
cp "$OUTPUT/net/core/filter.symtypes" "$EVIDENCE/filter.symtypes"
python3 "$CLOSURE" --symtypes "$EVIDENCE/filter.symtypes" \
 --symbol sk_filter_trim_cap \
 --output "$EVIDENCE/sk_filter_trim_cap-symtypes.json" ||
 echo "::warning title=Partial genksyms graph::Raw type definitions preserved"
awk '$1=="#SYMVER" && $2=="sk_filter_trim_cap" {print}' \
 "$OUTPUT/net/core/.filter.o.cmd" \
 > "$EVIDENCE/sk_filter_trim_cap-control.symver"
python3 - "$EVIDENCE/sk_filter_trim_cap-control.symver" \
 "$PRIMARY/vmlinux.symvers" "$EVIDENCE/sk_filter_trim_cap-control.json" \
 "$PRIMARY/.config" "$OUTPUT/.config" <<'PY'
import json,sys
from pathlib import Path
crc=Path(sys.argv[1]).read_text().split()
assert len(crc)==3 and crc[1]=="sk_filter_trim_cap"
orig=[x.split()[0].lower() for x in Path(sys.argv[2]).read_text().splitlines()
      if len(x.split())>=3 and x.split()[1:3]==["sk_filter_trim_cap","vmlinux"]]
assert len(orig)==1
a,b=crc[2].lower(),orig[0]
def parse(path):
 d={}
 for line in Path(path).read_text().splitlines():
  if line.startswith("CONFIG_") and "=" in line:
   k,v=line.split("=",1);d[k]=v
  elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
   d[line[2:].split(" is not set")[0]]="n"
 return d
old,new=parse(sys.argv[4]),parse(sys.argv[5])
diff={k:{"original":old.get(k),"control":new.get(k)}
      for k in sorted(old.keys()|new.keys()) if old.get(k)!=new.get(k)}
r={"schema_version":1,
   "status":"BASELINE_REPRODUCED" if a==b and not diff else
            "BASELINE_CRC_MATCH_CONFIG_DRIFT" if a==b else "BASELINE_NOT_REPRODUCED",
   "compiled_kernel_crc":b,"local_control_crc":a,
   "control_matches_kernel_crc":a==b,
   "baseline_config_changes":diff,
   "primary_kout_modified":False,"device_modified":False}
Path(sys.argv[3]).write_text(json.dumps(r,indent=2)+"\n")
print("Control sk_filter_trim_cap:",r["status"],b,a,"config_changes",len(diff))
PY
echo "::notice title=KMI control evidence::Isolated genksyms baseline compiled; original kout untouched"
