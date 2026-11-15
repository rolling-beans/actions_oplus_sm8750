#!/usr/bin/env bash
# Snapshot the already patched source without in-tree generated files.
# Does not touch original source, kout, devices, or module load state.
set -euo pipefail
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE required}"
W="$GITHUB_WORKSPACE"
ORIGINAL="$W/kernel_workspace/common"
COPY="$W/kernel_workspace/kmi-isolated-common"
EVIDENCE="$W/kmi-evidence"
mkdir -p "$EVIDENCE"

fail() {
  echo "::warning title=KMI isolated source unavailable::$1" >&2
  python3 - "$EVIDENCE/kmi-isolated-source.json" "$1" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps(
 {"schema_version":1,"status":"UNVERIFIED","reason":sys.argv[2],
  "primary_kout_modified":False,"device_modified":False},indent=2)+"\n")
PY
  exit 0
}
[[ -s "$ORIGINAL/Makefile" && -s "$ORIGINAL/net/core/filter.c" ]] ||
  fail "patched kernel source is unavailable"
[[ -s "$W/kout/.config" && -s "$W/kout/vmlinux.symvers" ]] ||
  fail "original build configuration or exports are missing"
[[ ! -e "$COPY" ]] || fail "refusing to overwrite an existing experiment source"
command -v rsync >/dev/null || fail "rsync unavailable"

mkdir -p "$COPY"
# Exact Kbuild out-of-tree cleanliness check: .config, include/config,
# and arch/arm64/include/generated. Also omit generated include/generated.
# Preserve all *source changes* applied by KernelSU, LRNG, SUSFS and the workflow.
if ! timeout 180s rsync -a --no-owner --no-group \
  --exclude='/.git/' \
  --exclude='/.config' \
  --exclude='/include/config/' \
  --exclude='/include/generated/' \
  --exclude='/arch/arm64/include/generated/' \
  "$ORIGINAL/" "$COPY/" > "$EVIDENCE/kmi-isolated-source-copy.log" 2>&1; then
  fail "copy failed (see kmi-isolated-source-copy.log)"
fi
[[ -s "$COPY/Makefile" && -s "$COPY/net/core/filter.c" ]] ||
  fail "isolated source is incomplete"
for dirty in "$COPY/.config" "$COPY/include/config" \
             "$COPY/arch/arm64/include/generated"; do
  [[ ! -e "$dirty" ]] || fail "Kbuild-dirty isolated source: $dirty"
done
python3 - "$ORIGINAL" "$COPY" "$EVIDENCE/kmi-isolated-source.json" <<'PY'
import hashlib,json,sys
from pathlib import Path
src,dst=map(Path,sys.argv[1:3])
files=["Makefile","net/core/filter.c","include/linux/skmsg.h",
       "net/Kconfig","android/abi_gki_aarch64.stg"]
checks={}
for f in files:
    srcsum=hashlib.sha256((src/f).read_bytes()).hexdigest()
    dstsum=hashlib.sha256((dst/f).read_bytes()).hexdigest()
    if srcsum!=dstsum:
        raise SystemExit(f"isolated source differs: {f}")
    checks[f]=srcsum
report={"schema_version":1,"status":"COMPLETE",
 "source_kind":"already patched, original generated files excluded",
 "source_match_sha256":checks,"primary_kout_modified":False,"device_modified":False}
Path(sys.argv[3]).write_text(json.dumps(report,indent=2)+"\n")
PY
echo "::notice title=KMI source snapshot::Clean patched source copy prepared for isolated genksyms"
