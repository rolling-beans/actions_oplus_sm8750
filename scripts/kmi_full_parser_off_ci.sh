#!/usr/bin/env bash
# Same-run primary Image parser=y, isolated complete Image parser=n.
# Does not modify primary kout, devices, or kernel releases.
set -euo pipefail
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
W="$GITHUB_WORKSPACE"
SRC="$W/kernel_workspace/kmi-isolated-common"
MAIN="$W/kout"
ALT="$W/kmi-full-parser-off-output"
EV="$W/kmi-full-parser-off-evidence"
TOOL="$W/kmi-tools/scripts/kmi_full_parser_compare.py"
mkdir -p "$EV"
LOG="$EV/build.log"
REPORT="$EV/report.json"
echo "Full parser-off kernel build, same-run parser-on control" > "$LOG"
if [[ ! -s "$SRC/Makefile" || ! -s "$MAIN/vmlinux.symvers" || ! -s "$MAIN/arch/arm64/boot/Image" ]]; then
  echo "::error::Main Image or isolated patched source not available"
  exit 2
fi
python3 - "$W/kmi-evidence/kmi-isolated-source.json" <<'PY'
import json,sys
a=json.load(open(sys.argv[1]))
assert a["status"]=="COMPLETE", "Isolated source snapshot was not verified"
PY
if [[ -e "$ALT/.config" ]]; then
  echo "::error::Refusing to reuse a configured parser-off build output"
  exit 2
fi
mkdir -p "$ALT"
cp "$MAIN/.config" "$ALT/.config"
"$SRC/scripts/config" --file "$ALT/.config" --disable BPF_STREAM_PARSER

export PATH="$W/kernel_workspace/clang-r563880c/bin:$W/kernel_workspace/build-tools/linux-x86/bin:$PATH"
export CCACHE_DIR="${CCACHE_DIR:-$HOME/.ccache_6.6.144}"
export CCACHE_IS_KERNEL_COMPILING=true
export CCACHE_LOGFILE="$EV/ccache.log"
MAP="-fdebug-prefix-map=${W}=. -fmacro-prefix-map=${W}=. -ffile-prefix-map=${W}=."
FLAGS="-O2 -pipe -Wno-error -Wno-implicit-function-declaration -Wno-implicit-int -Wno-default-const-init-var-unsafe -Wno-format -Wno-unknown-warning-option ${AFDO_CFLAGS:-} ${EXTRA_CFLAGS:-} ${MAP}"
LINKER="$SRC/ld-wrapper"
[[ -x "$LINKER" ]] || { echo "::error::No same-source LTO linker wrapper"; exit 2; }

make -C "$SRC" O="$ALT" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
  CROSS_COMPILE=aarch64-linux-gnu- CC="ccache clang" LD="$LINKER" HOSTLD="$LINKER" \
  KCFLAGS="$FLAGS" olddefconfig >> "$LOG" 2>&1

# Strict gate before allocating resources for another complete kernel.
PYTHONPATH="$W/kmi-tools" python3 "$TOOL" \
  --phase config --control-config "$MAIN/.config" --variant-config "$ALT/.config" \
  --net-kconfig "$SRC/net/Kconfig" --report-json "$EV/config-delta.json" \
  --report-md "$EV/config-delta.md" | tee -a "$LOG"
cp "$MAIN/.config" "$EV/parser-on.config"
cp "$ALT/.config" "$EV/parser-off.config"

python3 - "$W" "$SRC" "$EV" "$FLAGS" <<'PY'
import hashlib,json,os,subprocess,sys
from pathlib import Path
w,src,ev=map(Path,sys.argv[1:4])
def digest(p):
    if not p.is_file(): return None
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""):h.update(chunk)
    return h.hexdigest()
def gitsha(path):
    if not (path/".git").exists():return None
    r=subprocess.run(["git","-C",str(path),"rev-parse","HEAD"],
                     capture_output=True,text=True)
    return r.stdout.strip() if r.returncode==0 else None
data={
 "schema_version":1, "run_id":os.getenv("GITHUB_RUN_ID"),
 "run_sha":os.getenv("GITHUB_SHA"), "run_ref":os.getenv("GITHUB_REF"),
 "comparison":"same-run two complete Image targets from matched patched sources",
 "kernel_source_archive":"palazik 6.6.144_oneplus13_coloros16 (mutable branch at download time)",
 "kernel_source_archive_sha256_record":(
     (w/"kernel-source-archive.sha256").read_text().strip()
     if (w/"kernel-source-archive.sha256").is_file() else None),
 "source_isolation":json.loads((w/"kmi-evidence/kmi-isolated-source.json").read_text()),
 "source_fingerprints":{s:digest(src/s) for s in [
     "Makefile","net/core/filter.c","net/core/skmsg.c","net/ipv4/tcp_bpf.c",
     "net/Kconfig","arch/arm64/configs/gki_defconfig","android/abi_gki_aarch64.stg",
     "include/linux/skmsg.h","ld-wrapper"]},
 "external_patch_repos":{s:gitsha(w/"kernel_workspace"/s) for s in [
     "common/KernelSU","wildkernels_patches","kernel_patches",
     "SukiSU_patch","susfs4ksu"]},
 "ccache_not_source_of_truth":True,
 "afdo_profile_sha256":digest(w/"kernel.afdo"),
 "afdo_flags":os.getenv("AFDO_CFLAGS",""),
 "extra_cflags":os.getenv("EXTRA_CFLAGS",""),
 "kernel_compiler_flags":sys.argv[4],
 "clang_version":subprocess.run(["clang","--version"],capture_output=True,text=True).stdout.splitlines()[:1],
 "lld_version":subprocess.run(["ld.lld","--version"],capture_output=True,text=True).stdout.splitlines()[:1],
 "control_config_sha256":digest(w/"kout/.config"),
 "variant_config_sha256":digest(w/"kmi-full-parser-off-output/.config"),
 "control_image_sha256":digest(w/"kout/arch/arm64/boot/Image"),
 "private_modules_not_in_public_ci":True,"device_modified":False
}
(ev/"provenance.json").write_text(json.dumps(data,indent=2)+"\n")
PY

FREE_KB="$(df -Pk "$W" | awk 'NR==2 {print $4}')"
if (( FREE_KB < 4 * 1024 * 1024 )); then
  echo "::error::Insufficient free disk for a second complete kernel (<4 GiB)" | tee -a "$LOG"
  exit 2
fi
echo "Variant build disk free: $((FREE_KB/1024)) MiB" | tee -a "$LOG"
make -C "$SRC" -j"$(nproc --all)" O="$ALT" ARCH=arm64 \
  LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- \
  CC="ccache clang" LD="$LINKER" HOSTLD="$LINKER" \
  KCFLAGS="$FLAGS" Image >> "$LOG" 2>&1 || {
    rc=$?
    echo "::error::Full isolated parser-off Image build failed, rc=$rc; check artifact log"
    exit "$rc"
  }

[[ -s "$ALT/arch/arm64/boot/Image" && -s "$ALT/vmlinux" && -s "$ALT/vmlinux.symvers" ]] ||
  { echo "::error::Full variant Image/vmlinux/symvers incomplete"; exit 2; }
cp "$ALT/arch/arm64/boot/Image" "$EV/parser-off-Image"
cp "$ALT/vmlinux.symvers" "$EV/parser-off-vmlinux.symvers"
cp "$MAIN/vmlinux.symvers" "$EV/parser-on-vmlinux.symvers"

PYTHONPATH="$W/kmi-tools" python3 "$TOOL" \
  --phase exports --control-config "$MAIN/.config" --variant-config "$ALT/.config" \
  --net-kconfig "$SRC/net/Kconfig" --stg "$SRC/android/abi_gki_aarch64.stg" \
  --control-symvers "$MAIN/vmlinux.symvers" --variant-symvers "$ALT/vmlinux.symvers" \
  --known-sweep "$W/kmi-tools/kmi/ci-bpf-export-sweep-43661651465.json" \
  --report-json "$REPORT" --report-md "$EV/report.md"
python3 - "$EV" "$ALT" <<'PY'
import hashlib,json,sys
from pathlib import Path
ev,alt=map(Path,sys.argv[1:])
data=json.loads((ev/"provenance.json").read_text())
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()
for name,path in {"variant_image":alt/"arch/arm64/boot/Image",
                  "variant_vmlinux":alt/"vmlinux",
                  "variant_vmlinux_symvers":alt/"vmlinux.symvers"}.items():
    data[name]={"size":path.stat().st_size, "sha256":sha(path)}
(ev/"provenance.json").write_text(json.dumps(data,indent=2)+"\n")
PY
cat "$EV/report.md" >> "$GITHUB_STEP_SUMMARY"
echo "::notice::Full parser-off Image linked; private module-import coverage is UNVERIFIED."
