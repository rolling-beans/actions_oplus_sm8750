#!/usr/bin/env bash
# Optional, bounded diagnostic. Run only after a successful Image build.
# Generates genksyms evidence for net/core/filter.c. Never relinks Image.
set -euo pipefail

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE not set}"
WORKDIR="$GITHUB_WORKSPACE"
EVIDENCE="$WORKDIR/kmi-evidence"
COMMON="$WORKDIR/kernel_workspace/common"
OUTPUT="$WORKDIR/kout"
CLOSURE="$WORKDIR/kmi-tools/scripts/kmi_symtypes_closure.py"
mkdir -p "$EVIDENCE"

export PATH="$WORKDIR/kernel_workspace/clang-r563880c/bin:$WORKDIR/kernel_workspace/build-tools/linux-x86/bin:$PATH"
MAP="-fdebug-prefix-map=${WORKDIR}=. -fmacro-prefix-map=${WORKDIR}=. -ffile-prefix-map=${WORKDIR}=."
CFG="-O2 -pipe -Wno-error -Wno-implicit-function-declaration -Wno-implicit-int -Wno-default-const-init-var-unsafe -Wno-format -Wno-unknown-warning-option ${AFDO_CFLAGS:-} ${EXTRA_CFLAGS:-} ${MAP}"

echo "KMI symtypes: bounded target-specific preprocessor run"
set +e
timeout 180s make -C "$COMMON" -j2 \
  LLVM=1 LLVM_IAS=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
  CC="ccache clang" O="$OUTPUT" KBUILD_SYMTYPES=1 \
  KCFLAGS="$CFG" net/core/filter.symtypes \
  > "$EVIDENCE/filter-symtypes-build.log" 2>&1
rc=$?
set -e

SOURCE="$OUTPUT/net/core/filter.symtypes"
if [[ "$rc" -eq 0 && -s "$SOURCE" ]]; then
  cp "$SOURCE" "$EVIDENCE/filter.symtypes"
  if ! python3 "$CLOSURE" \
    --symtypes "$EVIDENCE/filter.symtypes" \
    --symbol sk_filter_trim_cap \
    --output "$EVIDENCE/sk_filter_trim_cap-symtypes.json"; then
    echo "::warning title=genksyms incomplete::Raw data present, closure partial"
  fi
  awk '$2 == "sk_filter_trim_cap" && $3 == "vmlinux" { print }' \
    "$OUTPUT/vmlinux.symvers" > "$EVIDENCE/sk_filter_trim_cap.symvers"
  echo "::notice title=genksyms evidence::Saved targeted type graph; Image unchanged"
else
  echo "::warning title=genksyms unavailable::Optional probe exit $rc; see log"
  printf '{"status":"UNVERIFIED","capture_exit_code":%d}\n' "$rc" \
    > "$EVIDENCE/sk_filter_trim_cap-symtypes.json"
fi
exit 0
