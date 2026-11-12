#!/data/data/com.termux/files/usr/bin/bash
# One safe user action for next KMI stage: live BTF + system_dlkm provider data.
# Read-only kernel/device operations. Output only into SAF Documents/KMI-Guard.
set -euo pipefail
: "$PREFIX"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"

echo "=== Running kernel BTF: read-only layout snapshot ==="
if bash "$HERE/kmi_capture_btf_termux.sh"; then
  echo "BTF_CAPTURE_OK"
else
  echo "BTF_CAPTURE_UNVERIFIED (no changes applied)" >&2
fi

echo "=== Discover system_dlkm provider modules ==="
MODULE_DIR=""
for dir in /system/lib/modules /system_dlkm/lib/modules; do
  if [[ -d "$dir" ]]; then
    MODULE_DIR="$dir"
    break
  fi
done
if [[ -z "$MODULE_DIR" ]]; then
  echo "system_dlkm module directory unavailable in current namespace" >&2
else
  echo "Module root: $MODULE_DIR"
  if bash "$HERE/kmi_capture_termux.sh" --root "system_dlkm=$MODULE_DIR"; then
    echo "SYSTEM_DLKM_CAPTURE_OK"
  else
    echo "SYSTEM_DLKM_CAPTURE_UNVERIFIED (see previous diagnostic)" >&2
  fi
fi

echo "=== Other first-stage module paths: read-only availability ==="
for dir in /lib/modules /odm/lib/modules /odm_dlkm/lib/modules; do
  if [[ -d "$dir" ]]; then
    echo "AVAILABLE: $dir (not modified or collected)"
  else
    echo "UNAVAILABLE: $dir"
  fi
done
echo "Outputs, if available: /sdcard/Documents/KMI-Guard/"
