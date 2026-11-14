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

echo "=== Discover system_dlkm provider modules (root read) ==="
# Do not test the directory with unprivileged [[ -d ]]: Android may return
# EACCES even when the modules exist and sudo can read them.
# The collector itself runs as root and checks whether modules are present.
CAPTURED=0
for dir in /system_dlkm/lib/modules /system/lib/modules; do
  echo "Trying root-readable module root: $dir"
  if bash "$HERE/kmi_capture_termux.sh" --root "system_dlkm=$dir"; then
    echo "SYSTEM_DLKM_CAPTURE_OK root=$dir"
    CAPTURED=1
    break
  fi
done
if [[ "$CAPTURED" != 1 ]]; then
  echo "SYSTEM_DLKM_CAPTURE_UNVERIFIED (root collection failed or no modules)" >&2
fi

echo "=== Other first-stage module paths ==="
echo "Not inferred from unprivileged tests. See separate sudo runtime probe."
echo "No other module roots were modified or collected."
echo "Outputs, if available: /sdcard/Documents/KMI-Guard/"
