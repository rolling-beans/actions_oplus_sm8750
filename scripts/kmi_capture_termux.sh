#!/data/data/com.termux/files/usr/bin/bash
# Android KMI metadata capture: privileged READ, unprivileged SAF WRITE.
# No mounts, flashing, module insertion, network access, or SELinux changes.
set -euo pipefail

: "$PREFIX"
COLLECTOR="$(cd -- "$(dirname -- "$0")" && pwd)/kmi_collect_android.py"
PYTHON="$PREFIX/bin/python3"
OUTDIR="/sdcard/Documents/KMI-Guard"

if [ ! -f "$COLLECTOR" ] || [ ! -x "$PYTHON" ]; then
  echo "Collector or Termux Python unavailable" >&2
  exit 2
fi
if ! command -v sudo >/dev/null 2>&1; then
  echo "Termux sudo is needed to read protected vendor modules" >&2
  exit 2
fi

# Verify SAF/shared directory permissions before any privileged operation.
if ! mkdir -p -- "$OUTDIR"; then
  echo "Cannot create $OUTDIR; grant Termux shared-storage access" >&2
  exit 2
fi
if [ ! -w "$OUTDIR" ]; then
  echo "$OUTDIR is not writable by the regular Termux user" >&2
  exit 2
fi

mkdir -p -- "$PREFIX/tmp"
TMPFILE="$(mktemp "$PREFIX/tmp/kmi-vendor-root-XXXXXXXX.json")"
chmod 600 "$TMPFILE"
cleanup() { rm -f -- "$TMPFILE"; }
trap cleanup EXIT

sudo "$PYTHON" "$COLLECTOR" --output "$TMPFILE" "$@"
sudo /system/bin/chown "$(id -u):$(id -g)" "$TMPFILE"

STAMP="$(date +%Y%m%d-%H%M%S)"
TARGET="$(mktemp "$OUTDIR/android-kmi-vendor-$STAMP-XXXXXXXX.json")"
chmod 600 "$TARGET" 2>/dev/null || true  # SAF emulated storage may not implement chmod.
if ! cp -- "$TMPFILE" "$TARGET"; then
  rm -f -- "$TARGET"
  exit 1
fi
echo "SAF-accessible KMI metadata: $TARGET"
