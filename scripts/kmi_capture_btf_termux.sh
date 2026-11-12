#!/data/data/com.termux/files/usr/bin/bash
# Read-only capture of the *currently booted* kernel BTF. SAF write as user.
# No flashing, mounts, writes to /sys, insmod, or SELinux policy changes.
set -euo pipefail
: "$PREFIX"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
PYTHON="$PREFIX/bin/python3"
PARSER="$HERE/kmi_btf_snapshot.py"
OUTDIR="/sdcard/Documents/KMI-Guard"

if [[ ! -f "$PARSER" || ! -x "$PYTHON" ]]; then
  echo "BTF parser or Termux Python missing" >&2
  exit 2
fi
if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
  echo "Running kernel does not expose /sys/kernel/btf/vmlinux" >&2
  exit 2
fi
if ! mkdir -p -- "$OUTDIR" || [[ ! -w "$OUTDIR" ]]; then
  echo "Cannot write $OUTDIR as unprivileged Termux user" >&2
  exit 2
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
TARGET="$(mktemp "$OUTDIR/live-kernel-btf-$STAMP-XXXXXXXX.json")"
chmod 600 "$TARGET"
REMOVE_PARTIAL=1
cleanup() { if [[ -n "$REMOVE_PARTIAL" ]]; then rm -f -- "$TARGET"; fi; }
trap cleanup EXIT

# The shell opens TARGET as the regular user; sudo only reads protected
# /sys/kernel/btf/vmlinux. No root-owned file in shared storage.
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  "$PYTHON" "$PARSER" --source /sys/kernel/btf/vmlinux --output - > "$TARGET"
elif command -v sudo >/dev/null 2>&1; then
  sudo "$PYTHON" "$PARSER" --source /sys/kernel/btf/vmlinux --output - > "$TARGET"
else
  echo "BTF source unreadable; Termux sudo not installed" >&2
  exit 2
fi
REMOVE_PARTIAL=
printf 'SAF-accessible live BTF structure snapshot: %s\n' "$TARGET"
