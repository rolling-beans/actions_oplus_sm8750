#!/data/data/com.termux/files/usr/bin/bash
# Read-only capture of the *currently booted* kernel BTF. SAF write as user.
# No flashing, mounts, writes to /sys, insmod, or SELinux policy changes.
set -euo pipefail
: "$PREFIX"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
PYTHON="$PREFIX/bin/python3"
PARSER="$HERE/kmi_btf_snapshot.py"
OUTDIR="${KMI_GUARD_SAF_DIR:-/sdcard/Documents/KMI-Guard}"

if [[ ! -f "$PARSER" || ! -x "$PYTHON" ]]; then
  echo "BTF parser or Termux Python missing" >&2
  exit 2
fi
# Do not test sysfs existence only in the unprivileged namespace:
# sudo may have different mount visibility / credentials. Attempt a
# read-only privileged open if ordinary Termux cannot read it.
if ! mkdir -p -- "$OUTDIR" || [[ ! -w "$OUTDIR" ]]; then
  echo "Cannot write $OUTDIR as unprivileged Termux user" >&2
  exit 2
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
TARGET="$(mktemp "$OUTDIR/live-kernel-btf-$STAMP-XXXXXXXX.json")"
chmod 600 "$TARGET" 2>/dev/null || true  # Android emulated storage may not implement chmod.
REMOVE_PARTIAL=1
cleanup() { if [[ -n "$REMOVE_PARTIAL" ]]; then rm -f -- "$TARGET"; fi; }
trap cleanup EXIT

# The shell opens TARGET as the regular user; sudo only reads protected
# /sys/kernel/btf/vmlinux. No root-owned file in shared storage.
# A PARTIAL capture is useful *evidence* and MUST NOT be deleted merely
# because the Python collector correctly returns nonzero for missing types.
RC=2
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  "$PYTHON" "$PARSER" --source /sys/kernel/btf/vmlinux --output - > "$TARGET" && RC=0 || RC=$?
elif command -v sudo >/dev/null 2>&1; then
  sudo "$PYTHON" "$PARSER" --source /sys/kernel/btf/vmlinux --output - > "$TARGET" && RC=0 || RC=$?
else
  echo "BTF source unreadable; Termux sudo not installed" >&2
  exit 2
fi

# Keep only a well-formed complete or partial JSON snapshot. An empty,
# truncated, or invalid result remains disposable and is cleaned by trap.
if ! "$PYTHON" - "$TARGET" <<'PY'
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text())
    assert data["schema_version"] == 1
    assert data["capture_kind"] == "booted-kernel-btf-sysfs"
    assert data["status"] in ("COMPLETE", "PARTIAL")
    assert isinstance(data["structures"], dict)
    assert isinstance(data["warnings"], list)
except (OSError, KeyError, ValueError, TypeError, AssertionError) as exc:
    print("Unusable BTF JSON: " + str(exc), file=sys.stderr)
    sys.exit(2)
print("Retained BTF snapshot status:", data["status"],
      "structures:", ", ".join(data["structures"]) or "(none)")
for warning in data["warnings"]:
    print("BTF warning:", warning)
PY
then
  exit 2
fi
REMOVE_PARTIAL=
printf 'SAF-accessible live BTF structure snapshot: %s\n' "$TARGET"
if [[ "$RC" != 0 ]]; then
  echo "BTF is partial; JSON was retained for diagnosis (not a KMI PASS)." >&2
fi
exit "$RC"
