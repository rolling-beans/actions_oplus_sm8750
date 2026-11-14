#!/data/data/com.termux/files/usr/bin/bash
# Read-only comparison of Android BTF and DLKM access as user and root.
# No mount, sysfs writes, flash, insmod, SELinux changes or networking.
set -euo pipefail
: "$PREFIX"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
PY="$PREFIX/bin/python3"
PROBE="$HERE/kmi_probe_android_sources.py"
OUTDIR="/sdcard/Documents/KMI-Guard"
[[ -f "$PROBE" && -x "$PY" ]] || { echo "Probe/Python missing" >&2; exit 2; }
command -v sudo >/dev/null 2>&1 || { echo "sudo unavailable" >&2; exit 2; }
mkdir -p -- "$OUTDIR"
[[ -w "$OUTDIR" ]] || { echo "Termux cannot write SAF Documents folder" >&2; exit 2; }

STAMP="$(date +%Y%m%d-%H%M%S)"
USER_OUT="$(mktemp "$OUTDIR/probe-user-$STAMP-XXXXXXXX.json")"
ROOT_OUT="$(mktemp "$OUTDIR/probe-root-$STAMP-XXXXXXXX.json")"
chmod 600 "$USER_OUT" "$ROOT_OUT" 2>/dev/null || true  # Android emulated storage may not implement chmod.
INCOMPLETE=1
cleanup() {
  if [[ "$INCOMPLETE" == 1 ]]; then
    rm -f -- "$USER_OUT" "$ROOT_OUT"
  fi
}
trap cleanup EXIT
"$PY" "$PROBE" > "$USER_OUT"
# The caller's shell opens the file as the ordinary Termux user.
# Root is used exclusively for read-only inspection.
sudo "$PY" "$PROBE" > "$ROOT_OUT"
INCOMPLETE=0

"$PY" - "$USER_OUT" "$ROOT_OUT" <<'PY'
import json
import sys
regular, elevated = [json.load(open(p)) for p in sys.argv[1:]]
print("=== Runtime kernel and namespaces ===")
print("kernel:", elevated["kernel_release"])
print("unprivileged mount namespace:", regular["mount_ns_self"])
print("root mount namespace:", elevated["mount_ns_self"])
print("init mount namespace:", elevated["mount_ns_init"])
for ref in (regular, elevated):
    print("\n=== euid =", ref["euid"], "===")
    for x in ref["paths"]:
        if x["path"].endswith(("/btf", "/btf/vmlinux", "/system_dlkm", "/system_dlkm/lib/modules", "/system/lib/modules", "/lib/modules")):
            print(x["path"], x["status"],
                  "errno=" + str(x.get("errno", "")),
                  "count=" + str(x.get("entry_count", "")),
                  "magic=" + str(x.get("first_four_bytes_hex", "")))
    print("kernel config:", ref["kernel_config"])
    print("loaded modules of interest:", ref["loaded_module_names_of_interest"])
print("\nUnprivileged report:", sys.argv[1])
print("Root-observed report:", sys.argv[2])
PY
