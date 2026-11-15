#!/usr/bin/env python3
"""Read-only Android BTF and DLKM mount source visibility probe.

Run as ordinary Termux and with sudo. Reports evidence as JSON to stdout.
Only reads from /proc, /sys, and files; does not alter the device.
"""
import errno
import gzip
import json
import os
from pathlib import Path
import stat
import sys

PATHS = (
    "/sys/kernel/btf", "/sys/kernel/btf/vmlinux",
    "/proc/1/root/sys/kernel/btf", "/proc/1/root/sys/kernel/btf/vmlinux",
    "/system_dlkm", "/system_dlkm/lib/modules", "/system/lib/modules",
    "/proc/1/root/system_dlkm/lib/modules",
    "/odm/lib/modules", "/odm_dlkm/lib/modules",
    "/proc/1/root/odm/lib/modules",
    "/lib/modules", "/proc/1/root/lib/modules",
)
FLAGS = (
    "CONFIG_DEBUG_INFO_BTF", "CONFIG_DEBUG_INFO_BTF_MODULES",
    "CONFIG_BPF_SYSCALL", "CONFIG_BPF", "CONFIG_SYSFS",
    "CONFIG_MODULES", "CONFIG_RFKILL", "CONFIG_CRYPTO_LIB_ARC4",
    "CONFIG_MODVERSIONS",
)


def state(path):
    result = {"path": path}
    try:
        info = os.stat(path)
    except OSError as exc:
        result["status"] = ("NOT_FOUND" if exc.errno == errno.ENOENT else
                            "ACCESS_DENIED" if exc.errno in (errno.EACCES, errno.EPERM)
                            else "ERROR")
        result["errno"] = exc.errno
        return result
    result.update({"status": "EXISTS", "mode": stat.filemode(info.st_mode),
                   "size_bytes": info.st_size})
    if stat.S_ISDIR(info.st_mode):
        try:
            entries = os.listdir(path)
            result["entry_count"] = len(entries)
            if path.endswith("/btf"):
                result["sample_entries"] = sorted(entries)[:20]
            if path.endswith("/modules"):
                result["module_count"] = sum(x.endswith((".ko", ".ko.gz", ".ko.xz", ".ko.zst"))
                                             for x in entries)
        except OSError as exc:
            result["listing_errno"] = exc.errno
    if stat.S_ISREG(info.st_mode) and path.endswith("/btf/vmlinux"):
        try:
            with open(path, "rb") as f:
                result["first_four_bytes_hex"] = f.read(4).hex()
        except OSError as exc:
            result["read_errno"] = exc.errno
    return result


def mount_summary(path):
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as exc:
        return [{"read_errno": exc.errno}]
    found = []
    for line in lines:
        if " - " not in line:
            continue
        cols = line.split()
        mountpoint = cols[4] if len(cols) > 4 else ""
        fstype = line.split(" - ", 1)[1].split()[0]
        if (fstype == "sysfs" or any(word in mountpoint
            for word in ("system_dlkm", "vendor_dlkm", "odm_dlkm", "/sys", "/system"))):
            found.append({"mountpoint": mountpoint, "fstype": fstype})
    return found[:50]


def config_flags():
    try:
        with gzip.open("/proc/config.gz", "rt", encoding="utf-8", errors="replace") as f:
            conf = f.read(4 * 1024 * 1024)
    except (OSError, EOFError) as exc:
        return {"status": "UNAVAILABLE", "reason": str(exc)}
    result = {}
    for line in conf.splitlines():
        for flag in FLAGS:
            if line.startswith(flag + "="):
                result[flag] = line.split("=", 1)[1]
            elif line == "# " + flag + " is not set":
                result[flag] = "n"
    return {"status": "READ", "values": result}


def namespace(pid):
    try:
        return os.readlink("/proc/" + pid + "/ns/mnt")
    except OSError as exc:
        return "UNAVAILABLE errno=" + str(exc.errno)


def collect():
    try:
        lines = Path("/proc/modules").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    return {
        "schema_version": 1,
        "probe_kind": "android-readonly-btf-dlkm-visibility",
        "euid": os.geteuid(),
        "kernel_release": os.uname().release,
        "mount_ns_self": namespace("self"),
        "mount_ns_init": namespace("1"),
        "paths": [state(path) for path in PATHS],
        "mounts_self": mount_summary("/proc/self/mountinfo"),
        "mounts_init": mount_summary("/proc/1/mountinfo"),
        "kernel_config": config_flags(),
        "loaded_module_names_of_interest": [
            line.split()[0] for line in lines if line.split()
            and any(s in line.split()[0].lower()
                    for s in ("rfkill", "arc4", "btpower", "cfg80211", "mac80211"))
        ],
        "notes": "Visibility only; a missing path does not prove a module partition does not exist.",
    }


if __name__ == "__main__":
    json.dump(collect(), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
