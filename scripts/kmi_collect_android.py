#!/usr/bin/env python3
"""Read-only OnePlus/Android vendor kernel-module metadata collector.

Requires Python 3 (Termux works). No .ko bytes are written to the output.
No flash/partition changes, module insertion or network requests.
Supports ELF64 little endian (arm64), basic and extended MODVERSIONS.
For .ko.zst files, the 'zstd' executable must be available.
"""
import argparse
import gzip
import hashlib
import json
import lzma
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

SUFFIXES = (".ko", ".ko.gz", ".ko.xz", ".ko.zst")
DEFAULT_SOURCES = {
    "vendor": "/vendor/lib/modules",
    "odm": "/odm/lib/modules",
    "vendor_boot": "/lib/modules",
}


def module_key(path):
    base = Path(path).name
    for suffix in SUFFIXES:
        if base.endswith(suffix):
            base = base[:-len(suffix)]
            break
    return base.replace("-", "_")


def prop(name):
    try:
        out = subprocess.run(["getprop", name], text=True,
                             capture_output=True, timeout=8, check=False)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def get_elf_bytes(path):
    raw = path.read_bytes()
    if path.name.endswith(".ko.zst"):
        zstd = shutil.which("zstd")
        if not zstd:
            raise ValueError("zstd executable unavailable (cannot read .ko.zst)")
        out = subprocess.run([zstd, "-dc", "--", str(path)],
                             capture_output=True, timeout=40, check=False)
        if out.returncode != 0:
            raise ValueError("zstd decompression failed")
        return out.stdout
    if path.name.endswith(".ko.xz"):
        return lzma.decompress(raw)
    if path.name.endswith(".ko.gz"):
        return gzip.decompress(raw)
    return raw


def elf_sections(data):
    if (len(data) < 64 or data[:4] != b"\x7fELF" or
        data[4] != 2 or data[5] != 1):
        raise ValueError("not a 64-bit little-endian ELF")
    offset = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, names_idx = struct.unpack_from("<HHH", data, 58)
    if entsize < 64 or count == 0 or names_idx >= count:
        raise ValueError("invalid ELF section header table")
    if offset > len(data) or count > (len(data) - offset) // entsize:
        raise ValueError("ELF section table extends beyond file")
    sections = []
    for i in range(count):
        base = offset + i * entsize
        nameid, _, _, _, pos, size, _, _, _, stride = struct.unpack_from(
            "<IIQQQQIIQQ", data, base)
        if pos > len(data) or size > len(data) - pos:
            raise ValueError("ELF section data extends beyond file")
        sections.append((nameid, data[pos:pos + size], stride))
    names = sections[names_idx][1]

    def name_at(index):
        if index >= len(names):
            return ""
        end = names.find(b"\0", index)
        if end < 0:
            return ""
        return names[index:end].decode("ascii", "replace")

    return {name_at(i): (blob, stride) for i, blob, stride in sections}


def parse_module(path):
    data = elf_sections(get_elf_bytes(path))
    modinfo = data.get(".modinfo", (b"", 0))[0]
    vermagic = ""
    for record in modinfo.split(b"\0"):
        if record.startswith(b"vermagic="):
            vermagic = record[len(b"vermagic="):].decode("utf-8", "replace")
    required = {}
    # Modern kernels may contain both layouts. Prefer the explicitly
    # separated extended form when it is internally consistent.
    if "__version_ext_names" in data and "__version_ext_crcs" in data:
        names = [n.decode("utf-8", "replace") for n in
                 data["__version_ext_names"][0].split(b"\0") if n]
        crc_bytes = data["__version_ext_crcs"][0]
        if len(crc_bytes) != 4 * len(names):
            raise ValueError("extended MODVERSIONS names/CRC count mismatch")
        for i, name in enumerate(names):
            required[name] = f"0x{struct.unpack_from('<I', crc_bytes, 4 * i)[0]:08x}"
    elif "__versions" in data:
        blob, elf_stride = data["__versions"]
        # The record's name[] size varies across kernel versions.
        # Linux 6.6/6.17 commonly uses 64-byte records (8+56), not 72.
        symbol_pat = re.compile(rb"[A-Za-z_][A-Za-z0-9_.$]*\Z")
        candidates = [elf_stride] if elf_stride else [64, 72, 128]
        for stride in candidates:
            if stride < 16 or len(blob) % stride:
                continue
            parsed = {}
            for offset in range(0, len(blob), stride):
                crc = struct.unpack_from("<Q", blob, offset)[0] & 0xffffffff
                record = blob[offset + 8:offset + stride]
                name = record.split(b"\0", 1)[0]
                if not symbol_pat.fullmatch(name):
                    break
                parsed[name.decode("ascii")] = f"0x{crc:08x}"
            else:
                required = parsed
                break
        if not required:
            raise ValueError("unsupported __versions entry size or names")
    else:
        raise ValueError("no MODVERSIONS section in module")
    if not required:
        raise ValueError("empty MODVERSIONS section")
    return required, vermagic


def collect(args):
    sources = []
    modules = []
    load_lists = []
    all_boot_names = set()
    present = []
    for label, source in args.root:
        root = Path(source).resolve()
        if not root.is_dir():
            sources.append({"label": label, "module_count": 0, "available": False})
            continue
        present.append((label, root))
        for load in sorted(root.glob("modules.load*")):
            if not load.is_file() or load.is_symlink():
                continue
            try:
                content = load.read_text(errors="replace")
            except OSError as exc:
                load_lists.append({"source": label, "file": load.name,
                                   "read_error": str(exc)})
                continue
            entries = [line.split("#", 1)[0].strip().split()[0]
                       for line in content.splitlines()
                       if line.split("#", 1)[0].strip()]
            all_boot_names.update(module_key(x) for x in entries)
            load_lists.append({
                "source": label, "file": load.name,
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "entries": entries,
            })
    for label, root in present:
        count = 0
        for base, _, files in os.walk(root, followlinks=False):
            for file in sorted(files):
                if not file.endswith(SUFFIXES):
                    continue
                path = Path(base) / file
                if path.is_symlink():
                    continue
                count += 1
                error, required, magic = "", {}, ""
                try:
                    required, magic = parse_module(path)
                except (OSError, ValueError, lzma.LZMAError,
                        gzip.BadGzipFile, subprocess.TimeoutExpired) as exc:
                    error = str(exc)
                try:
                    checksum = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    checksum = ""
                    error = (error + "; unreadable for checksum").strip("; ")
                modules.append({
                    "path": f"{label}/{path.relative_to(root).as_posix()}",
                    "module_sha256": checksum,
                    "boot_requested": module_key(path.name) in all_boot_names,
                    "boot_critical_reviewed": False,
                    "vermagic": magic,
                    "required_crcs": dict(sorted(required.items())),
                    "exported_crcs": {},  # Verified on a Linux host separately.
                    "capture_error": error,
                })
        sources.append({"label": label, "module_count": count, "available": True})
    manifest = {
        "schema_version": 1,
        "collector": "termux-elf-readonly-v1",
        "device_build_fingerprint": prop("ro.build.fingerprint") or "UNVERIFIED",
        "vendor_build_fingerprint": prop("ro.vendor.build.fingerprint"),
        "kernel_release": platform.uname().release,
        "sources": sources,
        "load_lists": load_lists,
        "modules": modules,
    }
    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    bad = [m["path"] for m in modules if m["capture_error"]]
    print(f"Sources: {len(sources)}, modules: {len(modules)}, "
          f"unverifiable: {len(bad)}, load-lists: {len(load_lists)}")
    print(f"Metadata only: {output}")
    if bad:
        print("Some modules could not be decoded; manifest must remain UNVERIFIED.")
    return 0 if modules else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", metavar="LABEL=PATH",
                        help="explicit module source; repeat as needed")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    selected_roots = args.root or [f"{label}={path}" for label, path in DEFAULT_SOURCES.items()]
    args.root = []
    for arg in selected_roots:
        if "=" not in arg:
            parser.error("--root must have LABEL=PATH form")
        label, path = arg.split("=", 1)
        if not re.fullmatch("[A-Za-z0-9_.-]+", label):
            parser.error("invalid root label")
        if label in [x[0] for x in args.root]:
            parser.error("duplicate root label")
        args.root.append((label, path))
    return collect(args)


if __name__ == "__main__":
    sys.exit(main())
