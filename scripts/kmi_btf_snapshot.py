#!/usr/bin/env python3
"""Capture a conservative BTF structure-layout snapshot from a *running* kernel.

Standard library only; read-only. Emits no BTF binary, code or addresses.
Only selected named structures and field offsets/types are written to JSON.
A BTF snapshot is ABI *evidence*, not a proof of kernel or module bootability.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

MONITORED = ("task_struct", "cgroup", "cfs_rq", "rq", "task_group")
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_TYPES = 1000000
# BTF type kinds defined by Documentation/bpf/btf.rst
EXTRA_PER_ELEMENT = {
    1: (4, 0),  # INT: 4-byte encoding
    2: (0, 0),  # PTR
    3: (12, 0),  # ARRAY
    4: (0, 12),  # STRUCT
    5: (0, 12),  # UNION
    6: (0, 8),  # ENUM
    7: (0, 0),  # FWD
    8: (0, 0),  # TYPEDEF
    9: (0, 0),  # VOLATILE
    10: (0, 0),  # CONST
    11: (0, 0),  # RESTRICT
    12: (0, 0),  # FUNC
    13: (0, 8),  # FUNC_PROTO
    14: (4, 0),  # VAR
    15: (0, 12),  # DATASEC
    16: (0, 0),  # FLOAT
    17: (4, 0),  # DECL_TAG
    18: (0, 0),  # TYPE_TAG
    19: (0, 12),  # ENUM64
}
KIND_LABEL = {1: "int", 2: "ptr", 3: "array", 4: "struct", 5: "union",
              6: "enum", 7: "fwd", 8: "typedef", 9: "volatile", 10: "const",
              11: "restrict", 12: "func", 13: "func_proto", 14: "var",
              15: "datasec", 16: "float", 17: "decl_tag", 18: "type_tag",
              19: "enum64"}


class BTFError(ValueError):
    pass


class BTF:
    def __init__(self, data):
        if len(data) < 24:
            raise BTFError("BTF header truncated")
        magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = (
            struct.unpack_from("<HBBIIIII", data, 0))
        if magic != 0xeb9f or version != 1 or flags != 0 or hdr_len < 24:
            raise BTFError("not a supported little-endian BTF v1 header")
        if hdr_len > len(data):
            raise BTFError("BTF header extends beyond file")
        def checked_section(offset, size):
            if offset > len(data) - hdr_len or size > len(data) - hdr_len - offset:
                raise BTFError("BTF section extends beyond file")
            return data[hdr_len + offset:hdr_len + offset + size]

        typedefs = checked_section(type_off, type_len)
        self.strings = checked_section(str_off, str_len)
        if not self.strings or self.strings[0] != 0:
            raise BTFError("invalid BTF string section")
        self.types = [None]  # type id 0 is void.
        pos = 0
        while pos < len(typedefs):
            if len(self.types) >= MAX_TYPES or len(typedefs) - pos < 12:
                raise BTFError("too many types or truncated BTF record")
            name_off, info, size_type = struct.unpack_from("<III", typedefs, pos)
            kind = (info >> 24) & 0x1f
            vlen = info & 0xffff
            kind_flag = bool(info & 0x80000000)
            if kind not in EXTRA_PER_ELEMENT:
                raise BTFError(f"unsupported BTF kind {kind}")
            fixed, each = EXTRA_PER_ELEMENT[kind]
            extra = fixed + vlen * each
            if len(typedefs) - pos - 12 < extra:
                raise BTFError(f"truncated extra data in BTF kind {kind}")
            rest = typedefs[pos + 12:pos + 12 + extra]
            rec = {
                "name": self.string(name_off),
                "kind": kind,
                "size_type": size_type,
                "flag": kind_flag,
                "data": rest,
            }
            if kind in (4, 5):
                members = []
                for i in range(vlen):
                    name_id, typ, bitoff = struct.unpack_from("<III", rest, i * 12)
                    member_offset = (bitoff & 0xffffff) if kind_flag else bitoff
                    width = (bitoff >> 24) if kind_flag else 0
                    members.append((self.string(name_id), typ, member_offset, width))
                rec["members"] = members
            elif kind == 3:
                rec["array"] = struct.unpack_from("<III", rest)
            self.types.append(rec)
            pos += 12 + extra
        if pos != len(typedefs):
            raise BTFError("BTF type data not fully consumed")

    def string(self, offset):
        if offset >= len(self.strings):
            raise BTFError("BTF string reference out of bounds")
        end = self.strings.find(b"\0", offset)
        if end < 0:
            raise BTFError("unterminated BTF string")
        return self.strings[offset:end].decode("utf-8", "replace")

    def type_name(self, type_id, depth=0, path=()):
        if type_id == 0:
            return "void"
        if type_id >= len(self.types):
            raise BTFError(f"unknown BTF type ID {type_id}")
        if depth > 12 or type_id in path:
            return "<recursive>"
        rec = self.types[type_id]
        kind = rec["kind"]
        name = rec["name"]
        target = rec["size_type"]
        trail = path + (type_id,)
        if kind == 1:
            return f"int {name}({target})"
        if kind in (4, 5):
            return (KIND_LABEL[kind] + " " + (name or "<anonymous>"))
        if kind in (6, 19):
            return f"enum {name}({target})"
        if kind in (7, 16):
            return f"{KIND_LABEL[kind]} {name}({target})"
        if kind == 2:
            return self.type_name(target, depth + 1, trail) + " *"
        if kind == 3:
            elem, _, count = rec["array"]
            return self.type_name(elem, depth + 1, trail) + f"[{count}]"
        if kind == 8:
            return f"typedef {name}<{self.type_name(target, depth + 1, trail)}>"
        if kind in (9, 10, 11, 18):
            return KIND_LABEL[kind] + "<" + self.type_name(target, depth + 1, trail) + ">"
        if kind == 12:
            return f"func {name}<{self.type_name(target, depth + 1, trail)}>"
        if kind == 13:
            return f"func_proto({target})"
        return f"{KIND_LABEL[kind]} {name}"

    def snapshot(self):
        by_name = {}
        for rec in self.types[1:]:
            if rec["kind"] == 4 and rec["name"] in MONITORED:
                by_name.setdefault(rec["name"], []).append(rec)
        result = {}
        warnings = []
        for name in MONITORED:
            matches = by_name.get(name, [])
            if len(matches) != 1:
                warnings.append(f"{name}: expected 1 complete struct, got {len(matches)}")
                continue
            rec = matches[0]
            fields = []
            for field_name, type_id, bit_offset, bitfield_size in rec["members"]:
                fields.append({
                    "name": field_name,
                    "bit_offset": bit_offset,
                    "bitfield_size": bitfield_size,
                    "type": self.type_name(type_id),
                })
            result[name] = {
                "size_bytes": rec["size_type"],
                "member_count": len(fields),
                "fields": fields,
            }
        return result, warnings


def capture_file(source):
    path = Path(source)
    if not path.is_file():
        raise BTFError(f"BTF source not a regular readable file: {path}")
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise BTFError("BTF file exceeds limit")
    data = path.read_bytes()
    if len(data) > MAX_SOURCE_BYTES:
        raise BTFError("BTF data exceeds limit")
    btf = BTF(data)
    layouts, warnings = btf.snapshot()
    return {
        "schema_version": 1,
        "capture_kind": "booted-kernel-btf-sysfs" if str(path) == "/sys/kernel/btf/vmlinux" else "raw-btf",
        "kernel_release": os.uname().release,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "btf_sha256": hashlib.sha256(data).hexdigest(),
        "btf_size_bytes": len(data),
        "btf_type_count": len(btf.types) - 1,
        "monitored_types": list(MONITORED),
        "status": "COMPLETE" if not warnings else "PARTIAL",
        "structures": layouts,
        "warnings": warnings,
        "notes": "BTF layout observation only; never sufficient proof of KMI compatibility or bootability.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="/sys/kernel/btf/vmlinux")
    parser.add_argument("--output", required=True, help="JSON output file or '-' for stdout")
    args = parser.parse_args(argv)
    try:
        result = capture_file(args.source)
        content = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.output == "-":
            sys.stdout.write(content)
        else:
            dest = Path(args.output)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)
        print(f"BTF structures: {len(result['structures'])}/{len(MONITORED)}; "
              f"types: {result['btf_type_count']}; "
              f"status: {result['status']}", file=sys.stderr)
        for warning in result["warnings"]:
            print("BTF type warning:", warning, file=sys.stderr)
        return 0 if result["status"] == "COMPLETE" else 2
    except (OSError, BTFError, struct.error) as exc:
        print(f"BTF SNAPSHOT ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
