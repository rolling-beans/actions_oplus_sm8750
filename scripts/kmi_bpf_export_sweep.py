#!/usr/bin/env python3
"""Compare changed source-STG BPF exports with isolated Kbuild object CRCs.

No device commands, module insertion, Image relink or boot prediction.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
try:
    from .kmi_stg_crc_diff import parse_stg, parse_symvers
except ImportError:
    from kmi_stg_crc_diff import parse_stg, parse_symvers

OBJECTS = {
    "net/core/filter.c": "net/core/.filter.o.cmd",
    "net/core/skmsg.c": "net/core/.skmsg.o.cmd",
    "net/ipv4/tcp_bpf.c": "net/ipv4/.tcp_bpf.o.cmd",
}
EXPORT = re.compile(
    r"\bEXPORT_(?:PER_CPU_)?SYMBOL(?:_GPL|_NS|_NS_GPL)?\s*"
    r"\(\s*([A-Za-z_]\w*)\b"
)
SYMVER = re.compile(r"(?m)^#SYMVER\s+([A-Za-z_]\w*)\s+(0x[0-9a-fA-F]{1,8})\s*$")
MAX_BYTES = 48 * 1024 * 1024
BPF_PREFIXES = ("bpf_", "sk_", "tcp_bpf_", "xdp_")


def read(path):
    p = Path(path)
    if p.stat().st_size > MAX_BYTES:
        raise ValueError("file too large: " + p.name)
    return p.read_bytes()


def extract_cmd_symbols(text):
    result = defaultdict(set)
    for match in SYMVER.finditer(text):
        result[match.group(1)].add(int(match.group(2), 16))
    return dict(result)


def source_exporters(root):
    owners = defaultdict(list)
    for src, object_cmd in OBJECTS.items():
        data = read(Path(root) / src).decode("utf-8")
        for name in sorted(set(EXPORT.findall(data))):
            owners[name].append(object_cmd)
    return dict(owners)


def evaluate(stg, symvers, source, control, variant):
    reference = parse_stg(stg)
    compiled = parse_symvers(symvers)
    owners = source_exporters(source)
    cmd_versions, hashes = {}, {}
    for label, base in (("control", control), ("variant", variant)):
        cmd_versions[label] = {}
        for obj in OBJECTS.values():
            path = Path(base) / obj
            if path.is_file():
                data = read(path)
                cmd_versions[label][obj] = extract_cmd_symbols(data.decode())
                hashes[label + "/" + obj] = hashlib.sha256(data).hexdigest()
    results = []
    for name in sorted(reference.keys() & compiled.keys()):
        if not name.startswith(BPF_PREFIXES) or len(reference[name]) != 1:
            continue
        expected_stg = next(iter(reference[name]))
        kernel = compiled[name]
        if expected_stg == kernel:
            continue
        row = {
            "symbol": name,
            "reference_stg_crc": f"0x{expected_stg:08x}",
            "compiled_kernel_crc": f"0x{kernel:08x}",
            "source_object": None, "control_crc": None,
            "variant_crc": None, "status": "UNVERIFIED",
        }
        mapping = owners.get(name, [])
        if len(mapping) != 1:
            row["reason"] = "missing or ambiguous exporter mapping"
        else:
            obj = mapping[0]
            row["source_object"] = obj
            base_values = cmd_versions["control"].get(obj, {}).get(name, set())
            alt_values = cmd_versions["variant"].get(obj, {}).get(name, set())
            if len(base_values) != 1 or len(alt_values) != 1:
                row["reason"] = "missing or ambiguous control/variant SYMVER"
            else:
                a, b = next(iter(base_values)), next(iter(alt_values))
                row["control_crc"] = f"0x{a:08x}"
                row["variant_crc"] = f"0x{b:08x}"
                if a != kernel:
                    row["status"] = "BASELINE_NOT_REPRODUCED"
                elif b == expected_stg:
                    row["status"] = "RESTORED_TO_STG"
                elif b == kernel:
                    row["status"] = "UNCHANGED_CRC"
                else:
                    row["status"] = "CHANGED_NOT_RESTORED"
        results.append(row)
    statuses = dict(sorted(Counter(x["status"] for x in results).items()))
    uncertain = any(x["status"] in ("UNVERIFIED", "BASELINE_NOT_REPRODUCED")
                    for x in results)
    return {
        "schema_version": 1,
        "status": "PARTIAL" if uncertain else "COMPLETE",
        "scope": "Changed BPF/socket/XDP reference STG exports only; object-level "
                 "genksyms, not module-load or Android boot safety",
        "changed_bpf_export_count": len(results),
        "status_counts": statuses,
        "input_object_cmd_sha256": hashes,
        "results": results,
        "complete_variant_image_built": False,
        "guaranteed_android_boot_safety": False,
        "device_modified": False,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for option in ("stg", "symvers", "source", "control", "variant",
                   "report-json", "report-md"):
        p.add_argument("--" + option, required=True)
    opts = p.parse_args(argv)
    try:
        report = evaluate(
            read(opts.stg).decode("utf-8"), read(opts.symvers).decode("utf-8"),
            opts.source, opts.control, opts.variant)
        rc = 0 if report["status"] == "COMPLETE" else 2
    except (OSError, UnicodeError, ValueError) as exc:
        report = {"schema_version": 1, "status": "UNVERIFIED",
                  "reason": str(exc), "device_modified": False,
                  "guaranteed_android_boot_safety": False}
        rc = 2
    target = Path(opts.report_json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "## BPF-related exported symbol CRC sweep", "",
        "**Status: " + report["status"] + "**", "",
        "Object-level genksyms only, not proof of boot compatibility.", "",
    ]
    if "results" in report:
        lines.extend([
            f"Changed BPF exports examined: {report['changed_bpf_export_count']}",
            f"Outcomes: {report['status_counts']}", "",
            "| Symbol | Built kernel | Control | Parser off | Reference | Verdict |",
            "|---|---|---|---|---|---|",
        ])
        for row in report["results"]:
            lines.append("| {symbol} | {compiled_kernel_crc} | {control_crc} "
                         "| {variant_crc} | {reference_stg_crc} | {status} |"
                         .format(**row))
    else:
        lines.append(report.get("reason", "evidence unavailable"))
    Path(opts.report_md).write_text("\n".join(lines) + "\n")
    print("BPF CRC sweep", report["status"],
          report.get("status_counts", report.get("reason", "")))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
