#!/usr/bin/env python3
"""Advisory comparison of AOSP ABI STG ELF symbol CRC vs vmlinux.symvers.

The STG file is a reference KMI contract, not a report of which modules
must load for Android to boot. CRC differences must never be silently
promoted to guaranteed boot failure.
"""
import argparse
import json
from pathlib import Path
import re

MAX_STG_BYTES = 48 * 1024 * 1024
MAX_SYMVERS_BYTES = 16 * 1024 * 1024
BLOCK = re.compile(r"(?ms)^elf_symbol \{\n(.*?)^\}")
NAME = re.compile(r'(?m)^\s*name:\s*"([^"]+)"\s*$')
CRC = re.compile(r"(?m)^\s*crc:\s*(0x[0-9a-fA-F]+)\s*$")
DEFINED = re.compile(r"(?m)^\s*is_defined:\s*true\s*$")


def classify(name):
    if name.startswith("LZ4_"):
        return "lz4"
    if name.startswith("zstd_"):
        return "zstd"
    if name.startswith(("icc_", "devm_of_icc_", "of_icc_")):
        return "interconnect"
    if name.startswith(("sk_", "tcp_bpf_", "xdp_", "bpf_")):
        return "bpf_socket_xdp"
    return "other"


def parse_stg(text):
    entries = {}
    for match in BLOCK.finditer(text):
        block = match.group(1)
        if not DEFINED.search(block):
            continue
        name = NAME.search(block)
        crc = CRC.search(block)
        if not name or not crc:
            continue
        entries.setdefault(name.group(1), set()).add(int(crc.group(1), 16))
    if not entries:
        raise ValueError("STG contains no defined ELF symbols with CRC")
    return entries


def parse_symvers(text):
    exports = {}
    conflicting = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 4:
            raise ValueError(f"invalid Module.symvers record at line {lineno}")
        crc_text, name, provider = parts[:3]
        if provider != "vmlinux":
            continue
        try:
            crc = int(crc_text, 16)
        except ValueError as exc:
            raise ValueError(f"bad CRC at line {lineno}") from exc
        if name in exports and exports[name] != crc:
            conflicting.append(name)
        exports[name] = crc
    if not exports or conflicting:
        raise ValueError("empty or inconsistent vmlinux export table")
    return exports


def compare(stg_text, symvers_text):
    reference = parse_stg(stg_text)
    candidate = parse_symvers(symvers_text)
    diffs = []
    matching = 0
    ambiguous = []
    for name, candidates in sorted(reference.items()):
        if name not in candidate:
            continue
        if len(candidates) != 1:
            ambiguous.append(name)
            continue
        original = next(iter(candidates))
        compiled = candidate[name]
        if original == compiled:
            matching += 1
        else:
            diffs.append({
                "symbol": name,
                "group": classify(name),
                "reference_crc": f"0x{original:08x}",
                "candidate_crc": f"0x{compiled:08x}",
                "boot_criticality": "UNVERIFIED",
            })
    groups = {}
    for entry in diffs:
        key = entry["group"]
        groups[key] = groups.get(key, 0) + 1
    return {
        "schema_version": 1,
        "status": "STG_CRC_DIFFERENCE" if diffs else (
            "UNVERIFIED" if ambiguous else "NO_CHECKED_CRC_DIFFERENCE"),
        "reference_elf_symbol_count": len(reference),
        "candidate_kernel_export_count": len(candidate),
        "overlap_compared": matching + len(diffs),
        "matched": matching,
        "mismatched": len(diffs),
        "ambiguous_reference_names": sorted(ambiguous),
        "mismatch_groups": dict(sorted(groups.items())),
        "mismatches": diffs,
        "guaranteed_module_load_failure": False,
        "guaranteed_android_boot_failure": False,
        "scope": "STG exported symbol CRC reference vs candidate vmlinux; "
                 "module import and boot policy must be examined separately",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stg", required=True)
    p.add_argument("--symvers", required=True)
    p.add_argument("--report-json", required=True)
    p.add_argument("--report-md", required=True)
    args = p.parse_args(argv)
    try:
        stg = Path(args.stg).read_bytes()
        symvers = Path(args.symvers).read_bytes()
        if len(stg) > MAX_STG_BYTES or len(symvers) > MAX_SYMVERS_BYTES:
            raise ValueError("reference or symbol file exceeds size limit")
        result = compare(stg.decode("utf-8"), symvers.decode("utf-8"))
        status = 0
    except (UnicodeError, OSError, ValueError) as exc:
        result = {"schema_version": 1, "status": "UNVERIFIED",
                  "reason": str(exc),
                  "guaranteed_android_boot_failure": False}
        status = 2
    out = Path(args.report_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    lines = [
        "## Reference KMI STG / built kernel CRC comparison",
        "", "**Status: " + result["status"] + "**", "",
        "CRC changes are advisory until matched to actual module imports;",
        "they do not prove Android boot failure.", "",
    ]
    if result["status"] == "UNVERIFIED":
        lines.append("Unverified: " + result.get("reason", "ambiguous STG data"))
    else:
        lines += [
            f"- Compared: {result['overlap_compared']}",
            f"- CRC matches: {result['matched']}",
            f"- CRC differences: {result['mismatched']}",
            f"- Groups: {result['mismatch_groups']}", "",
            "| Symbol | STG CRC | Kernel CRC |",
            "|---|---|---|",
        ]
        for row in result["mismatches"]:
            lines.append(
                f"| {row['symbol']} | {row['reference_crc']} | "
                f"{row['candidate_crc']} |")
    Path(args.report_md).write_text("\n".join(lines) + "\n")
    print("STG CRC:", result["status"],
          "matched:", result.get("matched", "?"),
          "changed:", result.get("mismatched", "?"))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
