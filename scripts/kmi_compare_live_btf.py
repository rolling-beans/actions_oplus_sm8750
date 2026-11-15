#!/usr/bin/env python3
"""Advisory cross-format live BTF vs candidate pahole structure layout audit.

Live BTF snapshot proves the reference type layout was observed on a booted
kernel. The candidate layout is NOT a complete STG representation. Only
unambiguous named, top-level fields and outer structure sizes are compared.
No finding here can establish that Android will certainly fail to boot.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if __package__:
    from . import kmi_layout_diff
else:
    import kmi_layout_diff

LOCATION = re.compile(r"/\*\s*(\d+)(?:\s*:\s*(\d+))?\s+(\d+)\s*\*/")
FIELD = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?::\s*(\d+))?\s*$")


def fields_from_pahole(body):
    """Return named top-level bit offsets only; skip undocumented syntax."""
    fields = {}
    unparsed = []
    for line in body.splitlines():
        if not line.startswith("\t") or line.startswith("\t\t"):
            continue
        if ";" not in line:
            continue
        match = LOCATION.search(line)
        if not match:
            continue
        head = line.split(";", 1)[0].split("__attribute__", 1)[0]
        name = FIELD.search(head)
        if not name:
            unparsed.append(line.strip())
            continue
        key = name.group(1)
        value = (int(match.group(1)) * 8 +
                 (int(match.group(2)) if match.group(2) else 0))
        width = int(name.group(2)) if name.group(2) else 0
        if key in fields and fields[key] != (value, width):
            raise ValueError(f"ambiguous duplicate pahole field {key}")
        fields[key] = (value, width)
    return fields, unparsed


def compare(live, candidate_text):
    if live.get("schema_version") != 1 or live.get("status") not in ("COMPLETE", "PARTIAL"):
        raise ValueError("live BTF evidence invalid or schema unsupported")
    if live.get("capture_kind") != "booted-kernel-btf-sysfs":
        raise ValueError("reference must be captured from running kernel BTF sysfs")
    layouts = live.get("structures", {})
    source = kmi_layout_diff.parse_layouts(candidate_text)
    changes = []
    uncertain = []
    details = {}
    absent = []
    for name in kmi_layout_diff.MONITORED:
        item = layouts.get(name)
        if not item or not isinstance(item.get("fields"), list):
            if live["status"] == "COMPLETE":
                raise ValueError(f"live BTF missing struct {name}")
            absent.append(name)
            uncertain.append(name)
            continue
        size_live = item.get("size_bytes")
        size_candidate = source[name]["size"]
        if not isinstance(size_live, int) or size_live <= 0:
            raise ValueError(f"invalid live size of {name}")
        current = {}
        for field in item["fields"]:
            key = field.get("name")
            if not key:
                continue
            value = (field["bit_offset"], field.get("bitfield_size", 0))
            if key in current and current[key] != value:
                raise ValueError(f"duplicate live BTF field {name}.{key}")
            current[key] = value
        candidate, rejected = fields_from_pahole(source[name]["body"])
        common = sorted(set(current) & set(candidate))
        shifted = [
            {"field": key,
             "live_bit_offset": current[key][0],
             "candidate_bit_offset": candidate[key][0],
             "live_bitfield_size": current[key][1],
             "candidate_bitfield_size": candidate[key][1]}
            for key in common if current[key] != candidate[key]
        ]
        missing_live = sorted(set(candidate) - set(current))
        missing_candidate = sorted(set(current) - set(candidate))
        detail = {
            "size_live": size_live,
            "size_candidate": size_candidate,
            "live_named_fields": len(current),
            "candidate_parsed_fields": len(candidate),
            "compared_fields": len(common),
            "shifted_fields": shifted,
            "missing_from_live": missing_live[:100],
            "missing_from_candidate": missing_candidate[:100],
            "pahole_unparsed_count": len(rejected),
        }
        details[name] = detail
        if size_live != size_candidate or shifted:
            changes.append(name)
        if missing_live or missing_candidate or rejected or len(common) < 5:
            uncertain.append(name)
    if not details:
        raise ValueError("no monitored BTF structures available for comparison")
    partial = live["status"] == "PARTIAL"
    status = (
        "PARTIAL_MONITORED_LAYOUT_DIFFERENCE" if partial and changes else
        "PARTIAL_BTF_COVERAGE" if partial else
        "MONITORED_LAYOUT_DIFFERENCE" if changes else
        "NO_CHECKED_OFFSET_DIFFERENCE" if uncertain else
        "NO_MONITORED_LAYOUT_DIFFERENCE"
    )
    return {
        "schema_version": 1, "status": status,
        "booted_kernel_release": live.get("kernel_release"),
        "live_btf_sha256": live.get("btf_sha256"),
        "candidate_pahole_sha256": hashlib.sha256(candidate_text.encode()).hexdigest(),
        "checked_types": list(details),
        "unverified_types": absent,
        "btf_capture_status": live["status"],
        "btf_warnings": live.get("warnings", []),
        "changed_types": changes,
        "uncertain_types": uncertain,
        "type_details": details,
        "guaranteed_android_boot_failure": False,
        "warning": "Only five monitored structs; no ABI-STG graph or module field-access proof.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-json", required=True)
    parser.add_argument("--candidate-layouts", required=True)
    parser.add_argument("--report-json", required=True)
    parser.add_argument("--report-md", required=True)
    args = parser.parse_args(argv)
    try:
        live = json.loads(Path(args.live_json).read_text())
        cand = Path(args.candidate_layouts).read_text()
        result = compare(live, cand)
        rc = 2 if result["btf_capture_status"] == "PARTIAL" else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"schema_version": 1, "status": "UNVERIFIED", "reason": str(exc),
                  "guaranteed_android_boot_failure": False}
        rc = 2
    out = Path(args.report_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    lines = ["## Booted-kernel BTF vs candidate pahole", "",
             "**Status: " + result["status"] + "**", "",
             "Does not establish guaranteed module rejection or Android boot failure.", ""]
    if result["status"] == "UNVERIFIED":
        lines.append(result["reason"])
    else:
        if result.get("unverified_types"):
            lines.append("Missing in running BTF: " +
                         ", ".join(result["unverified_types"]) + "\n")
        for warning in result.get("btf_warnings", []):
            lines.append("BTF warning: " + warning)
        if result.get("btf_warnings"):
            lines.append("")
        for name in result["checked_types"]:
            rec = result["type_details"][name]
            lines.extend([f"### {name}",
                          f"Size: {rec['size_live']} (booted) vs {rec['size_candidate']} (candidate)",
                          f"Compared fields: {rec['compared_fields']}; "
                          f"shifted: {len(rec['shifted_fields'])}; "
                          f"unmatched: {len(rec['missing_from_live']) + len(rec['missing_from_candidate'])}.", ""])
            for field in rec["shifted_fields"][:20]:
                lines.append("- {field}: bit offset {live_bit_offset} → "
                             "{candidate_bit_offset}, bitfield size "
                             "{live_bitfield_size} → {candidate_bitfield_size}".format(**field))
            if rec["shifted_fields"]:
                lines.append("")
    Path(args.report_md).write_text("\n".join(lines) + "\n")
    print(f"BTF-vs-pahole: {result['status']}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
