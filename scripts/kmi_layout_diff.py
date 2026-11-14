#!/usr/bin/env python3
"""Advisory BTF/pahole type-layout diff for Android KMI research.

A layout change is potential ABI risk, NOT a deterministic module load
rejection, much less a guaranteed Android boot failure.
"""
import argparse
import difflib
import hashlib
import json
import re
from pathlib import Path

MONITORED = ("task_struct", "cgroup", "cfs_rq", "rq", "task_group")
BEGIN = re.compile(r"^struct\s+([A-Za-z_]\w*)\s*\{$", re.M)
SIZE = re.compile(r"/\*\s*size:\s*(\d+),")
SENTINELS = ("UNAVAILABLE", "not a KMI pass")


def parse_layouts(content):
    if any(s in content for s in SENTINELS):
        raise ValueError("BTF layout data unavailable")
    found = list(BEGIN.finditer(content))
    result = {}
    for i, match in enumerate(found):
        name = match.group(1)
        if name not in MONITORED:
            continue
        if name in result:
            raise ValueError(f"duplicate type: {name}")
        end = found[i + 1].start() if i + 1 < len(found) else len(content)
        body = content[match.start():end].strip() + "\n"
        sizes = SIZE.findall(body)
        result[name] = {"body": body, "size": int(sizes[-1]) if sizes else None}
    missing = sorted(set(MONITORED) - set(result))
    if missing:
        raise ValueError("missing monitored types: " + ", ".join(missing))
    if any(v["size"] is None for v in result.values()):
        raise ValueError("some monitored type sizes cannot be identified")
    return result


def compare(reference, candidate):
    old = parse_layouts(reference)
    new = parse_layouts(candidate)
    changes = []
    for name in MONITORED:
        before = old[name]["body"]
        after = new[name]["body"]
        if before == after:
            continue
        patch = list(difflib.unified_diff(
            before.splitlines(), after.splitlines(),
            fromfile=f"reference/{name}", tofile=f"candidate/{name}",
            lineterm="", n=3))
        changes.append({
            "type": name, "before_size": old[name]["size"],
            "after_size": new[name]["size"], "unified_diff": patch[:300],
            "diff_truncated": len(patch) > 300,
        })
    return {
        "schema_version": 1, "status": "TYPE_LAYOUT_CHANGED" if changes else "NO_DIFFERENCE",
        "reference_sha256": hashlib.sha256(reference.encode()).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
        "monitored_types": list(MONITORED), "type_changes": changes,
        "guaranteed_module_load_failure": False,
        "guaranteed_android_boot_failure": False,
        "warning": "Advisory type diff only; unchanged CRCs do not prove KMI safety.",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reference", required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--report-json", required=True)
    p.add_argument("--report-md", required=True)
    args = p.parse_args(argv)
    result = {"schema_version": 1, "status": "UNVERIFIED",
              "type_changes": [], "guaranteed_android_boot_failure": False}
    try:
        reference = Path(args.reference).read_text(errors="replace")
        candidate = Path(args.candidate).read_text(errors="replace")
        result = compare(reference, candidate)
    except (OSError, ValueError) as exc:
        result["reason"] = str(exc)
    path = Path(args.report_json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n")
    lines = [
        "## Advisory KMI type-layout comparison", "",
        "**Status: " + result["status"] + "**", "",
        "This does not establish guaranteed Android boot failure.", "",
    ]
    if result["status"] == "UNVERIFIED":
        lines.append("Unverified: " + result["reason"])
    for item in result.get("type_changes", []):
        lines.extend([
            f"### struct {item['type']}",
            f"Size: {item['before_size']} -> {item['after_size']} bytes.",
            "", "~~~diff", *item["unified_diff"], "~~~", "",
        ])
        if item["diff_truncated"]:
            lines.append("Diff truncated after 300 lines.")
    Path(args.report_md).write_text("\n".join(lines) + "\n")
    print(f"Type layout comparison: {result['status']}; changes="
          f"{len(result['type_changes'])}")
    return 0 if result["status"] != "UNVERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
