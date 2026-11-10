#!/usr/bin/env python3
"""Conservative Android GKI vendor module KMI check.

A proven MODVERSIONS mismatch predicts rejection of a *module* by ordinary
module loading; it does not prove Android will fail to boot. No vendor
manifest means UNVERIFIED, never PASS. Standard-library Python only.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

CRC_LINE = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+(\S+)\s*$")
CONFIG_LINE = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.*)$")
KNOWN_RISK_CONFIGS = ("CFS_BANDWIDTH", "CGROUP_PIDS")
MODULE_EXTENSIONS = (".ko", ".ko.gz", ".ko.xz", ".ko.zst")


def symbol_table(path):
    """Only vmlinux exports; other exports can belong to separate .ko files."""
    result = {}
    if not path or not Path(path).is_file():
        return result
    for line in Path(path).read_text(errors="replace").splitlines():
        columns = line.split()
        if len(columns) < 4 or columns[2] != "vmlinux":
            continue
        try:
            result[columns[1]] = f"0x{int(columns[0], 16):08x}"
        except ValueError:
            continue
    return result


def config_table(path):
    result = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        match = CONFIG_LINE.fullmatch(line)
        if match:
            result[match[1]] = match[2]
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            result[line[len("# CONFIG_"):-len(" is not set")]] = "n"
    return result


def crc_equal(a, b):
    try:
        return int(a, 16) == int(b, 16)
    except (ValueError, TypeError):
        return False


def command(argv):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as error:
        return "", str(error)
    return proc.stdout, ("" if proc.returncode == 0
                         else proc.stderr.strip() or f"exit {proc.returncode}")


def module_key(name):
    """Normalize compression suffix and modprobe-equivalent '-' vs '_'."""
    base = Path(name).name
    for ext in MODULE_EXTENSIONS:
        if base.endswith(ext):
            base = base[:-len(ext)]
            break
    return base.replace("-", "_")


def module_names(paths):
    names = set()
    for path in paths:
        for line in Path(path).read_text(errors="replace").splitlines():
            words = line.split("#", 1)[0].strip().split()
            if words:
                names.add(module_key(words[0]))
    return names


def capture(args):
    roots = [Path(p) for p in args.modules_root]
    if any(not root.is_dir() for root in roots):
        raise ValueError("one or more module roots do not exist: " + str(roots))
    if len({str(p.resolve()) for p in roots}) != len(roots):
        raise ValueError("duplicate module roots")
    startup = module_names(args.modules_load)
    critical = module_names(args.critical_list)
    entries = []
    for root in roots:
      for path in sorted(root.rglob("*")):
        if not path.is_file() or not path.name.endswith(MODULE_EXTENSIONS):
            continue
        output, err = command([args.modprobe, "--show-modversions", str(path)])
        required = {}
        for line in output.splitlines():
            match = CRC_LINE.fullmatch(line)
            if match:
                required[match[2]] = f"0x{int(match[1], 16):08x}"
        vermagic, ver_error = command([args.modinfo, "-F", "vermagic", str(path)])
        entries.append({
            "path": str(root.name + "/" + str(path.relative_to(root))),
            "module_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "boot_requested": module_key(path.name) in startup,
            "boot_critical_reviewed": module_key(path.name) in critical,
            "vermagic": vermagic.strip(),
            "required_crcs": dict(sorted(required.items())),
            "capture_error": err or ver_error or ("no modversions found" if not required else ""),
        })
    result = {
        "schema_version": 1,
        "device_build_fingerprint": args.fingerprint or "UNVERIFIED",
        "modules": entries,
    }
    dest = Path(args.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    failed = sum(bool(x["capture_error"]) for x in entries)
    print(f"Captured {len(entries)} .ko modules, {failed} unverifiable")
    return 0 if entries else 2


def audit(args):
    if not Path(args.symvers).is_file() or not Path(args.config).is_file():
        raise ValueError("both candidate vmlinux.symvers and .config are required")
    exports = symbol_table(args.symvers)
    cfg = config_table(args.config)
    if not exports:
        raise ValueError("no vmlinux exports in candidate symvers")
    if cfg.get("MODVERSIONS") != "y":
        raise ValueError("CONFIG_MODVERSIONS=y is required for CRC checks")
    baseline = symbol_table(args.baseline_symvers) if args.baseline_symvers else {}
    report = {
        "schema_version": 1,
        "status": "UNVERIFIED",
        "candidate_export_count": len(exports),
        "vendor_module_count": 0,
        "checked_import_count": 0,
        "definite_module_rejections": [],
        "potential_risks": [],
        "unverified": [],
        "notes": [
            "Module rejection by the versioned loader does NOT prove an Android bootloop.",
            "Matching CRCs do NOT prove complete ABI/runtime compatibility."
        ],
    }
    for symbol in KNOWN_RISK_CONFIGS:
        if cfg.get(symbol) == "y":
            report["potential_risks"].append({
                "kind": "KNOWN_KMI_HAZARD", "config": "CONFIG_" + symbol,
                "reason": "Known OnePlus GKI ABI risk; needs vendor module review",
            })
    if args.baseline_symvers:
        if not baseline:
            report["unverified"].append("baseline symvers missing/invalid")
        else:
            changed = [n for n, value in baseline.items()
                       if n in exports and not crc_equal(value, exports[n])]
            removed = [n for n in baseline if n not in exports]
            report["baseline_change_counts"] = {"changed": len(changed), "removed": len(removed)}
            report["baseline_crc_changed"] = changed[:100]
            report["baseline_exports_removed"] = removed[:100]
            if changed or removed:
                report["potential_risks"].append({
                    "kind": "BASELINE_EXPORT_CHANGE",
                    "reason": "Affected consumers unknown until vendor imports are inspected",
                    "changed": len(changed), "removed": len(removed),
                })
    if args.vendor_manifest and Path(args.vendor_manifest).is_file():
        manifest = json.loads(Path(args.vendor_manifest).read_text())
        if manifest.get("schema_version") != 1 or not isinstance(manifest.get("modules"), list):
            raise ValueError("invalid vendor manifest schema")
        if not manifest["modules"]:
            report["unverified"].append("vendor manifest has no modules")
        if manifest.get("device_build_fingerprint") in ("", None, "UNVERIFIED"):
            report["unverified"].append("vendor build fingerprint not verified")
        for module in manifest["modules"]:
            report["vendor_module_count"] += 1
            path = module.get("path", "<unknown>")
            requirements = module.get("required_crcs", {})
            if not isinstance(requirements, dict) or not requirements or module.get("capture_error"):
                report["unverified"].append(
                    f"{path}: module imports cannot be verified: {module.get('capture_error', '')}"
                )
                continue
            for name, expected in requirements.items():
                # A missing non-vmlinux symbol might be provided by another .ko.
                # Only baseline-known vmlinux exports and the special module_layout
                # are definite missing-export errors.
                if name not in exports and name not in baseline and name != "module_layout":
                    report["unverified"].append(f"{path}: provider unknown for {name}")
                    continue
                report["checked_import_count"] += 1
                actual = exports.get(name)
                if actual is None or not crc_equal(expected, actual):
                    report["definite_module_rejections"].append({
                        "module": path, "symbol": name,
                        "expected_crc": expected, "kernel_crc": actual,
                        "boot_requested": bool(module.get("boot_requested")),
                        "boot_critical_reviewed": bool(module.get("boot_critical_reviewed")),
                        "reason": ("required kernel export missing" if actual is None
                                   else "MODVERSIONS CRC mismatch"),
                    })
    else:
        report["unverified"].append(
            "No device vendor-module manifest: module compatibility NOT verified"
        )
    if args.baseline_layouts and args.candidate_layouts:
        reference = Path(args.baseline_layouts).read_text(errors="replace")
        candidate = Path(args.candidate_layouts).read_text(errors="replace")
        if reference != candidate:
            report["potential_risks"].append({
                "kind": "MONITORED_TYPE_LAYOUT_DIFF",
                "reason": "Selected structure layouts differ; not proof of module rejection",
            })
    elif args.baseline_layouts or args.candidate_layouts:
        report["unverified"].append("layout comparison lacks approved baseline/candidate")
    if report["definite_module_rejections"]:
        report["status"] = "MODULE_LOAD_REJECTION"
    elif not report["unverified"]:
        report["status"] = "NO_CHECKED_MISMATCH"
    dest = Path(args.report_json)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    lines = [
        "## KMI Guard — vendor module compatibility", "",
        "**Status: " + report["status"] + "**", "",
        "A mismatch below predicts that the normal MODVERSIONS loader rejects a vendor",
        "module; this is not a proof that Android itself cannot boot.", "",
        "- Candidate kernel exports: " + str(len(exports)),
        "- Vendor modules in manifest: " + str(report["vendor_module_count"]),
        "- Imports compared against vmlinux: " + str(report["checked_import_count"]),
        "- Certain module-load rejections: " + str(len(report["definite_module_rejections"])),
        "- Potential risk findings: " + str(len(report["potential_risks"])),
        "- Unverified entries: " + str(len(report["unverified"])), "",
    ]
    if report["definite_module_rejections"]:
        lines += ["### Deterministic module-load failures", ""]
        for item in report["definite_module_rejections"][:50]:
            lines.append("- {module}: {symbol}: {reason}; expected={expected_crc}, "
                         "actual={kernel_crc}; boot_requested={boot_requested}; "
                         "reviewed_critical={boot_critical_reviewed}".format(**item))
        lines.append("")
    if report["potential_risks"]:
        lines += ["### Potential ABI risks (not proven failures)", ""]
        lines += ["- " + item["kind"] + ": " + item.get("config", item["reason"])
                  for item in report["potential_risks"]]
        lines.append("")
    if report["unverified"]:
        lines += ["### Unverified", ""]
        lines += ["- " + item for item in report["unverified"][:60]]
        lines.append("")
    Path(args.report_md).write_text("\n".join(lines) + "\n")
    print(f"KMI Guard: {report['status']}; rejections="
          f"{len(report['definite_module_rejections'])}; "
          f"unverified={len(report['unverified'])}")
    if args.mode == "enforce" and (report["definite_module_rejections"] or report["unverified"]):
        return 3
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    cap = sub.add_parser("capture")
    cap.add_argument("--modules-root", required=True, action="append",
                     help="repeat for vendor, odm, vendor_boot and other module directories")
    cap.add_argument("--modules-load", action="append", default=[])
    cap.add_argument("--critical-list", action="append", default=[])
    cap.add_argument("--fingerprint", default="")
    cap.add_argument("--modprobe", default="modprobe")
    cap.add_argument("--modinfo", default="modinfo")
    cap.add_argument("--output", required=True)
    check = sub.add_parser("audit")
    check.add_argument("--symvers", required=True)
    check.add_argument("--config", required=True)
    check.add_argument("--baseline-symvers")
    check.add_argument("--vendor-manifest")
    check.add_argument("--baseline-layouts")
    check.add_argument("--candidate-layouts")
    check.add_argument("--mode", choices=("audit", "enforce"), default="audit")
    check.add_argument("--report-json", required=True)
    check.add_argument("--report-md", required=True)
    args = parser.parse_args(argv)
    try:
        return capture(args) if args.action == "capture" else audit(args)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("KMI Guard ERROR: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
