#!/usr/bin/env python3
"""Compare a *full* isolated parser-off Image against same-run parser-on Image.

Never treats STG differences as evidence of required module loading or boot safety.
"""
import argparse
import json
import re
from pathlib import Path
from scripts.kmi_stg_crc_diff import compare, parse_stg, parse_symvers

EXPECTED_CHANGED = {"CONFIG_BPF_STREAM_PARSER", "CONFIG_STREAM_PARSER"}


def config_values(text):
    values = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            k, v = line.split("=", 1)
            values[k] = v
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:].split(" is not set")[0]] = "n"
    return values


def compare_config(control, variant, net_kconfig):
    before, after = config_values(control), config_values(variant)
    delta = {k: {"control": before.get(k), "variant": after.get(k)}
             for k in sorted(set(before) | set(after))
             if before.get(k) != after.get(k)}
    block = re.search(r"(?ms)^config BPF_STREAM_PARSER\s*\n(.*?)(?=^config |\Z)",
                      net_kconfig)
    selected = bool(block and re.search(r"(?m)^\s*select STREAM_PARSER\s*$",
                                        block.group(1)))
    parser_ok = delta.get("CONFIG_BPF_STREAM_PARSER") == {
        "control": "y", "variant": "n"}
    stream = delta.get("CONFIG_STREAM_PARSER")
    stream_ok = bool(selected and stream and stream["control"] == "y"
                     and stream["variant"] in ("n", None))
    only_expected = parser_ok and stream_ok and set(delta) == EXPECTED_CHANGED
    return {"status": "COMPLETE" if only_expected else "CONFOUNDED",
            "differences": delta,
            "direct_parser_disabled": parser_ok,
            "stream_parser_select_in_source": selected,
            "derived_stream_parser_disabled": stream_ok,
            "only_expected_changes": only_expected}


def compare_exports(stg, control_symvers, variant_symvers, sweep=None):
    baseline = parse_symvers(control_symvers)
    candidate = parse_symvers(variant_symvers)
    reference = parse_stg(stg)
    known = list((sweep or {}).get("comparator", {}).get("results", []))
    common = sorted(set(baseline) & set(candidate))
    crc_diff = [{"symbol": s, "control_crc": f"0x{baseline[s]:08x}",
                 "variant_crc": f"0x{candidate[s]:08x}"}
                for s in common if baseline[s] != candidate[s]]
    control_stg = compare(stg, control_symvers)
    variant_stg = compare(stg, variant_symvers)
    restored = []
    baseline_drift = []
    nonrestored = []
    for item in known:
        s = item["symbol"]
        expected = int(item["reference_stg_crc"], 16)
        old_crc = int(item["compiled_kernel_crc"], 16)
        live_control = baseline.get(s)
        live_variant = candidate.get(s)
        if live_control != old_crc:
            baseline_drift.append(s)
        if live_variant == expected and live_control is not None:
            restored.append(s)
        else:
            nonrestored.append(s)
    available_stg = sorted(set(reference) & set(candidate))
    missing_in_variant_stg = sorted(set(reference) - set(candidate))
    ambiguous_reference = sorted(s for s in available_stg if len(reference[s]) != 1)
    return {
        "status": "COMPLETE" if not ambiguous_reference else "PARTIAL",
        "baseline_exports": len(baseline),
        "variant_exports": len(candidate),
        "common_exports": len(common),
        "added_exports": sorted(set(candidate) - set(baseline)),
        "removed_exports": sorted(set(baseline) - set(candidate)),
        "changed_crc_count": len(crc_diff),
        "changed_crcs": crc_diff,
        "stg_control": control_stg,
        "stg_variant": variant_stg,
        "stg_missing_from_variant": missing_in_variant_stg,
        "stg_ambiguous_reference": ambiguous_reference,
        "known_sweep_count": len(known),
        "known_sweep_restored": sorted(restored),
        "known_sweep_not_restored": sorted(nonrestored),
        "known_sweep_control_drift": sorted(baseline_drift),
        "sk_filter_trim_cap_control": (
            f"0x{baseline['sk_filter_trim_cap']:08x}"
            if "sk_filter_trim_cap" in baseline else None),
        "sk_filter_trim_cap_variant": (
            f"0x{candidate['sk_filter_trim_cap']:08x}"
            if "sk_filter_trim_cap" in candidate else None),
        "private_593_module_imports": {
            "status": "UNVERIFIED",
            "reason": "Private 593-module metadata is not available in public CI",
            "matched": None, "mismatched": None, "missing_export": None,
            "ambiguous_provider": None, "source_coverage": "UNVERIFIED"},
        "scope": "Full Image/vmlinux.symvers compared within one CI run. "
                 "STG is not a substitute for private module import metadata.",
        "android_boot_tested": False,
        "module_loading_tested": False,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase", choices=["config", "exports"], required=True)
    p.add_argument("--control-config", required=True)
    p.add_argument("--variant-config", required=True)
    p.add_argument("--net-kconfig", required=True)
    p.add_argument("--stg")
    p.add_argument("--control-symvers")
    p.add_argument("--variant-symvers")
    p.add_argument("--known-sweep")
    p.add_argument("--report-json", required=True)
    p.add_argument("--report-md")
    a = p.parse_args(argv)
    check = compare_config(Path(a.control_config).read_text(),
                           Path(a.variant_config).read_text(),
                           Path(a.net_kconfig).read_text())
    report = {"schema_version": 1, "phase": a.phase, "config": check,
              "full_parser_off_image_built": a.phase == "exports",
              "device_modified": False}
    if a.phase == "exports":
        if not check["only_expected_changes"]:
            report["status"] = "CONFOUNDED"
        else:
            sweep = json.loads(Path(a.known_sweep).read_text()) if a.known_sweep else None
            result = compare_exports(Path(a.stg).read_text(),
                                     Path(a.control_symvers).read_text(),
                                     Path(a.variant_symvers).read_text(), sweep)
            report["exports"] = result
            report["status"] = result["status"]
    else:
        report["status"] = check["status"]
    dest = Path(a.report_json)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    if a.report_md:
        lines = ["## Full parser-off kernel KMI experiment", "",
                 f"Status: **{report['status']}**",
                 f"Effective Kconfig delta: {len(check['differences'])} symbols",
                 f"Only expected changes: {check['only_expected_changes']}", ""]
        if a.phase == "exports" and "exports" in report:
            x = report["exports"]
            lines.extend([
                f"Full vmlinux CRC changes vs control: {x['changed_crc_count']}",
                f"STG control mismatches: {x['stg_control']['mismatched']}",
                f"STG variant mismatches: {x['stg_variant']['mismatched']}",
                f"Known 19 restorations: {len(x['known_sweep_restored'])}/{x['known_sweep_count']}",
                f"sk_filter_trim_cap: {x['sk_filter_trim_cap_control']} -> {x['sk_filter_trim_cap_variant']}",
                f"Added exports: {len(x['added_exports'])}; removed exports: {len(x['removed_exports'])}",
                "Private module-import check: UNVERIFIED (not in public CI)",
                "No device flash, boot test or module loading.", ""])
        Path(a.report_md).write_text("\n".join(lines) + "\n")
    print("KMI full parser-off:", report["status"], a.phase)
    return 0 if report["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
