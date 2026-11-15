#!/usr/bin/env python3
"""Private, read-only KMI A/B comparison of Android module imports.

Manifests stay local. Public output contains aggregate counts, not module paths,
firmware identifiers, fingerprints, hashes, or private module metadata.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat

from scripts.kmi_guard import symbol_table


def crc_number(text):
    if not isinstance(text, str) or not text.startswith("0x"):
        raise ValueError("expected hexadecimal CRC string")
    val = int(text, 16)
    if val < 0 or val > 0xffffffff:
        raise ValueError("CRC must fit in 32 bits")
    return val


def read_source_manifests(paths):
    modules = []
    sources = []
    hashes = []
    identities = set()
    for filename in paths:
        content = Path(filename).read_bytes()
        obj = json.loads(content)
        if obj.get("schema_version") != 1 or not isinstance(obj.get("modules"), list):
            raise ValueError("manifest must have schema_version=1 and modules[]")
        if not obj["modules"]:
            raise ValueError("empty module set is not evidence")
        if not isinstance(obj.get("sources"), list):
            raise ValueError("manifest is missing source coverage")
        for source in obj["sources"]:
            if not isinstance(source, dict):
                raise ValueError("malformed source record")
            sources.append(source)
        hashes.append(hashlib.sha256(content).hexdigest())
        for mod in obj["modules"]:
            name = mod.get("path")
            if not isinstance(name, str) or not name or name in identities:
                raise ValueError("module path missing or duplicate across manifests")
            identities.add(name)
            if not isinstance(mod.get("required_crcs"), dict):
                raise ValueError("missing required_crcs on module " + name)
            if not isinstance(mod.get("exported_crcs"), dict):
                raise ValueError("missing exported_crcs on module " + name)
            for table in ("required_crcs", "exported_crcs"):
                for symbol, crc in mod[table].items():
                    if not isinstance(symbol, str) or not symbol:
                        raise ValueError("invalid module symbol name")
                    crc_number(crc)
            modules.append(mod)
    return modules, sources, hashes


def compare_manifests(modules, baseline, variant, sources=()):
    # Resolve module-provided symbols against the complete combined manifest,
    # not each vendor or system_dlkm manifest in isolation.
    providers = defaultdict(list)
    for mod in modules:
        for symbol, crc in mod["exported_crcs"].items():
            providers[symbol].append((mod["path"], crc_number(crc)))

    before = {s: int(v, 16) for s, v in baseline.items()}
    after = {s: int(v, 16) for s, v in variant.items()}
    changed = sorted(s for s in before.keys() & after.keys()
                     if before[s] != after[s])
    removed = sorted(before.keys() - after.keys())
    added = sorted(after.keys() - before.keys())
    delta = set(changed) | set(removed) | set(added)

    totals = {"baseline": Counter(), "variant": Counter()}
    details = {"baseline": [], "variant": []}
    relevant_imports = defaultdict(set)
    unknown_modules = []
    importer_totals = Counter()

    for mod in modules:
        module_path = mod["path"]
        if (mod.get("capture_error") or mod.get("export_capture_note")
                or not mod["required_crcs"]):
            unknown_modules.append(module_path)
        for symbol, expected_hex in mod["required_crcs"].items():
            expected = crc_number(expected_hex)
            importer_totals[module_path] += 1
            if symbol in delta:
                relevant_imports[symbol].add(module_path)
            for label, exports in (("baseline", before), ("variant", after)):
                # Once in baseline vmlinux, disappearance means removed kernel
                # export, not a fallback to a randomly matching .ko provider.
                if symbol in before or symbol in after or symbol == "module_layout":
                    actual = exports.get(symbol)
                    provider = "vmlinux"
                    if actual is None:
                        state = "missing_export"
                    else:
                        state = "matched" if actual == expected else "crc_mismatch"
                else:
                    matches = providers.get(symbol, [])
                    provider = "module"
                    if not matches:
                        state, actual = "unknown_provider", None
                    elif len(matches) != 1 or matches[0][0] == module_path:
                        state, actual = "ambiguous_provider", None
                    else:
                        actual = matches[0][1]
                        state = "matched" if actual == expected else "crc_mismatch"
                totals[label][state] += 1
                if state != "matched":
                    details[label].append({
                        "module": module_path,
                        "symbol": symbol,
                        "expected": f"0x{expected:08x}",
                        "actual": None if actual is None else f"0x{actual:08x}",
                        "provider_kind": provider,
                        "status": state,
                        "boot_requested": bool(mod.get("boot_requested")),
                    })
    total_imports = sum(importer_totals.values())
    # The importer count includes all required CRC entries even if a capture
    # error means the remaining imports for this module might be inaccessible.
    public = {
        "schema_version": 1,
        "scope": "CRC imports in supplied vendor/system_dlkm manifests only",
        "module_count": len(modules),
        "source_labels": sorted(set(s.get("label", "?") for s in sources)),
        "source_available": all(s.get("available") is not False for s in sources),
        "modules_with_incomplete_capture": len(unknown_modules),
        "observed_required_import_count": total_imports,
        "baseline": dict(sorted(totals["baseline"].items())),
        "variant": dict(sorted(totals["variant"].items())),
        "baseline_definite_rejection_modules": len({
            e["module"] for e in details["baseline"]
            if e["status"] in ("crc_mismatch", "missing_export")}),
        "variant_definite_rejection_modules": len({
            e["module"] for e in details["variant"]
            if e["status"] in ("crc_mismatch", "missing_export")}),
        "baseline_boot_requested_rejection_modules": len({
            e["module"] for e in details["baseline"]
            if e["status"] in ("crc_mismatch", "missing_export")
            and e["boot_requested"]}),
        "variant_boot_requested_rejection_modules": len({
            e["module"] for e in details["variant"]
            if e["status"] in ("crc_mismatch", "missing_export")
            and e["boot_requested"]}),
        "changed_kernel_export_crc_count": len(changed),
        "removed_kernel_export_count": len(removed),
        "added_kernel_export_count": len(added),
        "changed_or_removed_export_imports": [
            {"symbol": name, "importing_modules": len(importers)}
            for name, importers in sorted(relevant_imports.items())],
        "sk_filter_trim_cap": {
            "baseline_crc": baseline.get("sk_filter_trim_cap"),
            "variant_crc": variant.get("sk_filter_trim_cap"),
            "supplied_importer_count": len(relevant_imports.get("sk_filter_trim_cap", set())),
        },
        "source_coverage": "UNVERIFIED_FOR_FIRST_STAGE_VENDOR_BOOT_ODM",
        "proves_android_boot_safety": False,
        "proves_nested_structural_abi_safety": False,
        "does_not_publish_module_paths": True,
    }
    private = {
        "public_aggregate": public,
        "baseline_unmatched": details["baseline"],
        "variant_unmatched": details["variant"],
        "incomplete_capture_module_paths": unknown_modules,
        "delta_importers": {k: sorted(v) for k, v in relevant_imports.items()},
    }
    return public, private


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", action="append", required=True)
    p.add_argument("--baseline-symvers", required=True)
    p.add_argument("--variant-symvers", required=True)
    p.add_argument("--expected-modules", type=int)
    p.add_argument("--expected-imports", type=int)
    p.add_argument("--private-report", required=True)
    p.add_argument("--public-report", required=True)
    args = p.parse_args(argv)
    if Path(args.private_report).resolve() == Path(args.public_report).resolve():
        p.error("private and public output paths must differ")
    modules, sources, hashes = read_source_manifests(args.manifest)
    baseline, variant = symbol_table(args.baseline_symvers), symbol_table(args.variant_symvers)
    if not baseline or not variant:
        p.error("both vmlinux.symvers exports are required")
    public, private = compare_manifests(modules, baseline, variant, sources)
    public["expected_modules_met"] = args.expected_modules is None or public["module_count"] == args.expected_modules
    public["expected_imports_met"] = args.expected_imports is None or public["observed_required_import_count"] == args.expected_imports
    public["status"] = ("COMPLETE_FOR_SUPPLIED_MANIFESTS"
                        if public["expected_modules_met"] and public["expected_imports_met"]
                        and not public["modules_with_incomplete_capture"]
                        and public["source_available"]
                        and all(not public[c].get("unknown_provider") and
                                not public[c].get("ambiguous_provider")
                                for c in ("baseline", "variant"))
                        else "PARTIAL_OR_UNVERIFIED")
    private["input_manifest_sha256"] = hashes
    os.makedirs(Path(args.private_report).parent, exist_ok=True)
    # Never follow a symlink or replace existing private output with a less
    # restricted destination. The caller picks a fresh temporary filename.
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(args.private_report, flags, 0o600)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            json.dump(private, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except Exception:
        raise
    dest = Path(args.public_report)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(public, indent=2, ensure_ascii=False) + "\n")
    print(f"Module KMI A/B: {public['status']}; modules={public['module_count']}; "
          f"imports={public['observed_required_import_count']}; "
          f"baseline_rejected_modules={public['baseline_definite_rejection_modules']}; "
          f"variant_rejected_modules={public['variant_definite_rejection_modules']}")
    return 0 if public["status"] == "COMPLETE_FOR_SUPPLIED_MANIFESTS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
