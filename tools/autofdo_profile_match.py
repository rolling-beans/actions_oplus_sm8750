#!/usr/bin/env python3
"""Exact ELF symbol-name overlap with Android GKI sample profile.

This is not LLVM sample-to-IR coverage. Name matching is a static heuristic.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

FUNC = re.compile(r"^\s*\d+:\s+[0-9a-fA-F]+\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+(\S+)\s+(.+?)\s*$")
PROFILE = re.compile(r"^Function: (.*): (\d+), (\d+), (\d+) sampled lines$")


def stream_process(argv):
    p = subprocess.Popen(argv, text=True, errors="replace",
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in p.stdout:
        yield line.rstrip("\r\n")
    error = p.stderr.read()
    if p.wait():
        raise RuntimeError("Command failed: " + " ".join(argv) + "\n" + error[-1500:])


def parse_symbols(lines):
    symbols = {}
    zero = 0
    for line in lines:
        match = FUNC.match(line)
        if not match:
            continue
        size, section, name = int(match.group(1)), match.group(2), match.group(3)
        if section in ("UND", "ABS", "COM"):
            continue
        if not size:
            zero += 1
        else:
            symbols[name] = max(size, symbols.get(name, 0))
    return symbols, zero


def parse_profile(lines):
    entries = {}
    for line in lines:
        match = PROFILE.match(line)
        if match:
            entries[match.group(1)] = (int(match.group(2)), int(match.group(3)))
    return entries


def collect(args):
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    toolchain = Path(args.toolchain)
    names, zero = parse_symbols(stream_process(
        [str(toolchain / "llvm-readelf"), "--symbols", "--wide", args.vmlinux]))
    if not names:
        raise ValueError("No positive-sized STT_FUNC entries: cannot produce reliable ELF function sizes")
    profiles = parse_profile(stream_process(
        [str(toolchain / "llvm-profdata"), "show", "--sample", args.profile]))
    if not profiles:
        raise ValueError("No top-level 'Function:' headers in llvm-profdata sample output")
    matches = set(names) & set(profiles)
    total_weight = sum(v[0] for v in profiles.values())
    matched_weight = sum(profiles[k][0] for k in matches)
    result = {
        "method": "Exact top-level profile name vs nonzero-sized ELF STT_FUNC",
        "profile_function_count": len(profiles),
        "elf_function_names": len(names),
        "elf_zero_sized_func_records": zero,
        "exact_name_matches": len(matches),
        "exact_name_pct": round(100 * len(matches) / len(profiles), 3),
        "profile_top_level_total_weight": total_weight,
        "exact_name_total_weight": matched_weight,
        "exact_name_weight_pct": round(100 * matched_weight / total_weight, 3) if total_weight else None,
        "limitations": "Not actual sample-to-IR coverage: inlining, LTO, local aliases, function "
                       "removal, debug locations and TotalSamples double-counting are not resolved.",
    }
    for category, subset in [
        ("matched", matches),
        ("unmatched", set(profiles) - matches),
    ]:
        result["top_" + category] = [
            {"name": n, "total_weight": profiles[n][0], "head_weight": profiles[n][1]}
            for n in sorted(subset, key=lambda n: profiles[n][0], reverse=True)[:30]
        ]
    (out / "profile-elf-overlap.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / "elf-function-sizes.json").write_text(json.dumps(names, sort_keys=True) + "\n")
    mpath = out / "metrics.json"
    metrics = json.loads(mpath.read_text())
    # Replace the invalid llvm-nm zero-sized KCFI symbols from stage 1.
    metrics["text_symbol_count"] = len(names)
    metrics["text_symbol_size_sum"] = sum(names.values())
    metrics["elf_zero_sized_func_records"] = zero
    metrics["profile_exact_name_overlap"] = {k:v for k,v in result.items()
         if k not in ("top_matched", "top_unmatched", "limitations")}
    metrics["text_symbol_size_sum_note"] = "Sum of deduplicated, positive-sized STT_FUNC; may overlap; not .text bytes"
    metrics["symbol_metrics_version"] = 2
    mpath.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    md = [
        "# Static profile / ELF name overlap", "",
        "This is *not* compiler sample-to-IR coverage.",
        "",
        "| Quantity | Value |", "|---|---:|",
        "| Top-level sampled functions | " + f"{len(profiles):,}" + " |",
        "| Positive-sized ELF function names | " + f"{len(names):,}" + " |",
        "| Exact profile names matched | " + f"{len(matches):,}" + " |",
        "| Exact-name match proportion | " + str(result["exact_name_pct"]) + "% |",
        "| Exact-name TotalSamples weight proxy | " + str(result["exact_name_weight_pct"]) + "% |",
        "",
        "## Hot profile functions not found by exact ELF name",
        "",
        "| Function | TotalSamples proxy |",
        "|---|---:|",
    ]
    md.extend("| " + str(x["name"]) + " | " + f"{x['total_weight']:,}" + " |"
              for x in result["top_unmatched"][:25])
    md += ["", "Missing ELF names do not prove a profile was ignored by LLVM.",
           "TotalSamples can include nested/inlined samples, so percentages are heuristic.", ""]
    (out / "profile-elf-overlap.md").write_text("\n".join(md) + "\n")
    print(json.dumps({k:v for k,v in result.items() if not k.startswith("top_")}, indent=2))


def compare(args):
    root = Path(args.input_dir)
    items = {}
    for p in root.rglob("elf-function-sizes.json"):
        mode = "baseline" if "/baseline/" in str(p) else "profiled" if "/profiled/" in str(p) else None
        if not mode:
            raise ValueError("Cannot infer mode from " + str(p))
        if mode in items:
            raise ValueError("Duplicate mode: " + mode)
        items[mode] = (json.loads(p.read_text()),
                       json.loads((p.parent / "profile-elf-overlap.json").read_text()))
    if set(items) != {"baseline", "profiled"}:
        raise ValueError("Both modes required")
    a, ra = items["baseline"]
    b, rb = items["profiled"]
    common = set(a) & set(b)
    changed = [(n, a[n], b[n], b[n] - a[n]) for n in common if a[n] != b[n]]
    changed.sort(key=lambda x: abs(x[3]), reverse=True)
    rows = [
        "## ELF function comparison and profile name overlap", "",
        "Symbol sizes from llvm-readelf STT_FUNC, excluding zero-sized KCFI constants.",
        "Name matching is not actual sample-to-IR coverage or a measure of speed.",
        "",
        "| Measure | Baseline | AutoFDO |", "|---|---:|---:|",
        f"| Positive-size ELF function names | {len(a):,} | {len(b):,} |",
        f"| Exact profile name matches | {ra['exact_name_matches']:,} | {rb['exact_name_matches']:,} |",
        f"| Exact profile weight proxy | {ra['exact_name_weight_pct']}% | {rb['exact_name_weight_pct']}% |",
        f"| Symbols with sizes differing (common names) | {len(changed):,} | {len(changed):,} |",
        "", "### Largest STT_FUNC size changes (shared names)", "",
        "| Function | Baseline bytes | AutoFDO bytes | Delta bytes |",
        "|---|---:|---:|---:|",
    ]
    rows.extend("| " + n + " | " + f"{sa:,} | {sb:,} | {d:+,} |"
                for n, sa, sb, d in changed[:30])
    rows.extend(["", f"Shared function names: {len(common):,}.",
                 "This does not establish improvements in runtime performance.", ""])
    dest = Path(args.output)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "profile-elf-comparison.md").write_text("\n".join(rows) + "\n")
    print("\n".join(rows))


def selftest():
    lines = [
       "  123: ffffffc080001000   144 FUNC    GLOBAL DEFAULT    1 __schedule",
       "  124: ffffffc080001000     0 NOTYPE  GLOBAL DEFAULT  ABS __kcfi_typeid_foo",
       "  125: ffffffc080001050   192 FUNC    LOCAL DEFAULT    1 do_foo",
    ]
    names, zeros = parse_symbols(lines)
    assert names == {"__schedule":144,"do_foo":192} and zeros == 0, (names,zeros)
    profile = parse_profile(["Function: __schedule: 20, 4, 2 sampled lines",
                             "Function: has_kernel: 10, 1, 2 sampled lines"])
    assert profile == {"__schedule":(20,4),"has_kernel":(10,1)}
    print("PASS elf/profile parser selftest")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["collect","compare","selftest"])
    parser.add_argument("--toolchain")
    parser.add_argument("--vmlinux")
    parser.add_argument("--profile")
    parser.add_argument("--output")
    parser.add_argument("--input-dir")
    args = parser.parse_args()
    {"collect":collect,"compare":compare,"selftest":lambda _:selftest()}[args.command](args)
