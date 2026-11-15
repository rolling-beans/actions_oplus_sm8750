#!/usr/bin/env python3
"""Offline binary comparison for AutoFDO+ThinLTO. No runtime claims."""
import argparse
import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_output(args):
    cp = subprocess.run(args, capture_output=True, text=True, check=True)
    return cp.stdout


def section_sizes(toolchain, vmlinux):
    output = tool_output([str(toolchain / "llvm-size"), "-A", str(vmlinux)])
    sections = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].isdigit():
            sections[parts[0]] = int(parts[1])
    if ".text" not in sections:
        raise ValueError("llvm-size did not report .text (wrong or missing ELF?)")
    return sections, output


def function_sizes(toolchain, vmlinux):
    output = tool_output([str(toolchain / "llvm-nm"), "--defined-only",
                          "--print-size", "--size-sort", "--radix=d", str(vmlinux)])
    functions = {}
    for line in output.splitlines():
        match = re.match(r"^\s*\d+\s+(\d+)\s+([tTwW])\s+(.+?)\s*$", line)
        if match:
            name = match.group(3)
            # Include local (t) and global (T) text symbols; no function-inlining claims.
            functions[name] = int(match.group(1))
    return functions


def collect(args):
    root = Path(args.build_dir)
    toolchain = Path(args.toolchain)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    vmlinux = root / "vmlinux"
    image = root / "arch/arm64/boot/Image"
    config = root / ".config"
    for p in (vmlinux, image, config):
        if not p.is_file():
            raise FileNotFoundError(str(p))
    sections, size_output = section_sizes(toolchain, vmlinux)
    functions = function_sizes(toolchain, vmlinux)
    (output / "llvm-size.txt").write_text(size_output, encoding="utf-8")
    (output / "top-text-symbols.tsv").write_text(
        "size_bytes\tsymbol\n" +
        "".join(f"{size}\t{name}\n" for name, size in
                sorted(functions.items(), key=lambda x: x[1], reverse=True)[:200]),
        encoding="utf-8")
    data = {
        "mode": args.mode,
        "source_fingerprint": Path(args.source_fingerprint).read_text().strip(),
        "compiler": tool_output([str(toolchain / "clang"), "--version"]).splitlines()[0],
        "lld": tool_output([str(toolchain / "ld.lld"), "--version"]).splitlines()[0],
        "config_sha256": digest(config),
        "vmlinux_size": vmlinux.stat().st_size,
        "vmlinux_sha256": digest(vmlinux),
        "image_size": image.stat().st_size,
        "image_sha256": digest(image),
        "sections": sections,
        "text_symbol_count": len(functions),
        "text_symbol_size_sum": sum(functions.values()),
        "top_text_symbols": [
            {"name": name, "size": size} for name, size in
            sorted(functions.items(), key=lambda x: x[1], reverse=True)[:200]
        ],
        "build_seconds": int(Path(args.build_duration).read_text().strip()),
        "profile_sha256": (
            digest(Path(args.profile))
            if args.profile and Path(args.profile).is_file()
            else None
        ),
        "profiled_linker_arg_seen": bool(
            args.linker_args and Path(args.linker_args).is_file()
            and "--lto-sample-profile=" in Path(args.linker_args).read_text()
        ),
        "kconfig_autofdo": "CONFIG_AUTOFDO_CLANG=y" in config.read_text(),
        "kconfig_thinlto": "CONFIG_LTO_CLANG_THIN=y" in config.read_text(),
    }
    (output / "metrics.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in data.items()
                      if k not in ("sections", "top_text_symbols")}, indent=2))


def compare(args):
    folder = Path(args.input_dir)
    items = {}
    for p in folder.rglob("metrics.json"):
        data = json.loads(p.read_text())
        if data["mode"] in items:
            raise ValueError(f"duplicate mode: {data['mode']}")
        items[data["mode"]] = data
    if set(items) != {"baseline", "profiled"}:
        raise ValueError(f"expected both modes, got {sorted(items)}")
    a, b = items["baseline"], items["profiled"]
    required = ["source_fingerprint", "compiler", "lld", "config_sha256", "profile_sha256"]
    mismatches = [key for key in required if a[key] != b[key]]
    if mismatches:
        raise ValueError(f"A/B is not controlled: different {mismatches}")
    if not (a["kconfig_autofdo"] and b["kconfig_autofdo"]
            and a["kconfig_thinlto"] and b["kconfig_thinlto"]):
        raise ValueError("Kconfig does not have AutoFDO+ThinLTO in both builds")
    if a["profiled_linker_arg_seen"] or not b["profiled_linker_arg_seen"]:
        raise ValueError("link-time profile isolation failed")

    lines = [
        "# AutoFDO + ThinLTO — offline A/B report", "",
        "Both binaries were built from identical patched sources and effective Kconfig.",
        "The only intended treatment is the presence of CLANG_AUTOFDO_PROFILE.",
        "These are *static code/build measurements*, not device performance benchmarks.",
        "",
        f"- Compiler: `{a['compiler']}`",
        f"- Source manifest SHA256: `{a['source_fingerprint']}`",
        f"- Configuration SHA256: `{a['config_sha256']}`",
        f"- Profile SHA256: `{b['profile_sha256']}`", "",
        "| Metric | ThinLTO only | ThinLTO + AutoFDO | Change |",
        "|---|---:|---:|---:|",
    ]
    rows = []
    keys = ["vmlinux_size", "image_size", "build_seconds", "text_symbol_count",
            "text_symbol_size_sum"]
    sections = sorted(set(a["sections"]) | set(b["sections"]))
    for key in sections:
        if key == "Total":
            continue
        if key == ".text" or key.startswith((".text.", ".rodata", ".data", ".bss", ".init.text")):
            keys.append("section:" + key)
    for key in keys:
        va = a["sections"].get(key[8:], 0) if key.startswith("section:") else a[key]
        vb = b["sections"].get(key[8:], 0) if key.startswith("section:") else b[key]
        diff = 100 * (vb - va) / va if va else None
        change = f"{diff:+.3f}%" if diff is not None else "n/a"
        lines.append(f"| {key} | {va:,} | {vb:,} | {change} |")
        rows.append((key, va, vb, change))
    lines += ["",
              "**Important:** Identical symbol names do not imply identical instruction",
              "sequences. Size decreases do not demonstrate faster execution.",
              "Clang sample-profile diagnostics and disassembly must be examined",
              "separately before drawing conclusions about coverage or speed.",
              "",
              "Profile top-function output and LLVM section data are retained in artifacts.",
              ]
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.md").write_text("\n".join(lines) + "\n")
    with (output / "comparison.csv").open("w", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(["metric", "baseline", "profiled", "delta"])
        writer.writerows(rows)
    print((output / "summary.md").read_text())


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--mode", choices=["baseline", "profiled"], required=True)
    c.add_argument("--build-dir", required=True)
    c.add_argument("--toolchain", required=True)
    c.add_argument("--source-fingerprint", required=True)
    c.add_argument("--build-duration", required=True)
    c.add_argument("--profile")
    c.add_argument("--linker-args")
    c.add_argument("--output", required=True)
    d = sub.add_parser("compare")
    d.add_argument("--input-dir", required=True)
    d.add_argument("--output", required=True)
    args = parser.parse_args()
    (collect if args.command == "collect" else compare)(args)


if __name__ == "__main__":
    main()
