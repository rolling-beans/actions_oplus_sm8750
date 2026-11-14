#!/usr/bin/env python3
"""Extract transitive genksyms type evidence for ONE exported kernel symbol.

Input: KBUILD_SYMTYPES=1 output from the *same configured source tree and
toolchain* as the kernel. Not a module loader and not a CRC fixer.
Missing type records or ambiguous duplicate type keys remain visible.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000
MAX_WALK = 5000
TYPE_REF = re.compile(r"(?<![A-Za-z0-9_])(?:s|u|e|t)#[A-Za-z0-9_$.-]+")


def extract(content, symbol):
    raw = content.encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise ValueError("symtypes input too large")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
        raise ValueError("invalid export symbol name")
    records = {}
    conflicts = {}
    for line in content.splitlines():
        if not line.strip():
            continue
        if len(records) > MAX_RECORDS:
            raise ValueError("too many symtypes records")
        key, sep, declaration = line.partition(" ")
        if not sep or not key or not declaration:
            raise ValueError("invalid symtypes record (expected key + declaration)")
        if key in records and records[key] != declaration:
            conflicts.setdefault(key, [records[key]]).append(declaration)
        records.setdefault(key, declaration)
    if symbol not in records:
        raise ValueError(f"exported symbol {symbol} missing from symtypes")
    pending = set(TYPE_REF.findall(records[symbol]))
    definitions = {}
    missing = []
    while pending:
        if len(definitions) + len(missing) >= MAX_WALK:
            raise ValueError("symtypes transitive graph exceeds limit")
        key = min(pending)
        pending.remove(key)
        if key in definitions or key in missing:
            continue
        if key not in records:
            missing.append(key)
            continue
        definitions[key] = records[key]
        pending.update(
            candidate for candidate in TYPE_REF.findall(records[key])
            if candidate not in definitions and candidate not in missing
        )
    blockers = sorted([key for key in conflicts if key == symbol or key in definitions])
    return {
        "schema_version": 1,
        "symbol": symbol,
        "status": "PARTIAL" if missing or blockers else "COMPLETE",
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "symbol_declaration": records[symbol],
        "transitive_record_count": len(definitions),
        "transitive_declarations": dict(sorted(definitions.items())),
        "unresolved_type_references": sorted(missing),
        "ambiguous_records": {key: conflicts[key] for key in blockers},
        "scope": "genksyms declaration graph; not a claim of runtime ABI safety",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symtypes", required=True)
    parser.add_argument("--symbol", default="sk_filter_trim_cap")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        src = Path(args.symtypes).read_bytes()
        if len(src) > MAX_BYTES:
            raise ValueError("symtypes input too large")
        report = extract(src.decode("utf-8"), args.symbol)
    except (UnicodeError, ValueError, OSError) as exc:
        report = {
            "schema_version": 1,
            "symbol": args.symbol,
            "status": "UNVERIFIED",
            "reason": str(exc),
        }
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print("KMI symtypes closure:", report["status"], "symbol:", args.symbol,
          "references:", report.get("transitive_record_count", "?"))
    return 0 if report["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
