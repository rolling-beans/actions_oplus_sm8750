#!/usr/bin/env python3
"""AutoFDO sample-loader diagnostics and linker optimization remarks.

Read-only parser. LLVM sample-profile warnings are per function / compilation
unit; they are NOT globally additive. Optimization remarks are a selected
subset of passes, not all inlining decisions.
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

COVERAGE = re.compile(
    r"(?P<used>\d+) of (?P<available>\d+) available profile "
    r"(?P<kind>records|samples) \((?P<pct>\d+)%\) were applied"
)
YAML_START = re.compile(r"^---\s+!<?(?P<kind>Passed|Missed|Analysis|Failure)>?")
FIELD = re.compile(r"^(?P<name>Pass|Name|Function|Hotness):\s*(?P<value>.*)$")
MAX_LOG_BYTES = 100_000_000
MAX_REMARK_BYTES = 120_000_000


def parse_coverage(lines):
    """Retain warning instances, including duplicates to reveal reprocessing."""
    rows = []
    for line in lines:
        match = COVERAGE.search(line)
        if not match:
            continue
        # Preserve the diagnostic's source location, but bound its size.
        source = line[:match.start()].strip()[-400:]
        used = int(match['used'])
        avail = int(match['available'])
        if not avail or used > avail:
            continue
        rows.append({
            'source': source,
            'kind': match['kind'],
            'used': used,
            'available': avail,
            'percent_from_llvm': int(match['pct']),
            'percent_exact': round(100 * used / avail, 3),
        })
    return rows


def parse_yaml_remarks(lines):
    """Streaming subset parser for LLVM YAML document headers and scalar keys."""
    result = []
    current = None

    def finish():
        if current is not None and current.get('pass'):
            result.append(current)

    for line in lines:
        m = YAML_START.match(line)
        if m:
            finish()
            current = {'type': m['kind']}
            continue
        if line == '...' or line.startswith('... '):
            finish()
            current = None
            continue
        if current is None:
            continue
        # Avoid nested Args keys (the YAML top-level fields are unindented).
        m = FIELD.match(line)
        if m:
            key = m['name'].lower()
            value = m['value'].strip().strip('"').strip("'")
            current[key] = value[:500]
    finish()
    return result


def summarize(rows, remarks):
    by_kind = {}
    for kind in ('records', 'samples'):
        selected = [r for r in rows if r['kind'] == kind]
        unique = {(r['source'], r['kind'], r['used'], r['available']) for r in selected}
        by_kind[kind] = {
            'warning_instances': len(selected),
            'unique_warning_tuples': len(unique),
            'below_50_pct': sum(r['percent_exact'] < 50 for r in selected),
            'below_80_pct': sum(r['percent_exact'] < 80 for r in selected),
            'at_100_pct': sum(r['used'] == r['available'] for r in selected),
            'note': 'No global ratio: warnings may duplicate sample records across TUs and LTO.',
        }
    filtered = [r for r in remarks if 'inline' in r.get('pass', '').lower() or
                'sample' in r.get('pass', '').lower()]
    cnt = collections.Counter((r.get('pass', '?'), r['type']) for r in filtered)
    top_functions = collections.Counter(r.get('function', '<unknown>') for r in filtered)
    return {
        'coverage': by_kind,
        'remarks': {
            'total_parsed_documents': len(remarks),
            'inline_or_sample_documents': len(filtered),
            'by_pass_and_type': [
                {'pass': k[0], 'type': k[1], 'count': n}
                for k,n in cnt.most_common(40)
            ],
            'top_functions_by_remark_count': top_functions.most_common(30),
            'limitations': 'Only selected ThinLTO backend remarks; not all compiler invocations.',
        },
    }


def collect(args):
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    log = Path(args.log)
    if log.stat().st_size > MAX_LOG_BYTES:
        raise ValueError('Build log >100MB; inspect streaming volume before parsing')
    lines = log.read_text(errors='replace').splitlines()
    coverage = parse_coverage(lines)
    remark_files = sorted(Path(args.remarks_dir).glob('*.yaml'))
    remarks = []
    oversized = []
    for f in remark_files:
        if f.stat().st_size > MAX_REMARK_BYTES:
            oversized.append(f.name)
            continue
        remarks.extend(parse_yaml_remarks(f.read_text(errors='replace').splitlines()))
    report = summarize(coverage, remarks)
    report['mode'] = args.mode
    report['coverage_options_requested'] = args.mode == 'profiled'
    report['coverage_warning_count'] = len(coverage)
    report['remarks_files_found'] = len(remark_files)
    report['remarks_files_oversized'] = oversized
    report['note'] = ('The coverage checker is diagnostic. 101% forces reporting '
                      'even for fully matched functions; does not alter optimization.')
    # Bound artifact size; do not archive raw giant log or YAML files.
    (out / 'sample-coverage-cases.json').write_text(
        json.dumps(sorted(coverage, key=lambda r: (r['kind'], r['percent_exact'],
                   -r['available']))[:1500], indent=2) + '\n')
    (out / 'lto-remark-cases.json').write_text(
        json.dumps([r for r in remarks if 'inline' in r.get('pass', '').lower()]
                   [:2000], indent=2) + '\n')
    (out / 'compiler-diagnostics.json').write_text(json.dumps(report, indent=2) + '\n')
    if args.mode == 'profiled' and not coverage:
        print('::warning::No sample-loader coverage warnings captured; do not infer 100% matching.')
    if not remarks:
        print('::warning::No LTO remarks captured; do not infer zero inlining.')
    print(json.dumps(report, indent=2))


def compare(args):
    root = Path(args.input_dir)
    records = {}
    for p in root.rglob('compiler-diagnostics.json'):
        data = json.loads(p.read_text())
        mode = data['mode']
        if mode in records:
            raise ValueError(f'duplicate mode {mode}')
        records[mode] = data
    if set(records) != {'baseline', 'profiled'}:
        raise ValueError('Need diagnostics from both A/B builds')
    a, b = records['baseline'], records['profiled']
    lines = [
        '# LLVM sample loader and ThinLTO inline diagnostics', '',
        'Warnings with “X of Y profile samples/records applied” originate from LLVM',
        'sample-profile coverage checks. **Do not sum them across functions/TUs.**',
        'Each function/IR instance may be reprocessed and inline contexts overlap.', '',
        '| Diagnostic | Baseline | Profiled |',
        '|---|---:|---:|',
    ]
    for kind in ('records', 'samples'):
        for key in ('warning_instances', 'unique_warning_tuples', 'below_50_pct',
                    'below_80_pct', 'at_100_pct'):
            lines.append(f'| {kind} — {key} | {a["coverage"][kind][key]:,} '
                         f'| {b["coverage"][kind][key]:,} |')
    lines += [
        f'| ThinLTO remark YAML files | {a["remarks_files_found"]} '
        f'| {b["remarks_files_found"]} |',
        f'| Parsed inline/sample remarks | {a["remarks"]["inline_or_sample_documents"]:,} '
        f'| {b["remarks"]["inline_or_sample_documents"]:,} |',
        '',
        '## Remarks by pass and type', '',
        '| Pass/type | Baseline | Profiled |', '|---|---:|---:|',
    ]
    for r in sorted(set((x['pass'], x['type']) for item in (a,b)
                        for x in item['remarks']['by_pass_and_type'])):
        def count(d):
            return next((x['count'] for x in d['remarks']['by_pass_and_type']
                         if (x['pass'], x['type']) == r), 0)
        lines.append(f'| {r[0]} / {r[1]} | {count(a):,} | {count(b):,} |')
    lines += [
        '', '### Interpretation limits', '',
        '- Warning ratios are **per-function**, not global kernel coverage.',
        '- Missing warnings are not proof of complete matching.',
        '- “Passed” inline remarks confirm specific decisions, not speedups.',
        '- Counts reflect only reported ThinLTO link passes; preprocessing and',
        '  earlier optimization stages may already have performed inlining.',
        '- The ELF function-name intersection and binary-size A/B report remain',
        '  separate, complementary measurements.', '',
    ]
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'loader-inline-report.md').write_text('\n'.join(lines) + '\n')
    print('\n'.join(lines))


def selftest():
    samples = [
        'foo.c:10:2: warning: 5 of 10 available profile records (50%) were applied',
        'foo.c:10:2: warning: 90 of 200 available profile samples (45%) were applied',
        'foo.c:10:2: warning: 200 of 200 available profile samples (100%) were applied',
    ]
    rows = parse_coverage(samples)
    assert len(rows) == 3 and rows[1]['percent_exact'] == 45
    remarks = parse_yaml_remarks([
        '--- !Passed', 'Pass:            inline', 'Name:            Inlined',
        'Function:        binder_transaction', 'Hotness:         1234',
        'Args:', '  - String: x', '...',
        '--- !Missed', 'Pass: inline', 'Name: NotInlined',
        'Function: __schedule', '...',
    ])
    assert len(remarks) == 2 and remarks[0]['type'] == 'Passed'
    assert remarks[1]['function'] == '__schedule'
    summary = summarize(rows, remarks)
    assert summary['coverage']['samples']['below_50_pct'] == 1
    assert summary['remarks']['inline_or_sample_documents'] == 2
    print('PASS coverage parser and remark parser selftest')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['collect', 'compare', 'selftest'])
    parser.add_argument('--mode', choices=['baseline', 'profiled'])
    parser.add_argument('--log')
    parser.add_argument('--remarks-dir')
    parser.add_argument('--input-dir')
    parser.add_argument('--output')
    opts = parser.parse_args()
    {'collect': collect, 'compare': compare, 'selftest': lambda a: selftest()}[opts.command](opts)
