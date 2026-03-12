#!/usr/bin/env python3
"""
Open Redirect Scanner - CLI entry point.

Scans JavaScript files and HTML inline scripts for open redirect patterns:
redirect sinks (location.href, location.replace, etc.), user-controllable
URL sources (location.search, location.hash, URLSearchParams), and
confirmed source-to-sink chains.

Usage:
  python main.py --country AE
  python main.py --all
  python main.py --all --category CHAIN       # confirmed open redirect paths only
  python main.py --all --no-defensive
  python main.py --country DE --no-html
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scanner import scan_js_file, scan_html_file


BASE_DIR = Path(__file__).resolve().parent.parent.parent
JS_DATA_DIR = BASE_DIR / 'snapshot_js_data'
HTML_DATA_DIR = BASE_DIR / 'snapshot_data'

SEVERITY_ORDER = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


def get_countries(base: Path) -> list:
    if not base.exists():
        return []
    return sorted(p.name for p in base.iterdir()
                  if p.is_dir() and len(p.name) == 2 and p.name.isupper())


def write_csv(rows: list, path: Path):
    if not rows:
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_domain_summary(findings: list, out_path: Path):
    """
    One row per (country, domain, year) summarizing redirect risk.

    The most actionable columns for longitudinal analysis are:
      has_confirmed_chain   - direct source-to-sink path found in the same expression
      sink_with_source      - sink and source in the same domain/year (likely connected)
      has_defense           - at least one validation pattern present
    """
    agg = defaultdict(lambda: {
        'sink_count': 0, 'source_count': 0, 'chain_count': 0,
        'defensive_count': 0, 'has_chain': False, 'has_defense': False,
        'sink_patterns': set(), 'chain_patterns': set(),
    })
    for f in findings:
        key = (f.country, f.domain, f.year)
        a = agg[key]
        if f.category == 'SINK':
            a['sink_count'] += 1
            a['sink_patterns'].add(f.pattern_id)
        elif f.category == 'SOURCE':
            a['source_count'] += 1
        elif f.category == 'CHAIN':
            a['chain_count'] += 1
            a['has_chain'] = True
            a['chain_patterns'].add(f.pattern_id)
        elif f.category == 'DEFENSIVE':
            a['defensive_count'] += 1
            a['has_defense'] = True

    rows = []
    for (country, domain, year), s in sorted(agg.items()):
        rows.append({
            'country': country,
            'domain': domain,
            'year': year,
            'sink_count': s['sink_count'],
            'source_count': s['source_count'],
            'chain_count': s['chain_count'],
            'defensive_count': s['defensive_count'],
            'has_confirmed_chain': s['has_chain'],
            'has_defense': s['has_defense'],
            'sink_with_source': s['sink_count'] > 0 and s['source_count'] > 0,
            'sink_patterns': '|'.join(sorted(s['sink_patterns'])),
            'chain_patterns': '|'.join(sorted(s['chain_patterns'])),
        })
    write_csv(rows, out_path)


def main():
    ap = argparse.ArgumentParser(
        description='Scan JS and HTML for JavaScript-based open redirect patterns.'
    )
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument('--country', metavar='CC')
    grp.add_argument('--all', action='store_true')

    ap.add_argument('--no-js', action='store_true', help='Skip .js files')
    ap.add_argument('--no-html', action='store_true', help='Skip HTML inline scripts')
    ap.add_argument('--no-defensive', action='store_true',
                    help='Exclude DEFENSIVE (INFO) patterns from output')
    ap.add_argument('--category',
                    choices=['SINK', 'SOURCE', 'CHAIN', 'DEFENSIVE'],
                    help='Filter output to one category')
    ap.add_argument('--chains-only', action='store_true',
                    help='Shorthand: output only CHAIN findings (confirmed redirect paths)')
    ap.add_argument('--output', default=None, metavar='DIR')
    args = ap.parse_args()

    countries = get_countries(JS_DATA_DIR) if args.all else [args.country.upper()]
    if not countries:
        print('[!] No country directories found.')
        sys.exit(1)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir = Path(args.output) if args.output else Path(__file__).parent / 'results' / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []
    total_js = total_html = 0

    for country in countries:
        print(f'\n[+] {country}')

        if not args.no_js:
            js_dir = JS_DATA_DIR / country
            js_files = sorted(js_dir.rglob('*.js')) if js_dir.exists() else []
            print(f'    JS files  : {len(js_files)}')
            for p in js_files:
                all_findings.extend(scan_js_file(p))
                total_js += 1

        if not args.no_html:
            html_dir = HTML_DATA_DIR / country
            html_files = sorted(html_dir.rglob('*_index_*.html')) if html_dir.exists() else []
            print(f'    HTML files: {len(html_files)}')
            for p in html_files:
                all_findings.extend(scan_html_file(p))
                total_html += 1

    # Filters
    if args.chains_only or args.category == 'CHAIN':
        all_findings = [f for f in all_findings if f.category == 'CHAIN']
    elif args.category:
        all_findings = [f for f in all_findings if f.category == args.category]

    if args.no_defensive:
        all_findings = [f for f in all_findings if f.category != 'DEFENSIVE']

    # Aggregate statistics
    by_cat = defaultdict(int)
    by_pattern = defaultdict(int)
    by_year = defaultdict(int)
    domains_with_chain = set()
    domains_with_defense = set()

    for f in all_findings:
        by_cat[f.category] += 1
        by_pattern[f.pattern_label] += 1
        by_year[f.year] += 1
        if f.category == 'CHAIN':
            domains_with_chain.add((f.country, f.domain))
        if f.category == 'DEFENSIVE':
            domains_with_defense.add((f.country, f.domain))

    # Sink + Source co-occurrence at domain/year level
    sinks = {(f.country, f.domain, f.year) for f in all_findings if f.category == 'SINK'}
    sources = {(f.country, f.domain, f.year) for f in all_findings if f.category == 'SOURCE'}
    sink_source_overlap = sinks & sources

    # Write outputs
    findings_path = out_dir / 'redirect_findings.csv'
    domain_path = out_dir / 'domain_summary.csv'
    summary_path = out_dir / 'redirect_summary.json'

    write_csv([f.to_dict() for f in all_findings], findings_path)
    write_domain_summary(all_findings, domain_path)

    summary = {
        'generated': datetime.now().isoformat(),
        'countries_scanned': countries,
        'js_files_scanned': total_js,
        'html_files_scanned': total_html,
        'total_findings': len(all_findings),
        'by_category': dict(by_cat),
        'by_pattern': dict(sorted(by_pattern.items(), key=lambda x: -x[1])),
        'by_year': dict(sorted(by_year.items())),
        'domains_with_confirmed_chain': len(domains_with_chain),
        'domains_with_sink_and_source': len(sink_source_overlap),
        'domains_with_defensive_patterns': len(domains_with_defense),
    }
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

    print(f'\n{"=" * 60}')
    print(f'  Open Redirect Scanner - Results')
    print(f'{"=" * 60}')
    print(f'  Countries         : {", ".join(countries)}')
    print(f'  JS files scanned  : {total_js}')
    print(f'  HTML files scanned: {total_html}')
    print(f'  Total findings    : {len(all_findings)}')
    print()
    print('  By category:')
    for cat in ('CHAIN', 'SINK', 'SOURCE', 'DEFENSIVE'):
        print(f'    {cat:<12} {by_cat.get(cat, 0)}')
    print()
    print('  Top patterns:')
    for pat, count in list(sorted(by_pattern.items(), key=lambda x: -x[1]))[:8]:
        print(f'    {count:>6}  {pat}')
    print()
    print(f'  Domains with confirmed chain (high risk)  : {len(domains_with_chain)}')
    print(f'  Domains with sink + source (moderate)     : {len(sink_source_overlap)}')
    print(f'  Domains with defensive patterns           : {len(domains_with_defense)}')
    print()
    print(f'  Findings CSV   -> {findings_path}')
    print(f'  Domain summary -> {domain_path}')
    print(f'  Summary JSON   -> {summary_path}')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
