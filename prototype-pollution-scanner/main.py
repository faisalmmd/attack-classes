#!/usr/bin/env python3
"""
Prototype Pollution Scanner - CLI entry point.

Scans JS files and HTML inline scripts for code patterns associated with
prototype pollution vulnerabilities and their defenses.

Usage:
  python main.py --country AE
  python main.py --all
  python main.py --all --category VULNERABLE
  python main.py --all --no-defensive    # skip INFO-level defensive patterns
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
    One row per (country, domain, year) with counts broken out by category.
    This is the table for longitudinal analysis - how many vulnerable patterns
    exist per domain over time, and whether defenses appear.
    """
    agg = defaultdict(lambda: {
        'vulnerable': 0, 'indicator': 0, 'defensive': 0,
        'forin_count': 0, 'jquery_deep': 0, 'lodash_merge': 0,
        'has_defense': False,
    })
    for f in findings:
        key = (f.country, f.domain, f.year)
        a = agg[key]
        cat = f.category.lower()
        if cat in ('vulnerable', 'indicator', 'defensive'):
            a[cat] += 1
        if f.pattern_id == 'forin_bracket_assign':
            a['forin_count'] += 1
        if f.pattern_id == 'jquery_extend_deep':
            a['jquery_deep'] += 1
        if f.pattern_id == 'lodash_deep_merge':
            a['lodash_merge'] += 1
        if cat == 'defensive':
            a['has_defense'] = True

    rows = []
    for (country, domain, year), stats in sorted(agg.items()):
        rows.append({
            'country': country,
            'domain': domain,
            'year': year,
            'vulnerable_patterns': stats['vulnerable'],
            'indicator_patterns': stats['indicator'],
            'defensive_patterns': stats['defensive'],
            'forin_bracket_assign_count': stats['forin_count'],
            'jquery_deep_extend_count': stats['jquery_deep'],
            'lodash_merge_count': stats['lodash_merge'],
            'has_any_defense': stats['has_defense'],
        })
    write_csv(rows, out_path)


def main():
    ap = argparse.ArgumentParser(
        description='Scan JS and HTML for prototype pollution patterns and defenses.'
    )
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument('--country', metavar='CC')
    grp.add_argument('--all', action='store_true')

    ap.add_argument('--no-js', action='store_true', help='Skip .js files')
    ap.add_argument('--no-html', action='store_true', help='Skip HTML inline scripts')
    ap.add_argument('--no-defensive', action='store_true',
                    help='Exclude DEFENSIVE (INFO) patterns from findings CSV')
    ap.add_argument('--category',
                    choices=['VULNERABLE', 'INDICATOR', 'DEFENSIVE'],
                    help='Filter output to one category')
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
    if args.no_defensive:
        all_findings = [f for f in all_findings if f.category != 'DEFENSIVE']
    if args.category:
        all_findings = [f for f in all_findings if f.category == args.category]

    # Count by category before writing
    by_cat = defaultdict(int)
    by_pattern = defaultdict(int)
    by_year = defaultdict(int)
    domains_with_vulnerable = set()
    domains_with_defense = set()

    for f in all_findings:
        by_cat[f.category] += 1
        by_pattern[f.pattern_label] += 1
        by_year[f.year] += 1
        if f.category == 'VULNERABLE':
            domains_with_vulnerable.add((f.country, f.domain))
        if f.category == 'DEFENSIVE':
            domains_with_defense.add((f.country, f.domain))

    # Write outputs
    findings_path = out_dir / 'pollution_findings.csv'
    domain_path = out_dir / 'domain_summary.csv'
    summary_path = out_dir / 'pollution_summary.json'

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
        'domains_with_vulnerable_patterns': len(domains_with_vulnerable),
        'domains_with_defensive_patterns': len(domains_with_defense),
    }
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

    print(f'\n{"=" * 60}')
    print(f'  Prototype Pollution Scanner - Results')
    print(f'{"=" * 60}')
    print(f'  Countries         : {", ".join(countries)}')
    print(f'  JS files scanned  : {total_js}')
    print(f'  HTML files scanned: {total_html}')
    print(f'  Total findings    : {len(all_findings)}')
    print()
    print('  By category:')
    for cat in ('VULNERABLE', 'INDICATOR', 'DEFENSIVE'):
        print(f'    {cat:<12} {by_cat.get(cat, 0)}')
    print()
    print('  Top patterns:')
    for pat, count in list(sorted(by_pattern.items(), key=lambda x: -x[1]))[:8]:
        print(f'    {count:>6}  {pat}')
    print()
    print(f'  Domains with vulnerable patterns : {len(domains_with_vulnerable)}')
    print(f'  Domains with defensive patterns  : {len(domains_with_defense)}')
    print()
    print(f'  Findings CSV     -> {findings_path}')
    print(f'  Domain summary   -> {domain_path}')
    print(f'  Summary JSON     -> {summary_path}')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
