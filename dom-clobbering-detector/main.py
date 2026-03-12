#!/usr/bin/env python3
"""
DOM Clobbering Detector - CLI entry point.

Scans HTML files and JavaScript files for DOM clobbering patterns:
  HTML_SINK    - HTML elements with sensitive names that could clobber globals
  JS_RELIANCE  - JS code accessing globals in ways susceptible to clobbering
  CHAIN        - named element and matching global access in the same HTML page
  DEFENSIVE    - explicit DOM API usage (getElementById, querySelector)

Usage:
  python main.py --country AE
  python main.py --all
  python main.py --all --category CHAIN     # confirmed element/JS name collisions
  python main.py --all --no-defensive
  python main.py --country DE --no-js       # HTML-only: scan for named elements
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
    One row per (country, domain, year) with category counts and risk flags.

    Key columns for longitudinal analysis:
      has_chain             - named element collides with inline JS in same page
      html_sink_count       - number of sensitive named elements
      js_reliance_count     - number of clobbering-susceptible JS patterns
      has_defense           - getElementById/querySelector usage present
      unique_clobbered_names - distinct name values involved across all findings
    """
    agg = defaultdict(lambda: {
        'html_sink': 0, 'js_reliance': 0, 'chain': 0, 'defensive': 0,
        'has_chain': False, 'has_defense': False,
        'clobbered_names': set(), 'element_tags': set(),
    })
    for f in findings:
        key = (f.country, f.domain, f.year)
        a = agg[key]
        cat = f.category
        if cat == 'HTML_SINK':
            a['html_sink'] += 1
            a['element_tags'].add(f.element_tag)
        elif cat == 'JS_RELIANCE':
            a['js_reliance'] += 1
        elif cat == 'CHAIN':
            a['chain'] += 1
            a['has_chain'] = True
        elif cat == 'DEFENSIVE':
            a['defensive'] += 1
            a['has_defense'] = True
        if f.clobbered_name:
            a['clobbered_names'].add(f.clobbered_name)

    rows = []
    for (country, domain, year), s in sorted(agg.items()):
        rows.append({
            'country': country,
            'domain': domain,
            'year': year,
            'html_sink_count': s['html_sink'],
            'js_reliance_count': s['js_reliance'],
            'chain_count': s['chain'],
            'defensive_count': s['defensive'],
            'has_chain': s['has_chain'],
            'has_defense': s['has_defense'],
            'unique_clobbered_names': len(s['clobbered_names']),
            'clobbered_names': '|'.join(sorted(s['clobbered_names'])),
            'element_tags_seen': '|'.join(sorted(s['element_tags'])),
        })
    write_csv(rows, out_path)


def main():
    ap = argparse.ArgumentParser(
        description='Detect DOM clobbering: named HTML elements that collide with JS globals.'
    )
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument('--country', metavar='CC')
    grp.add_argument('--all', action='store_true')

    ap.add_argument('--no-js', action='store_true', help='Skip standalone .js files')
    ap.add_argument('--no-html', action='store_true', help='Skip HTML files')
    ap.add_argument('--no-defensive', action='store_true',
                    help='Exclude DEFENSIVE (INFO) patterns from output')
    ap.add_argument('--category',
                    choices=['HTML_SINK', 'JS_RELIANCE', 'CHAIN', 'DEFENSIVE'],
                    help='Filter output to one category')
    ap.add_argument('--chains-only', action='store_true',
                    help='Output only CHAIN findings (named element + JS access collision)')
    ap.add_argument('--output', default=None, metavar='DIR')
    args = ap.parse_args()

    countries = get_countries(HTML_DATA_DIR) if args.all else [args.country.upper()]
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

        # HTML scan first: covers HTML_SINK, inline JS_RELIANCE, and CHAIN together
        if not args.no_html:
            html_dir = HTML_DATA_DIR / country
            html_files = sorted(html_dir.rglob('*_index_*.html')) if html_dir.exists() else []
            print(f'    HTML files: {len(html_files)}')
            for p in html_files:
                all_findings.extend(scan_html_file(p))
                total_html += 1

        # Standalone JS scan: JS_RELIANCE and DEFENSIVE only
        if not args.no_js:
            js_dir = JS_DATA_DIR / country
            js_files = sorted(js_dir.rglob('*.js')) if js_dir.exists() else []
            print(f'    JS files  : {len(js_files)}')
            for p in js_files:
                all_findings.extend(scan_js_file(p))
                total_js += 1

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
    by_name = defaultdict(int)
    domains_with_chain = set()
    domains_with_defense = set()

    for f in all_findings:
        by_cat[f.category] += 1
        by_pattern[f.pattern_label] += 1
        by_year[f.year] += 1
        if f.clobbered_name:
            by_name[f.clobbered_name] += 1
        if f.category == 'CHAIN':
            domains_with_chain.add((f.country, f.domain))
        if f.category == 'DEFENSIVE':
            domains_with_defense.add((f.country, f.domain))

    # Write outputs
    findings_path = out_dir / 'clobbering_findings.csv'
    domain_path = out_dir / 'domain_summary.csv'
    summary_path = out_dir / 'clobbering_summary.json'

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
        'top_clobbered_names': dict(sorted(by_name.items(), key=lambda x: -x[1])[:20]),
        'domains_with_chain_findings': len(domains_with_chain),
        'domains_with_defensive_patterns': len(domains_with_defense),
    }
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

    print(f'\n{"=" * 60}')
    print(f'  DOM Clobbering Detector - Results')
    print(f'{"=" * 60}')
    print(f'  Countries         : {", ".join(countries)}')
    print(f'  JS files scanned  : {total_js}')
    print(f'  HTML files scanned: {total_html}')
    print(f'  Total findings    : {len(all_findings)}')
    print()
    print('  By category:')
    for cat in ('CHAIN', 'HTML_SINK', 'JS_RELIANCE', 'DEFENSIVE'):
        print(f'    {cat:<14} {by_cat.get(cat, 0)}')
    print()
    print('  Top clobbered names:')
    for name, count in list(sorted(by_name.items(), key=lambda x: -x[1]))[:10]:
        print(f'    {count:>6}  {name}')
    print()
    print(f'  Domains with chain findings      : {len(domains_with_chain)}')
    print(f'  Domains with defensive patterns  : {len(domains_with_defense)}')
    print()
    print(f'  Findings CSV   -> {findings_path}')
    print(f'  Domain summary -> {domain_path}')
    print(f'  Summary JSON   -> {summary_path}')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
