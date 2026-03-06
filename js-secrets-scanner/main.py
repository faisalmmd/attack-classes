#!/usr/bin/env python3
"""
JS Secrets Scanner — CLI entry point.

Scans JavaScript files and HTML inline scripts from the regional longitudinal
dataset for hardcoded secrets, API keys, and credentials.

Usage examples:
  # Scan a specific country
  python main.py --country AE

  # Scan all countries, JS files only
  python main.py --all --no-html

  # Scan everything, save to custom output dir
  python main.py --all --output results/run1
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scanner import scan_js_file, scan_html_file, Finding


BASE_DIR = Path(__file__).resolve().parent.parent.parent  # subset_collected_data/
JS_DATA_DIR = BASE_DIR / 'snapshot_js_data'
HTML_DATA_DIR = BASE_DIR / 'snapshot_data'


def get_available_countries(base_dir: Path) -> list:
    if not base_dir.exists():
        return []
    return sorted(p.name for p in base_dir.iterdir()
                  if p.is_dir() and len(p.name) == 2 and p.name.isupper())


def iter_js_files(country: str) -> list:
    country_dir = JS_DATA_DIR / country
    if not country_dir.exists():
        return []
    return sorted(country_dir.rglob('*.js'))


def iter_html_files(country: str) -> list:
    country_dir = HTML_DATA_DIR / country
    if not country_dir.exists():
        return []
    return sorted(country_dir.rglob('*_index_*.html'))


def write_csv(findings: list, out_path: Path):
    if not findings:
        return
    fieldnames = list(findings[0].to_dict().keys())
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.to_dict())


def write_summary(findings: list, out_path: Path, countries: list):
    by_severity = defaultdict(int)
    by_pattern = defaultdict(int)
    by_country = defaultdict(int)
    by_year = defaultdict(int)
    domains_affected = set()

    for f in findings:
        by_severity[f.severity] += 1
        by_pattern[f.pattern_label] += 1
        by_country[f.country] += 1
        by_year[f.year] += 1
        domains_affected.add((f.country, f.domain))

    summary = {
        'generated': datetime.now().isoformat(),
        'countries_scanned': countries,
        'total_findings': len(findings),
        'unique_domains_with_findings': len(domains_affected),
        'by_severity': dict(sorted(by_severity.items())),
        'by_pattern': dict(sorted(by_pattern.items(), key=lambda x: -x[1])),
        'by_country': dict(sorted(by_country.items(), key=lambda x: -x[1])),
        'by_year': dict(sorted(by_year.items())),
    }

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

    return summary


def main():
    ap = argparse.ArgumentParser(
        description='Scan JS files and HTML inline scripts for hardcoded secrets.'
    )
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--country', metavar='CC',
                       help='Two-letter country code (e.g. AE, DE)')
    group.add_argument('--all', action='store_true',
                       help='Scan all available countries')

    ap.add_argument('--no-js', action='store_true',
                    help='Skip standalone JS files (snapshot_js_data/)')
    ap.add_argument('--no-html', action='store_true',
                    help='Skip HTML inline scripts (snapshot_data/)')
    ap.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                    default=None,
                    help='Only report findings at or above this severity level')
    ap.add_argument('--output', default=None, metavar='DIR',
                    help='Output directory (default: results/<timestamp>/)')
    args = ap.parse_args()

    # Resolve which countries to scan
    if args.all:
        countries = get_available_countries(JS_DATA_DIR)
        countries += [c for c in get_available_countries(HTML_DATA_DIR)
                      if c not in countries]
        if not countries:
            print('[!] No country directories found. Check your data paths.')
            sys.exit(1)
    else:
        countries = [args.country.upper()]

    # Output directory
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir = Path(args.output) if args.output else Path(__file__).parent / 'results' / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    SEVERITY_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    min_severity = SEVERITY_ORDER.get(args.severity, 0)

    all_findings = []
    total_js = 0
    total_html = 0

    for country in countries:
        print(f'\n[+] Scanning {country}')

        if not args.no_js:
            js_files = iter_js_files(country)
            print(f'    JS files:   {len(js_files)}')
            for path in js_files:
                findings = scan_js_file(path)
                total_js += 1
                all_findings.extend(findings)

        if not args.no_html:
            html_files = iter_html_files(country)
            print(f'    HTML files: {len(html_files)}')
            for path in html_files:
                findings = scan_html_file(path)
                total_html += 1
                all_findings.extend(findings)

    # Apply severity filter
    if args.severity:
        all_findings = [f for f in all_findings
                        if SEVERITY_ORDER.get(f.severity, 0) >= min_severity]

    # Write outputs
    csv_path = out_dir / 'secrets_findings.csv'
    summary_path = out_dir / 'secrets_summary.json'

    write_csv(all_findings, csv_path)
    summary = write_summary(all_findings, summary_path, countries)

    # Print summary
    print(f'\n{"=" * 60}')
    print(f'  JS Secrets Scanner — Results')
    print(f'{"=" * 60}')
    print(f'  Countries scanned : {", ".join(countries)}')
    print(f'  JS files scanned  : {total_js}')
    print(f'  HTML files scanned: {total_html}')
    print(f'  Total findings    : {summary["total_findings"]}')
    print(f'  Domains affected  : {summary["unique_domains_with_findings"]}')
    print()
    print('  By severity:')
    for sev, count in summary['by_severity'].items():
        print(f'    {sev:<12} {count}')
    print()
    print('  Top patterns:')
    for pat, count in list(summary['by_pattern'].items())[:8]:
        print(f'    {count:>5}  {pat}')
    print()
    print(f'  CSV     -> {csv_path}')
    print(f'  Summary -> {summary_path}')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
