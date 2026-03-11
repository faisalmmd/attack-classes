#!/usr/bin/env python3
"""
High-Risk Browser API Detector - CLI entry point.

Scans JS files and HTML inline scripts for usage of browser APIs that carry
elevated privacy or security risk (Geolocation, getUserMedia, WebRTC, etc.).
Also checks HTTP response headers for Permissions-Policy / Feature-Policy.

Usage:
  python main.py --country AE
  python main.py --all
  python main.py --all --category PRIVACY
  python main.py --all --severity HIGH --no-html
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from detector import scan_js_file, scan_html_file, check_header_policy


BASE_DIR = Path(__file__).resolve().parent.parent.parent
JS_DATA_DIR = BASE_DIR / 'snapshot_js_data'
HTML_DATA_DIR = BASE_DIR / 'snapshot_data'

SEVERITY_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
CATEGORIES = {'PRIVACY', 'SECURITY', 'FINGERPRINTING', 'SENSOR'}


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


def write_summary(findings, header_results, out_path, countries):
    by_api = defaultdict(int)
    by_category = defaultdict(int)
    by_severity = defaultdict(int)
    by_year = defaultdict(int)
    by_country = defaultdict(int)
    domains_affected = set()

    for f in findings:
        by_api[f.api_label] += 1
        by_category[f.category] += 1
        by_severity[f.severity] += 1
        by_year[f.year] += 1
        by_country[f.country] += 1
        domains_affected.add((f.country, f.domain))

    no_policy = sum(1 for r in header_results if not r.header_found)
    has_policy = len(header_results) - no_policy

    summary = {
        'generated': datetime.now().isoformat(),
        'countries_scanned': countries,
        'total_api_findings': len(findings),
        'unique_domains_with_findings': len(domains_affected),
        'by_api': dict(sorted(by_api.items(), key=lambda x: -x[1])),
        'by_category': dict(sorted(by_category.items(), key=lambda x: -x[1])),
        'by_severity': dict(sorted(by_severity.items())),
        'by_year': dict(sorted(by_year.items())),
        'by_country': dict(sorted(by_country.items(), key=lambda x: -x[1])),
        'permissions_policy': {
            'headers_found': has_policy,
            'no_policy': no_policy,
            'total_checked': len(header_results),
        },
    }
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    return summary


def main():
    ap = argparse.ArgumentParser(
        description='Detect high-risk browser API usage in archived JS and HTML.'
    )
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument('--country', metavar='CC')
    grp.add_argument('--all', action='store_true')

    ap.add_argument('--no-js', action='store_true', help='Skip .js files')
    ap.add_argument('--no-html', action='store_true', help='Skip HTML inline scripts')
    ap.add_argument('--no-headers', action='store_true', help='Skip header policy check')
    ap.add_argument('--category', choices=list(CATEGORIES),
                    help='Filter to a specific API category')
    ap.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH'],
                    help='Minimum severity level')
    ap.add_argument('--output', default=None, metavar='DIR')
    args = ap.parse_args()

    countries = get_countries(JS_DATA_DIR) if args.all else [args.country.upper()]
    if not countries:
        print('[!] No country directories found.')
        sys.exit(1)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir = Path(args.output) if args.output else Path(__file__).parent / 'results' / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    min_sev = SEVERITY_ORDER.get(args.severity, 0) if args.severity else 0

    all_findings = []
    header_results = []
    total_js = total_html = total_headers = 0

    for country in countries:
        print(f'\n[+] {country}')

        if not args.no_js:
            js_files = sorted((JS_DATA_DIR / country).rglob('*.js')) if (JS_DATA_DIR / country).exists() else []
            print(f'    JS files  : {len(js_files)}')
            for p in js_files:
                all_findings.extend(scan_js_file(p))
                total_js += 1

        if not args.no_html:
            html_files = sorted((HTML_DATA_DIR / country).rglob('*_index_*.html')) if (HTML_DATA_DIR / country).exists() else []
            print(f'    HTML files: {len(html_files)}')
            for p in html_files:
                all_findings.extend(scan_html_file(p))
                total_html += 1

        if not args.no_headers:
            header_files = sorted((HTML_DATA_DIR / country).rglob('*_headers_*.json')) if (HTML_DATA_DIR / country).exists() else []
            print(f'    Headers   : {len(header_files)}')
            for p in header_files:
                try:
                    import json as _json
                    headers = _json.loads(p.read_text(encoding='utf-8', errors='replace'))
                    result = check_header_policy(p, headers)
                    if result:
                        header_results.append(result)
                        total_headers += 1
                except Exception:
                    pass

    # Apply filters
    if args.category:
        all_findings = [f for f in all_findings if f.category == args.category]
    if args.severity:
        all_findings = [f for f in all_findings
                        if SEVERITY_ORDER.get(f.severity, 0) >= min_sev]

    # Write outputs
    findings_path = out_dir / 'api_findings.csv'
    headers_path = out_dir / 'permissions_policy.csv'
    summary_path = out_dir / 'api_summary.json'

    write_csv([f.to_dict() for f in all_findings], findings_path)
    write_csv([r.to_dict() for r in header_results], headers_path)
    summary = write_summary(all_findings, header_results, summary_path, countries)

    print(f'\n{"=" * 60}')
    print(f'  High-Risk Browser API Detector - Results')
    print(f'{"=" * 60}')
    print(f'  Countries         : {", ".join(countries)}')
    print(f'  JS files scanned  : {total_js}')
    print(f'  HTML files scanned: {total_html}')
    print(f'  Header files      : {total_headers}')
    print(f'  API findings      : {summary["total_api_findings"]}')
    print(f'  Domains affected  : {summary["unique_domains_with_findings"]}')
    print()
    print('  By API:')
    for api, count in list(summary['by_api'].items())[:10]:
        print(f'    {count:>5}  {api}')
    print()
    print('  Permissions-Policy header:')
    pp = summary['permissions_policy']
    print(f'    Present  : {pp["headers_found"]} / {pp["total_checked"]} files')
    print(f'    Absent   : {pp["no_policy"]} files')
    print()
    print(f'  API findings CSV    -> {findings_path}')
    print(f'  Header policy CSV   -> {headers_path}')
    print(f'  Summary JSON        -> {summary_path}')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
