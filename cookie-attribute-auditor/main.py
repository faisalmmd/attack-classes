#!/usr/bin/env python3
"""
Cookie Attribute Auditor — CLI entry point.

Parses Set-Cookie headers from archived HTTP response JSON files and audits
each cookie for the three core security attributes: HttpOnly, Secure, and
SameSite. Produces per-cookie findings and longitudinal adoption summaries.

Usage examples:
  # Audit a specific country
  python main.py --country AE

  # Audit all countries
  python main.py --all

  # Only report session-like cookies missing HttpOnly
  python main.py --all --risk NO_HTTPONLY_SESSION
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from auditor import extract_cookies_from_headers, CookieRecord


BASE_DIR = Path(__file__).resolve().parent.parent.parent  # subset_collected_data/
SNAPSHOT_DIR = BASE_DIR / 'snapshot_data'


def get_available_countries() -> list:
    if not SNAPSHOT_DIR.exists():
        return []
    return sorted(p.name for p in SNAPSHOT_DIR.iterdir()
                  if p.is_dir() and len(p.name) == 2 and p.name.isupper())


def iter_header_files(country: str):
    country_dir = SNAPSHOT_DIR / country
    if not country_dir.exists():
        return []
    return sorted(country_dir.rglob('*_headers_*.json'))


def parse_provenance(path: Path):
    """Extract country, domain, year, timestamp from file path."""
    parts = path.parts
    country = 'UNKNOWN'
    domain = path.parent.name

    for i, part in enumerate(parts):
        if len(part) == 2 and part.isupper():
            country = part
            if i + 1 < len(parts):
                domain = parts[i + 1]
            break

    name = path.stem
    tokens = name.split('_')
    year = tokens[0] if tokens and tokens[0].isdigit() and len(tokens[0]) == 4 else 'UNKNOWN'

    import re
    ts_match = re.search(r'(\d{14})', name)
    timestamp = ts_match.group(1) if ts_match else 'UNKNOWN'

    return country, domain, year, timestamp


def write_findings_csv(rows: list, out_path: Path):
    if not rows:
        return
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def write_adoption_csv(adoption: dict, out_path: Path):
    """
    Write a longitudinal adoption table:
    year | country | total_cookies | pct_httponly | pct_secure | pct_samesite
    """
    rows = []
    for (year, country), stats in sorted(adoption.items()):
        total = stats['total']
        if total == 0:
            continue
        rows.append({
            'year': year,
            'country': country,
            'total_cookies': total,
            'with_httponly': stats['httponly'],
            'with_secure': stats['secure'],
            'with_samesite': stats['samesite'],
            'pct_httponly': round(100 * stats['httponly'] / total, 1),
            'pct_secure': round(100 * stats['secure'] / total, 1),
            'pct_samesite': round(100 * stats['samesite'] / total, 1),
            'samesite_strict': stats['samesite_strict'],
            'samesite_lax': stats['samesite_lax'],
            'samesite_none': stats['samesite_none'],
            'session_cookies': stats['session_like'],
            'session_no_httponly': stats['session_no_httponly'],
        })

    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        if not rows:
            return
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def main():
    ap = argparse.ArgumentParser(
        description='Audit Set-Cookie headers for HttpOnly, Secure, and SameSite.'
    )
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--country', metavar='CC',
                       help='Two-letter country code (e.g. AE, DE)')
    group.add_argument('--all', action='store_true',
                       help='Audit all available countries')

    ap.add_argument('--risk', metavar='FLAG', default=None,
                    help='Filter output to a specific risk flag (e.g. NO_HTTPONLY_SESSION)')
    ap.add_argument('--output', default=None, metavar='DIR',
                    help='Output directory (default: results/<timestamp>/)')
    args = ap.parse_args()

    if args.all:
        countries = get_available_countries()
        if not countries:
            print('[!] No country directories found.')
            sys.exit(1)
    else:
        countries = [args.country.upper()]

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir = Path(args.output) if args.output else Path(__file__).parent / 'results' / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    all_rows = []
    # (year, country) -> { httponly, secure, samesite, samesite_strict, samesite_lax,
    #                       samesite_none, total, session_like, session_no_httponly }
    adoption = defaultdict(lambda: {
        'httponly': 0, 'secure': 0, 'samesite': 0,
        'samesite_strict': 0, 'samesite_lax': 0, 'samesite_none': 0,
        'total': 0, 'session_like': 0, 'session_no_httponly': 0,
    })

    total_files = 0
    total_cookies = 0

    for country in countries:
        header_files = iter_header_files(country)
        print(f'[+] {country}: {len(header_files)} header files')

        for path in header_files:
            country_p, domain, year, timestamp = parse_provenance(path)

            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    headers = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            total_files += 1
            cookies_found = extract_cookies_from_headers(headers)

            for source_key, record in cookies_found:
                total_cookies += 1
                key = (year, country_p)
                s = adoption[key]
                s['total'] += 1

                if record.httponly:
                    s['httponly'] += 1
                if record.secure:
                    s['secure'] += 1
                if record.samesite is not None:
                    s['samesite'] += 1
                    if record.samesite == 'strict':
                        s['samesite_strict'] += 1
                    elif record.samesite == 'lax':
                        s['samesite_lax'] += 1
                    elif record.samesite == 'none':
                        s['samesite_none'] += 1
                if record.is_session_like:
                    s['session_like'] += 1
                    if not record.httponly:
                        s['session_no_httponly'] += 1

                row = {
                    'country': country_p,
                    'domain': domain,
                    'year': year,
                    'timestamp': timestamp,
                    'source_file': path.name,
                    'header_source': source_key,
                    'cookie_name': record.name,
                    'value_hash': record.value_hash,
                    'value_length': record.value_length,
                    'secure': record.secure,
                    'httponly': record.httponly,
                    'samesite': record.samesite or '',
                    'domain_attr': record.domain or '',
                    'path_attr': record.path or '',
                    'has_max_age': record.max_age is not None,
                    'has_expires': record.has_expires,
                    'is_session_like': record.is_session_like,
                    'risks': '|'.join(record.risks),
                }
                all_rows.append(row)

    # Apply risk filter if requested
    if args.risk:
        all_rows = [r for r in all_rows if args.risk in r.get('risks', '')]

    # Write outputs
    findings_path = out_dir / 'cookie_findings.csv'
    adoption_path = out_dir / 'adoption_over_time.csv'
    summary_path = out_dir / 'cookie_summary.json'

    write_findings_csv(all_rows, findings_path)
    write_adoption_csv(adoption, adoption_path)

    summary = {
        'generated': datetime.now().isoformat(),
        'countries_scanned': countries,
        'header_files_processed': total_files,
        'total_cookies_found': total_cookies,
        'total_findings_after_filter': len(all_rows),
        'risk_filter_applied': args.risk,
    }
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

    # Print summary
    print(f'\n{"=" * 60}')
    print(f'  Cookie Attribute Auditor — Results')
    print(f'{"=" * 60}')
    print(f'  Countries   : {", ".join(countries)}')
    print(f'  Files parsed: {total_files}')
    print(f'  Cookies found: {total_cookies}')
    if args.risk:
        print(f'  Risk filter : {args.risk} ({len(all_rows)} matches)')
    print()

    # Overall attribute adoption
    if total_cookies > 0:
        tot_ho = sum(s['httponly'] for s in adoption.values())
        tot_sec = sum(s['secure'] for s in adoption.values())
        tot_ss = sum(s['samesite'] for s in adoption.values())
        print(f'  Overall adoption across all years/countries:')
        print(f'    HttpOnly  : {tot_ho}/{total_cookies} ({100*tot_ho//total_cookies}%)')
        print(f'    Secure    : {tot_sec}/{total_cookies} ({100*tot_sec//total_cookies}%)')
        print(f'    SameSite  : {tot_ss}/{total_cookies} ({100*tot_ss//total_cookies}%)')

    print()
    print(f'  Findings CSV      -> {findings_path}')
    print(f'  Adoption over time-> {adoption_path}')
    print(f'  Summary JSON      -> {summary_path}')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
