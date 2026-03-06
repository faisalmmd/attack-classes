#!/usr/bin/env python3
"""
Third-Party Script Inclusion Mapper — CLI entry point.

Parses HTML snapshots for every <script src="..."> tag and classifies each
inclusion as first-party, CDN, analytics tracker, advertising tracker, social
widget, or unknown third-party. Also detects inline tracker API calls
(gtag, fbq, _gaq.push, etc.).

This directly parallels the methodology of Lerner et al. (USENIX 2016), who
used the Wayback Machine to trace tracker history from 1996 to 2016. Here we
focus on government website snapshots across 16 countries and ~20 years.

Usage examples:
  # Map a single country
  python main.py --country AE

  # Map all countries
  python main.py --all

  # Only report tracker inclusions (exclude CDN and first-party)
  python main.py --all --trackers-only
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from mapper import scan_html_file, ScriptInclusion, InlineTracker


BASE_DIR = Path(__file__).resolve().parent.parent.parent  # subset_collected_data/
SNAPSHOT_DIR = BASE_DIR / 'snapshot_data'


def get_available_countries() -> list:
    if not SNAPSHOT_DIR.exists():
        return []
    return sorted(p.name for p in SNAPSHOT_DIR.iterdir()
                  if p.is_dir() and len(p.name) == 2 and p.name.isupper())


def iter_html_files(country: str):
    country_dir = SNAPSHOT_DIR / country
    if not country_dir.exists():
        return []
    return sorted(country_dir.rglob('*_index_*.html'))


def write_csv(rows: list, out_path: Path, fieldnames=None):
    if not rows:
        return
    fn = fieldnames or list(rows[0].keys())
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fn)
        writer.writeheader()
        writer.writerows(rows)


def write_tracker_prevalence(prevalence: dict, out_path: Path):
    """
    Longitudinal table: year | tracker_name | category | count | unique_domains
    """
    rows = []
    for (year, tracker_name, category), stats in sorted(prevalence.items()):
        rows.append({
            'year': year,
            'tracker_name': tracker_name,
            'category': category,
            'occurrences': stats['count'],
            'unique_domains': len(stats['domains']),
            'unique_countries': len(stats['countries']),
        })
    rows.sort(key=lambda r: (-r['occurrences'], r['year']))
    write_csv(rows, out_path)


def write_third_party_summary(tp_stats: dict, out_path: Path):
    """
    Per year/country: how many pages had ≥1 third-party script, tracker, CDN load.
    """
    rows = []
    for (year, country), s in sorted(tp_stats.items()):
        total = s['pages']
        if total == 0:
            continue
        rows.append({
            'year': year,
            'country': country,
            'pages_scanned': total,
            'pages_with_any_third_party': s['pages_with_3p'],
            'pages_with_tracker': s['pages_with_tracker'],
            'pages_with_cdn': s['pages_with_cdn'],
            'total_script_inclusions': s['total_inclusions'],
            'total_third_party_inclusions': s['total_3p'],
            'total_tracker_inclusions': s['total_trackers'],
            'pct_pages_with_tracker': round(100 * s['pages_with_tracker'] / total, 1),
        })
    write_csv(rows, out_path)


def main():
    ap = argparse.ArgumentParser(
        description='Map third-party script inclusions and tracker usage in HTML snapshots.'
    )
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--country', metavar='CC',
                       help='Two-letter country code (e.g. AE, DE)')
    group.add_argument('--all', action='store_true',
                       help='Scan all available countries')

    ap.add_argument('--trackers-only', action='store_true',
                    help='Only output rows where is_tracker=True')
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

    ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir = Path(args.output) if args.output else Path(__file__).parent / 'results' / ts_str
    out_dir.mkdir(parents=True, exist_ok=True)

    inclusion_rows = []
    inline_tracker_rows = []

    # (year, tracker_name, category) -> { count, domains: set, countries: set }
    tracker_prevalence = defaultdict(lambda: {'count': 0, 'domains': set(), 'countries': set()})

    # (year, country) -> { pages, pages_with_3p, pages_with_tracker, pages_with_cdn,
    #                       total_inclusions, total_3p, total_trackers }
    tp_stats = defaultdict(lambda: {
        'pages': 0, 'pages_with_3p': 0, 'pages_with_tracker': 0, 'pages_with_cdn': 0,
        'total_inclusions': 0, 'total_3p': 0, 'total_trackers': 0,
    })

    total_pages = 0

    for country in countries:
        html_files = iter_html_files(country)
        print(f'[+] {country}: {len(html_files)} HTML snapshots')

        for path in html_files:
            inclusions, inline_trackers = scan_html_file(path)
            total_pages += 1

            # Aggregate stats
            year = 'UNKNOWN'
            if inclusions:
                year = inclusions[0].year
            elif inline_trackers:
                year = inline_trackers[0].year
            else:
                # Parse from filename
                import re
                m = re.match(r'(\d{4})', path.name)
                year = m.group(1) if m else 'UNKNOWN'

            key = (year, country)
            tp_stats[key]['pages'] += 1
            tp_stats[key]['total_inclusions'] += len(inclusions)

            page_has_3p = False
            page_has_tracker = False
            page_has_cdn = False

            for inc in inclusions:
                if args.trackers_only and not inc.is_tracker:
                    continue
                inclusion_rows.append(inc.to_dict())

                if inc.is_third_party:
                    page_has_3p = True
                    tp_stats[key]['total_3p'] += 1

                if inc.is_tracker:
                    page_has_tracker = True
                    tp_stats[key]['total_trackers'] += 1
                    pkey = (year, inc.tracker_name or 'Unknown', inc.tracker_category or 'UNKNOWN')
                    tracker_prevalence[pkey]['count'] += 1
                    tracker_prevalence[pkey]['domains'].add(inc.domain)
                    tracker_prevalence[pkey]['countries'].add(country)

                if inc.is_cdn:
                    page_has_cdn = True

            if page_has_3p:
                tp_stats[key]['pages_with_3p'] += 1
            if page_has_tracker:
                tp_stats[key]['pages_with_tracker'] += 1
            if page_has_cdn:
                tp_stats[key]['pages_with_cdn'] += 1

            for it in inline_trackers:
                inline_tracker_rows.append(it.to_dict())

    # Write outputs
    inclusions_path = out_dir / 'script_inclusions.csv'
    inline_path = out_dir / 'inline_trackers.csv'
    prevalence_path = out_dir / 'tracker_prevalence.csv'
    summary_path = out_dir / 'thirdparty_summary.csv'
    json_path = out_dir / 'thirdparty_overview.json'

    write_csv(inclusion_rows, inclusions_path)
    write_csv(inline_tracker_rows, inline_path)
    write_tracker_prevalence(tracker_prevalence, prevalence_path)
    write_third_party_summary(tp_stats, summary_path)

    total_trackers = sum(1 for r in inclusion_rows if r.get('is_tracker'))
    total_3p = sum(1 for r in inclusion_rows if r.get('is_third_party'))
    unique_tracker_names = len({r.get('tracker_name') for r in inclusion_rows if r.get('tracker_name')})

    overview = {
        'generated': datetime.now().isoformat(),
        'countries_scanned': countries,
        'html_snapshots_processed': total_pages,
        'total_script_inclusions': len(inclusion_rows),
        'total_third_party': total_3p,
        'total_tracker_inclusions': total_trackers,
        'unique_tracker_names': unique_tracker_names,
        'total_inline_tracker_calls': len(inline_tracker_rows),
    }
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(overview, f, indent=2)

    print(f'\n{"=" * 60}')
    print(f'  Third-Party Tracker Mapper — Results')
    print(f'{"=" * 60}')
    print(f'  Countries scanned       : {", ".join(countries)}')
    print(f'  HTML snapshots          : {total_pages}')
    print(f'  Script inclusions found : {len(inclusion_rows)}')
    print(f'  Third-party inclusions  : {total_3p}')
    print(f'  Tracker inclusions      : {total_trackers}')
    print(f'  Unique trackers seen    : {unique_tracker_names}')
    print(f'  Inline tracker calls    : {len(inline_tracker_rows)}')
    print()
    print(f'  Inclusions CSV     -> {inclusions_path}')
    print(f'  Inline trackers    -> {inline_path}')
    print(f'  Tracker prevalence -> {prevalence_path}')
    print(f'  3P summary table   -> {summary_path}')
    print(f'  Overview JSON      -> {json_path}')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
