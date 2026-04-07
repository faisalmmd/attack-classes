#!/usr/bin/env python3
"""
Convert zip sample archives to the snapshot_data / snapshot_js_data format
expected by the analysis pipeline.

Input zip structure:
  output/{domain}/years/{year}/{timestamp}/page.html
  output/{domain}/years/{year}/{timestamp}/meta.txt
  output/{domain}/years/{year}/{timestamp}/assets/{domain_path}.js|css

Output structure:
  snapshot_data/{CC}/{domain_underscored}/{year}_index_{domain_underscored}_{ts}.html
  snapshot_data/{CC}/{domain_underscored}/{year}_headers_{domain_underscored}_{ts}.json
  snapshot_js_data/{CC}/{domain_underscored}/{year}_{ts}_script_{N}.js

Notes:
  - No HTTP headers are present in the zip data; empty JSON objects are written
    so header-dependent tools degrade gracefully instead of crashing.
  - country_code must be exactly 2 uppercase chars so the tools' country
    detection (len == 2 and isupper()) picks it up correctly.
  - Only .js asset files are copied to snapshot_js_data; .css files are skipped.

Usage:
  python convert_zips_to_snapshot_format.py --zip sub01_sample_archive_files.zip --country S1
  python convert_zips_to_snapshot_format.py --zip sub04_sample_archive_files.zip --country S4
  python convert_zips_to_snapshot_format.py --all
"""

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # subset_collected_data
SNAPSHOT_DATA_DIR = BASE_DIR / 'snapshot_data'
SNAPSHOT_JS_DIR = BASE_DIR / 'snapshot_js_data'

ZIPS = {
    'S1': Path(__file__).resolve().parent / 'sub01_sample_archive_files.zip',
    'S4': Path(__file__).resolve().parent / 'sub04_sample_archive_files.zip',
}

# Match output/{domain}/years/{year}/{timestamp}/...
_ENTRY_RE = re.compile(
    r'^output/([^/]+)/years/(\d{4})/(\d{8,14})/(.+)$'
)


def domain_to_dir(domain: str) -> str:
    """chatgpt.com -> chatgpt_com"""
    return re.sub(r'[^\w]', '_', domain).strip('_')


def convert_zip(zip_path: Path, country_code: str, dry_run: bool = False) -> dict:
    stats = {'html': 0, 'js': 0, 'headers': 0, 'skipped': 0}

    with zipfile.ZipFile(zip_path, 'r') as zf:
        entries = zf.namelist()
        print(f'\n[+] {zip_path.name} -> country={country_code}  ({len(entries)} zip entries)')

        # Group entries by (domain, year, timestamp)
        snapshots: dict = {}
        for entry in entries:
            m = _ENTRY_RE.match(entry)
            if not m:
                continue
            domain, year, ts, rel = m.group(1), m.group(2), m.group(3), m.group(4)
            key = (domain, year, ts)
            snapshots.setdefault(key, []).append((entry, rel))

        print(f'    Snapshots found: {len(snapshots)}')

        for (domain, year, ts), files in sorted(snapshots.items()):
            domain_dir = domain_to_dir(domain)

            html_out_dir = SNAPSHOT_DATA_DIR / country_code / domain_dir
            js_out_dir = SNAPSHOT_JS_DIR / country_code / domain_dir

            if not dry_run:
                html_out_dir.mkdir(parents=True, exist_ok=True)

            # --- HTML file ---
            html_src = f'output/{domain}/years/{year}/{ts}/page.html'
            html_dst = html_out_dir / f'{year}_index_{domain_dir}_{ts}.html'

            if html_src in [e for e, _ in files]:
                if not dry_run:
                    data = zf.read(html_src)
                    html_dst.write_bytes(data)
                stats['html'] += 1
                print(f'    [HTML] {html_dst.name}')

            # --- Empty headers JSON (no HTTP headers in zip data) ---
            headers_dst = html_out_dir / f'{year}_headers_{domain_dir}_{ts}.json'
            if not dry_run and not headers_dst.exists():
                headers_dst.write_text('{}', encoding='utf-8')
            stats['headers'] += 1

            # --- JS assets ---
            js_files = [
                (entry, rel) for entry, rel in files
                if rel.startswith('assets/') and rel.lower().endswith('.js')
            ]
            if js_files and not dry_run:
                js_out_dir.mkdir(parents=True, exist_ok=True)

            for n, (entry, rel) in enumerate(js_files, start=1):
                # Preserve original asset filename for traceability but use
                # the pipeline's script_N naming convention.
                js_dst = js_out_dir / f'{year}_{ts}_script_{n}.js'
                if not dry_run:
                    js_data = zf.read(entry)
                    js_dst.write_bytes(js_data)
                stats['js'] += 1

            if js_files:
                print(f'    [ JS ] {len(js_files)} assets for {domain}/{year}/{ts}')

    return stats


def main():
    ap = argparse.ArgumentParser(
        description='Convert zip sample archives to snapshot_data/snapshot_js_data format.'
    )
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument('--all', action='store_true', help='Convert both zips (S1 and S4)')
    grp.add_argument('--zip', metavar='PATH', help='Path to a single zip file')
    ap.add_argument('--country', metavar='CC', help='2-letter country code (required with --zip)')
    ap.add_argument('--dry-run', action='store_true', help='Show what would be done without writing')
    args = ap.parse_args()

    if args.all:
        jobs = list(ZIPS.items())
    else:
        if not args.country:
            ap.error('--country is required when using --zip')
        cc = args.country.upper()
        if len(cc) != 2:
            ap.error('Country code must be exactly 2 characters')
        jobs = [(cc, Path(args.zip))]

    total = {'html': 0, 'js': 0, 'headers': 0}

    for cc, zpath in jobs:
        if not zpath.exists():
            print(f'[!] Zip not found: {zpath}', file=sys.stderr)
            continue
        stats = convert_zip(zpath, cc, dry_run=args.dry_run)
        for k in total:
            total[k] += stats[k]

    print(f'\n{"=" * 50}')
    mode = 'DRY RUN' if args.dry_run else 'DONE'
    print(f'  {mode}')
    print(f'  HTML files written  : {total["html"]}')
    print(f'  Headers JSON created: {total["headers"]}')
    print(f'  JS files written    : {total["js"]}')
    print(f'  snapshot_data ->  {SNAPSHOT_DATA_DIR}')
    print(f'  snapshot_js_data -> {SNAPSHOT_JS_DIR}')
    print(f'{"=" * 50}')


if __name__ == '__main__':
    main()
