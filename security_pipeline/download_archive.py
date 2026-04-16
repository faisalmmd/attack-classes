#!/usr/bin/env python3
"""
================================================================================
download_archive.py — Download website snapshots from the Wayback Machine
================================================================================

Usage:
    python download_archive.py example.com
    python download_archive.py example.com another-site.org
    python download_archive.py example.com --timestamps 3 --output output_web
    python download_archive.py example.com --from 2018 --to 2023

This script:
  1. Queries the Wayback Machine CDX API for available snapshots
  2. Selects timestamps (spread across the available range)
  3. Downloads files using the id_ modifier (raw content, no Wayback injection)
  4. Saves to output_web/{website}/{timestamp}/{files}
  5. Only downloads files matching the scanner's target extensions

Requirements:
    pip install requests

The id_ modifier is critical — it returns the ORIGINAL archived content
without Wayback Machine's wombat.js, toolbar, or URL rewriting injections.
This means you get clean data and the archive filter becomes a safety net
rather than a necessity.
================================================================================
"""

import os
import sys
import time
import json
import argparse
import hashlib
from urllib.parse import urlparse, quote
from collections import defaultdict

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library required. Install with:")
    print("  pip install requests")
    sys.exit(1)


# Extensions we want to download (matching the scanner)
TARGET_EXTENSIONS = {
    ".js", ".mjs", ".jsx", ".ts", ".tsx",
    ".css",
    ".xml", ".xsl", ".xslt", ".soap", ".rss", ".atom",
    ".wasm",
}

# Also download HTML for context (even though scanner doesn't scan it)
EXTRA_EXTENSIONS = {".html", ".htm"}

# CDX API endpoint
CDX_API = "https://web.archive.org/cdx/search/cdx"

# Rate limiting
REQUEST_DELAY = 1.0  # seconds between requests (be polite to IA)
MAX_RETRIES = 3


def cdx_query(url, params, retries=MAX_RETRIES):
    """Query the CDX API with retries."""
    for attempt in range(retries):
        try:
            resp = requests.get(url, params=params, timeout=30)
            if resp.status_code == 200:
                return resp.text
            elif resp.status_code == 429:
                wait = 30 * (attempt + 1)
                print(f"    Rate limited. Waiting {wait}s...")
                time.sleep(wait)
            else:
                print(f"    CDX API returned {resp.status_code}")
                time.sleep(5)
        except requests.RequestException as e:
            print(f"    Request error: {e}")
            time.sleep(5)
    return None


def get_available_timestamps(website, from_year=None, to_year=None):
    """Get available snapshot timestamps from CDX API."""
    print(f"  Querying CDX API for {website}...")

    params = {
        "url": f"{website}/*",
        "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,length",
        "filter": "statuscode:200",
        "collapse": "timestamp:6",  # One per month
        "limit": "10000",
    }

    if from_year:
        params["from"] = str(from_year)
    if to_year:
        params["to"] = str(to_year)

    text = cdx_query(CDX_API, params)
    if not text or not text.strip():
        return []

    lines = text.strip().split("\n")
    if len(lines) <= 1:
        return []

    # Parse JSON array format
    try:
        rows = json.loads(text)
        header = rows[0]
        data = rows[1:]
    except json.JSONDecodeError:
        # Fallback: space-separated
        data = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 5:
                data.append(parts)

    # Collect unique timestamps
    timestamps = sorted(set(row[0][:14] for row in data if len(row[0]) >= 14))
    print(f"  Found {len(timestamps)} unique timestamps")
    return timestamps


def select_timestamps(timestamps, count=3):
    """Select evenly-spaced timestamps from the available range."""
    if len(timestamps) <= count:
        return timestamps

    step = len(timestamps) // count
    selected = []
    for i in range(count):
        idx = min(i * step, len(timestamps) - 1)
        selected.append(timestamps[idx])

    # Always include the latest
    if timestamps[-1] not in selected:
        selected[-1] = timestamps[-1]

    return selected


def get_file_list(website, timestamp):
    """Get list of files for a specific timestamp."""
    params = {
        "url": f"{website}/*",
        "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,length",
        "filter": "statuscode:200",
        "from": timestamp,
        "to": timestamp,
        "limit": "5000",
    }

    text = cdx_query(CDX_API, params)
    if not text:
        return []

    try:
        rows = json.loads(text)
        if len(rows) <= 1:
            return []
        return rows[1:]  # Skip header
    except json.JSONDecodeError:
        return []


def download_file(url, timestamp, output_path):
    """Download a file using the id_ modifier (raw content)."""
    # id_ gives us the original content without Wayback modifications
    wayback_url = f"https://web.archive.org/web/{timestamp}id_/{url}"

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.get(wayback_url, timeout=30, stream=True)
            if resp.status_code == 200:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
                return True
            elif resp.status_code == 404:
                return False  # Not archived
            else:
                time.sleep(2)
        except requests.RequestException:
            time.sleep(2)

    return False


def url_to_filepath(url, website):
    """Convert a URL to a local file path."""
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        path = "index.html"
    # Clean up path
    path = path.replace("//", "/")
    # Remove query strings from filename
    if "?" in path:
        path = path.split("?")[0]
    return path


def download_website(website, output_dir, num_timestamps=3,
                     from_year=None, to_year=None, include_html=False):
    """Download archived snapshots of a website."""

    print(f"\n{'='*60}")
    print(f"  Downloading: {website}")
    print(f"{'='*60}")

    # Get timestamps
    timestamps = get_available_timestamps(website, from_year, to_year)
    if not timestamps:
        print(f"  ERROR: No snapshots found for {website}")
        return

    selected = select_timestamps(timestamps, num_timestamps)
    print(f"  Selected {len(selected)} timestamps:")
    for ts in selected:
        print(f"    {ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}:{ts[12:14]}")

    exts = TARGET_EXTENSIONS | (EXTRA_EXTENSIONS if include_html else set())
    total_downloaded = 0

    for ts in selected:
        print(f"\n  [{ts}] Getting file list...")
        time.sleep(REQUEST_DELAY)

        files = get_file_list(website, ts)
        if not files:
            print(f"    No files found for this timestamp")
            continue

        # Filter to target extensions
        to_download = []
        for row in files:
            if len(row) < 2:
                continue
            url = row[1]
            ext = os.path.splitext(urlparse(url).path)[1].lower()
            if ext in exts:
                to_download.append((row[0], url))  # (exact_timestamp, url)

        print(f"    {len(to_download)} target files to download")

        for i, (exact_ts, url) in enumerate(to_download, 1):
            filepath = url_to_filepath(url, website)
            output_path = os.path.join(output_dir, website, ts, filepath)

            # Skip if already downloaded
            if os.path.exists(output_path):
                continue

            print(f"    [{i}/{len(to_download)}] {filepath}", end="", flush=True)

            success = download_file(url, exact_ts, output_path)
            if success:
                size = os.path.getsize(output_path)
                print(f"  ({size:,} bytes)")
                total_downloaded += 1
            else:
                print(f"  FAILED")

            time.sleep(REQUEST_DELAY)

    print(f"\n  Done: {total_downloaded} files downloaded for {website}")
    return total_downloaded


def main():
    parser = argparse.ArgumentParser(
        description="Download website snapshots from the Wayback Machine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download 3 snapshots of example.com
  python download_archive.py example.com

  # Download 2 sites, 5 snapshots each
  python download_archive.py example.com evil-shop.org --timestamps 5

  # Download from specific year range
  python download_archive.py example.com --from 2018 --to 2023

  # Include HTML files too (scanner doesn't check these but useful for context)
  python download_archive.py example.com --include-html

  # Custom output directory
  python download_archive.py example.com --output my_archive

After downloading, scan with:
  python scan_archive.py output_web/
        """,
    )

    parser.add_argument("websites", nargs="+",
                        help="Website domain(s) to download (e.g., example.com)")
    parser.add_argument("--output", "-o", default="output_web",
                        help="Output directory (default: output_web)")
    parser.add_argument("--timestamps", "-t", type=int, default=3,
                        help="Number of snapshots per site (default: 3)")
    parser.add_argument("--from", dest="from_year", type=int,
                        help="Start year (e.g., 2018)")
    parser.add_argument("--to", dest="to_year", type=int,
                        help="End year (e.g., 2023)")
    parser.add_argument("--include-html", action="store_true",
                        help="Also download HTML files")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Seconds between requests (default: 1.0, be polite)")

    args = parser.parse_args()

    global REQUEST_DELAY
    REQUEST_DELAY = args.delay

    os.makedirs(args.output, exist_ok=True)

    total = 0
    for website in args.websites:
        # Clean up website name
        website = website.strip("/").replace("https://", "").replace("http://", "")

        count = download_website(
            website, args.output,
            num_timestamps=args.timestamps,
            from_year=args.from_year,
            to_year=args.to_year,
            include_html=args.include_html,
        )
        if count:
            total += count

    print(f"\n{'='*60}")
    print(f"  DOWNLOAD COMPLETE")
    print(f"  Total files: {total}")
    print(f"  Output: {os.path.abspath(args.output)}/")
    print(f"{'='*60}")
    print(f"\n  Next step — scan for vulnerabilities:")
    print(f"  python scan_archive.py {args.output}/")
    print()


if __name__ == "__main__":
    main()
