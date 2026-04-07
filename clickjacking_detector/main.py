#!/usr/bin/env python3
"""
Clickjacking Detection Tool

CLI tool for analyzing archived HTML files for clickjacking vulnerabilities.
Generates CSV reports suitable for temporal/longitudinal analysis.

Usage:
    python main.py --input-dir ./archive_data --output report.csv
    python main.py --input-file page.html --headers headers.txt
    python main.py --input-dir ./data --output report.csv --verbose
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Generator
from datetime import datetime
import csv
import logging

import pandas as pd

from analyzer import ClickjackingAnalyzer, BatchAnalyzer, VulnerabilityReport


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_headers_file(headers_path: str) -> Dict[str, str]:
    """
    Parse HTTP headers from a text file.

    Supports formats:
    - Header-Name: value
    - Header-Name=value
    - JSON format

    Args:
        headers_path: Path to headers file

    Returns:
        Dictionary of headers
    """
    headers = {}

    try:
        with open(headers_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        # Try JSON first
        if content.startswith('{'):
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                pass

        # Parse line by line
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Try colon separator
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            # Try equals separator
            elif '=' in line:
                key, value = line.split('=', 1)
                headers[key.strip()] = value.strip()

    except Exception as e:
        logger.warning(f"Failed to parse headers file {headers_path}: {e}")

    return headers


def parse_metadata_file(metadata_path: str) -> Dict[str, Any]:
    """
    Parse metadata from a JSON file.

    Args:
        metadata_path: Path to metadata JSON file

    Returns:
        Dictionary of metadata
    """
    try:
        with open(metadata_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to parse metadata file {metadata_path}: {e}")
        return {}


def find_associated_files(html_path: Path) -> Dict[str, Optional[Path]]:
    """
    Find header and metadata files associated with an HTML file.

    Looks for:
    - {name}.headers, {name}_headers.txt, {name}.headers.json
    - {name}.json, {name}_metadata.json

    Args:
        html_path: Path to HTML file

    Returns:
        Dictionary with 'headers' and 'metadata' paths
    """
    stem = html_path.stem
    parent = html_path.parent

    result = {'headers': None, 'metadata': None}

    # Look for headers file
    # Also handles pipeline naming: {year}_index_{domain}_{ts}.html
    # -> {year}_headers_{domain}_{ts}.json
    pipeline_headers = stem.replace('_index_', '_headers_') + '.json'
    header_patterns = [
        pipeline_headers,
        f"{stem}.headers",
        f"{stem}_headers.txt",
        f"{stem}.headers.txt",
        f"{stem}.headers.json",
    ]
    for pattern in header_patterns:
        path = parent / pattern
        if path.exists():
            result['headers'] = path
            break

    # Look for metadata file
    metadata_patterns = [
        f"{stem}.json",
        f"{stem}_metadata.json",
        f"{stem}.metadata.json",
    ]
    for pattern in metadata_patterns:
        path = parent / pattern
        if path.exists():
            result['metadata'] = path
            break

    return result


def scan_directory(directory: str,
                   recursive: bool = True) -> Generator[Dict[str, Any], None, None]:
    """
    Scan directory for HTML files and their associated metadata.

    Args:
        directory: Directory to scan
        recursive: Whether to scan subdirectories

    Yields:
        Dictionaries with html_content, headers, metadata
    """
    dir_path = Path(directory)

    if recursive:
        html_files = list(dir_path.rglob('*.html')) + list(dir_path.rglob('*.htm'))
    else:
        html_files = list(dir_path.glob('*.html')) + list(dir_path.glob('*.htm'))

    logger.info(f"Found {len(html_files)} HTML files in {directory}")

    for html_path in html_files:
        try:
            # Read HTML content
            with open(html_path, 'r', encoding='utf-8', errors='replace') as f:
                html_content = f.read()

            # Find associated files
            associated = find_associated_files(html_path)

            # Parse headers
            headers = {}
            if associated['headers']:
                headers = parse_headers_file(str(associated['headers']))

            # Parse metadata
            metadata = {'url': str(html_path), 'file_path': str(html_path)}
            if associated['metadata']:
                metadata.update(parse_metadata_file(str(associated['metadata'])))

            # Try to extract timestamp from filename if not in metadata
            if 'timestamp' not in metadata and 'capture_date' not in metadata:
                # Common patterns: 20200101_page.html, page_2020-01-01.html
                import re
                date_match = re.search(r'(\d{4})[-_]?(\d{2})[-_]?(\d{2})', html_path.stem)
                if date_match:
                    metadata['capture_date'] = f"{date_match.group(1)}-{date_match.group(2)}-{date_match.group(3)}"

            yield {
                'html_content': html_content,
                'headers': headers,
                'metadata': metadata
            }

        except Exception as e:
            logger.error(f"Error processing {html_path}: {e}")
            continue


def analyze_single_file(html_path: str,
                        headers_path: Optional[str] = None,
                        metadata_path: Optional[str] = None,
                        metadata_json: Optional[str] = None) -> VulnerabilityReport:
    """
    Analyze a single HTML file.

    Args:
        html_path: Path to HTML file
        headers_path: Optional path to headers file
        metadata_path: Optional path to metadata JSON file
        metadata_json: Optional inline JSON metadata

    Returns:
        VulnerabilityReport
    """
    # Read HTML
    with open(html_path, 'r', encoding='utf-8', errors='replace') as f:
        html_content = f.read()

    # Get headers
    headers = {}
    if headers_path:
        headers = parse_headers_file(headers_path)
    else:
        # Try to find associated headers file
        associated = find_associated_files(Path(html_path))
        if associated['headers']:
            headers = parse_headers_file(str(associated['headers']))

    # Get metadata
    metadata = {'url': html_path, 'file_path': html_path}
    if metadata_path:
        metadata.update(parse_metadata_file(metadata_path))
    elif metadata_json:
        try:
            metadata.update(json.loads(metadata_json))
        except json.JSONDecodeError:
            pass
    else:
        # Try to find associated metadata file
        associated = find_associated_files(Path(html_path))
        if associated['metadata']:
            metadata.update(parse_metadata_file(str(associated['metadata'])))

    # Analyze
    analyzer = ClickjackingAnalyzer()
    return analyzer.analyze_page(html_content, headers, metadata)


def write_csv_report(reports: List[VulnerabilityReport],
                     output_path: str,
                     include_details: bool = False):
    """
    Write analysis reports to CSV file.

    Args:
        reports: List of VulnerabilityReport objects
        output_path: Output CSV file path
        include_details: Whether to include detailed JSON in output
    """
    rows = []
    for report in reports:
        row = report.to_csv_row()
        if not include_details:
            row.pop('details', None)
        rows.append(row)

    df = pd.DataFrame(rows)

    # Reorder columns for readability
    column_order = [
        'url', 'timestamp', 'capture_date', 'vulnerable', 'risk_level',
        'vulnerability_score', 'total_frames', 'transparent_frames',
        'cross_domain_frames', 'suspicious_frames', 'overlapping_elements',
        'high_value_targets_at_risk', 'has_xframe_options', 'xframe_options_value',
        'has_csp_frame_ancestors', 'has_framebusting_js', 'framebusting_patterns_count',
        'defense_score', 'defense_level', 'analysis_date'
    ]
    if include_details:
        column_order.append('details')

    # Only include columns that exist
    column_order = [c for c in column_order if c in df.columns]
    df = df[column_order]

    df.to_csv(output_path, index=False)
    logger.info(f"Report written to {output_path}")


def write_json_report(reports: List[VulnerabilityReport],
                      output_path: str):
    """
    Write analysis reports to JSON file.

    Args:
        reports: List of VulnerabilityReport objects
        output_path: Output JSON file path
    """
    data = {
        'analysis_date': datetime.now().isoformat(),
        'total_pages': len(reports),
        'vulnerable_pages': sum(1 for r in reports if r.vulnerable),
        'reports': [r.to_dict() for r in reports]
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)

    logger.info(f"JSON report written to {output_path}")


def print_summary(reports: List[VulnerabilityReport]):
    """Print summary statistics to console."""
    total = len(reports)
    if total == 0:
        print("No pages analyzed.")
        return

    vulnerable = sum(1 for r in reports if r.vulnerable)
    risk_counts = {}
    for r in reports:
        risk_counts[r.risk_level] = risk_counts.get(r.risk_level, 0) + 1

    print("\n" + "=" * 60)
    print("CLICKJACKING ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total pages analyzed: {total}")
    print(f"Vulnerable pages: {vulnerable} ({vulnerable/total*100:.1f}%)")
    print(f"\nRisk level distribution:")
    for level in ['critical', 'high', 'medium', 'low', 'none']:
        count = risk_counts.get(level, 0)
        print(f"  {level.upper():10} {count:5} ({count/total*100:.1f}%)")

    # Defense adoption
    with_xfo = sum(1 for r in reports if r.has_xframe_options)
    with_csp = sum(1 for r in reports if r.has_csp_frame_ancestors)
    with_fb = sum(1 for r in reports if r.has_framebusting_js)

    print(f"\nDefense mechanisms:")
    print(f"  X-Frame-Options:      {with_xfo:5} ({with_xfo/total*100:.1f}%)")
    print(f"  CSP frame-ancestors:  {with_csp:5} ({with_csp/total*100:.1f}%)")
    print(f"  Frame-busting JS:     {with_fb:5} ({with_fb/total*100:.1f}%)")

    # Frame statistics
    with_frames = sum(1 for r in reports if r.total_frames > 0)
    with_suspicious = sum(1 for r in reports if r.suspicious_frames > 0)

    print(f"\nFrame analysis:")
    print(f"  Pages with frames:      {with_frames:5} ({with_frames/total*100:.1f}%)")
    print(f"  Pages with suspicious:  {with_suspicious:5} ({with_suspicious/total*100:.1f}%)")

    print("=" * 60 + "\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Clickjacking vulnerability detector for archived HTML files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze single file:
    python main.py --input-file page.html

  Analyze directory:
    python main.py --input-dir ./archive_data --output report.csv

  Analyze with headers:
    python main.py --input-file page.html --headers headers.txt

  Analyze with metadata:
    python main.py --input-file page.html --metadata '{"url": "http://example.gov", "timestamp": "2020-01-01"}'

  Full analysis with JSON output:
    python main.py --input-dir ./data -o report.csv --json-output report.json --verbose
"""
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--input-file', '-f',
        help='Single HTML file to analyze'
    )
    input_group.add_argument(
        '--input-dir', '-d',
        help='Directory containing HTML files to analyze'
    )

    # Output options
    parser.add_argument(
        '--output', '-o',
        help='Output CSV file path (default: clickjacking_report.csv)',
        default='clickjacking_report.csv'
    )
    parser.add_argument(
        '--json-output', '-j',
        help='Optional JSON output file path for detailed results'
    )

    # Additional input options
    parser.add_argument(
        '--headers',
        help='Path to headers file (for single file analysis)'
    )
    parser.add_argument(
        '--metadata',
        help='JSON metadata string (for single file analysis)'
    )
    parser.add_argument(
        '--metadata-file',
        help='Path to metadata JSON file (for single file analysis)'
    )

    # Processing options
    parser.add_argument(
        '--no-recursive', '-nr',
        action='store_true',
        help='Do not recursively scan subdirectories'
    )
    parser.add_argument(
        '--include-details',
        action='store_true',
        help='Include detailed JSON in CSV output'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress summary output'
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    reports = []

    if args.input_file:
        # Single file analysis
        logger.info(f"Analyzing single file: {args.input_file}")
        report = analyze_single_file(
            args.input_file,
            headers_path=args.headers,
            metadata_path=args.metadata_file,
            metadata_json=args.metadata
        )
        reports.append(report)

        # Print single file result
        print(f"\nAnalysis of: {args.input_file}")
        print(f"  Vulnerable: {report.vulnerable}")
        print(f"  Risk Level: {report.risk_level}")
        print(f"  Score: {report.vulnerability_score}")
        print(f"  Frames: {report.total_frames} total, {report.suspicious_frames} suspicious")
        print(f"  Defenses: XFO={report.has_xframe_options}, CSP={report.has_csp_frame_ancestors}, JS={report.has_framebusting_js}")

        if report.details.get('findings'):
            print(f"\n  Findings:")
            for finding in report.details['findings']:
                print(f"    - {finding}")

        if report.details.get('recommendations'):
            print(f"\n  Recommendations:")
            for rec in report.details['recommendations']:
                print(f"    - {rec}")

    else:
        # Directory analysis
        logger.info(f"Scanning directory: {args.input_dir}")

        analyzer = ClickjackingAnalyzer()
        processed = 0

        for page_data in scan_directory(args.input_dir, recursive=not args.no_recursive):
            try:
                report = analyzer.analyze_page(
                    html_content=page_data['html_content'],
                    headers=page_data['headers'],
                    metadata=page_data['metadata']
                )
                reports.append(report)
                processed += 1

                if args.verbose and processed % 100 == 0:
                    logger.info(f"Processed {processed} files...")

            except Exception as e:
                logger.error(f"Error analyzing {page_data['metadata'].get('file_path', 'unknown')}: {e}")

        logger.info(f"Completed analysis of {processed} files")

    # Write reports
    if reports:
        write_csv_report(reports, args.output, include_details=args.include_details)

        if args.json_output:
            write_json_report(reports, args.json_output)

        if not args.quiet and len(reports) > 1:
            print_summary(reports)

    return 0


if __name__ == '__main__':
    sys.exit(main())
