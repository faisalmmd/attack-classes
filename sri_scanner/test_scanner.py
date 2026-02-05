#!/usr/bin/env python3
"""
Quick test script for SRI Scanner
Tests on a small sample of files from different countries
"""

import sys
from pathlib import Path
from scanner import SRIScanner, HTMLSnapshot


def test_single_file(html_file: Path):
    """Test parsing a single HTML file"""
    print(f"\nTesting file: {html_file.name}")
    print("-" * 60)

    snapshot = HTMLSnapshot(html_file)
    if snapshot.parse():
        print(f"Country: {snapshot.country}")
        print(f"Domain: {snapshot.domain}")
        print(f"Year: {snapshot.year}")
        print(f"Total subresources: {len(snapshot.subresources)}")

        # Show subresources with integrity
        sri_resources = [s for s in snapshot.subresources if s.has_integrity]
        if sri_resources:
            print(f"\n✓ Found {len(sri_resources)} subresources with SRI:")
            for res in sri_resources:
                print(f"  - {res.resource_type}: {res.url[:80]}...")
                print(f"    Algorithms: {res.hash_algorithms}")
                print(f"    External: {res.is_external}")
                print(f"    Protocol: {res.protocol}")
                if res.is_malformed:
                    print(f"    ⚠ MALFORMED")
        else:
            print("\n✗ No SRI attributes found")

        # Show external resources without SRI
        external_no_sri = [s for s in snapshot.subresources if s.is_external and not s.has_integrity]
        if external_no_sri:
            print(f"\n⚠ {len(external_no_sri)} external subresources WITHOUT SRI:")
            for res in external_no_sri[:5]:  # Show first 5
                print(f"  - {res.resource_type}: {res.url[:80]}...")
            if len(external_no_sri) > 5:
                print(f"  ... and {len(external_no_sri) - 5} more")

        return True
    else:
        print("Failed to parse file")
        return False


def test_sample_files():
    """Test on sample files from different countries"""
    # Try test_data first, fall back to ../snapshot_data
    test_dir = Path('test_data')
    base_dir = test_dir if test_dir.exists() else Path('../snapshot_data')

    # Find some sample files from different countries
    countries = ['AE', 'BA', 'CL', 'DE', 'JP']
    sample_files = []

    for country in countries:
        country_dir = base_dir / country
        if country_dir.exists():
            html_files = list(country_dir.rglob('*.html'))
            if html_files:
                # Get a recent file (they're usually sorted by date in filename)
                sample_files.append(html_files[-1])

    if not sample_files:
        print("No sample files found!")
        return

    print("="*60)
    print("TESTING SRI SCANNER ON SAMPLE FILES")
    print("="*60)

    success_count = 0
    for html_file in sample_files:
        if test_single_file(html_file):
            success_count += 1

    print("\n" + "="*60)
    print(f"Test complete: {success_count}/{len(sample_files)} files parsed successfully")
    print("="*60)


def test_country_sample(country: str, limit: int = 20):
    """Test on a sample from a specific country"""
    # Try test_data first, fall back to ../snapshot_data
    test_dir = Path('test_data')
    base_dir = test_dir if test_dir.exists() else Path('../snapshot_data')
    country_dir = base_dir / country

    if not country_dir.exists():
        print(f"Error: Country directory {country_dir} not found")
        return

    print("="*60)
    print(f"SCANNING {limit} FILES FROM {country}")
    print("="*60)

    scanner = SRIScanner(base_dir)
    file_count = scanner.scan_directory(country_dir, limit=limit)

    if file_count == 0:
        print("No files processed")
        return

    # Analyze
    results = scanner.analyze()

    # Print results
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    print(f"Pages analyzed: {results['summary']['total_pages_analyzed']}")
    print(f"Pages with SRI: {results['summary']['pages_with_sri']}")
    print(f"Adoption rate: {results['summary']['sri_adoption_rate']}")

    print(f"\nExternal resources: {results['summary']['total_external_subresources']}")
    print(f"External with SRI: {results['summary']['external_with_sri']}")
    print(f"External SRI rate: {results['summary']['external_sri_rate']}")

    if results['hash_algorithm_distribution']:
        print(f"\nHash algorithms:")
        for algo, count in results['hash_algorithm_distribution'].items():
            print(f"  {algo}: {count}")

    if results['top_sri_domains']:
        print(f"\nTop domains with SRI:")
        for domain, count in list(results['top_sri_domains'].items())[:5]:
            print(f"  {domain}: {count}")

    # Save test results
    output_dir = Path('./test_results')
    output_dir.mkdir(exist_ok=True)

    import json
    output_file = output_dir / f'test_{country}_{limit}_files.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to: {output_file}")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Test specific country
        country = sys.argv[1].upper()
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        test_country_sample(country, limit)
    else:
        # Test sample files from multiple countries
        test_sample_files()
