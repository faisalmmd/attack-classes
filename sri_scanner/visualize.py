#!/usr/bin/env python3
"""
Visualization script for SRI analysis results
Generates charts and graphs from the JSON output
"""

import json
import sys
from pathlib import Path
from typing import Dict


def print_bar_chart(data: Dict[str, int], title: str, max_width: int = 50):
    """Print a simple text-based bar chart"""
    if not data:
        return

    print(f"\n{title}")
    print("=" * (max_width + 20))

    # Find max value for scaling
    max_val = max(data.values()) if data else 1

    for label, value in sorted(data.items(), key=lambda x: x[1], reverse=True):
        bar_length = int((value / max_val) * max_width) if max_val > 0 else 0
        bar = "█" * bar_length
        print(f"{label:20s} {bar} {value}")


def print_temporal_chart(data: Dict, title: str = "SRI Adoption Over Time"):
    """Print temporal analysis"""
    if not data:
        return

    print(f"\n{title}")
    print("=" * 80)
    print(f"{'Year':>6} {'Total':>8} {'With SRI':>10} {'Adoption %':>12}")
    print("-" * 80)

    for year, stats in sorted(data.items()):
        total = stats['total']
        with_sri = stats['with_sri']
        rate = (with_sri / total * 100) if total > 0 else 0

        # Simple bar visualization
        bar_length = int(rate / 2)  # Scale to 50 chars max
        bar = "▓" * bar_length

        print(f"{year:>6} {total:>8} {with_sri:>10} {rate:>11.2f}% {bar}")


def print_country_comparison(data: Dict, title: str = "SRI Adoption by Country"):
    """Print country comparison"""
    if not data:
        return

    print(f"\n{title}")
    print("=" * 80)
    print(f"{'Country':>8} {'Total':>8} {'With SRI':>10} {'Adoption %':>12}")
    print("-" * 80)

    # Sort by adoption rate
    sorted_countries = sorted(
        data.items(),
        key=lambda x: (x[1]['with_sri'] / x[1]['total']) if x[1]['total'] > 0 else 0,
        reverse=True
    )

    for country, stats in sorted_countries:
        total = stats['total']
        with_sri = stats['with_sri']
        rate = (with_sri / total * 100) if total > 0 else 0

        bar_length = int(rate / 2)
        bar = "▓" * bar_length

        print(f"{country:>8} {total:>8} {with_sri:>10} {rate:>11.2f}% {bar}")


def generate_report(json_file: Path):
    """Generate a comprehensive text report from JSON results"""
    print("\n" + "="*80)
    print("SUBRESOURCE INTEGRITY (SRI) ANALYSIS REPORT")
    print("="*80)

    with open(json_file, 'r') as f:
        results = json.load(f)

    # Summary section
    summary = results.get('summary', {})
    print("\nOVERALL SUMMARY")
    print("-" * 80)
    print(f"Total pages analyzed: {summary.get('total_pages_analyzed', 0):,}")
    print(f"Pages using SRI: {summary.get('pages_with_sri', 0):,}")
    print(f"SRI adoption rate: {summary.get('sri_adoption_rate', '0%')}")
    print()
    print(f"Total subresources found: {summary.get('total_external_subresources', 0) + summary.get('total_internal_subresources', 0):,}")
    print(f"External subresources: {summary.get('total_external_subresources', 0):,}")
    print(f"  - With SRI: {summary.get('external_with_sri', 0):,} ({summary.get('external_sri_rate', '0%')})")
    print(f"Internal subresources: {summary.get('total_internal_subresources', 0):,}")
    print(f"  - With SRI: {summary.get('internal_with_sri', 0):,} ({summary.get('internal_sri_rate', '0%')})")
    print()
    print(f"Malformed integrity attributes: {summary.get('total_malformed_integrity', 0):,}")

    # Security headers section
    print("\n" + "="*80)
    print("SECURITY HEADERS ANALYSIS")
    print("="*80)
    print(f"Pages with HTTP headers: {summary.get('pages_with_headers', 0):,}")
    print(f"Pages with CSP: {summary.get('pages_with_csp', 0):,} ({summary.get('csp_adoption_rate', '0%')})")
    print(f"Pages with CSP require-sri-for: {summary.get('pages_with_csp_require_sri', 0):,} ({summary.get('csp_require_sri_rate', '0%')})")
    print(f"Pages with HSTS: {summary.get('pages_with_hsts', 0):,} ({summary.get('hsts_adoption_rate', '0%')})")
    print(f"Average security score: {summary.get('avg_security_score', '0.00')}/10")

    # Hash algorithms
    hash_algos = results.get('hash_algorithm_distribution', {})
    if hash_algos:
        print_bar_chart(hash_algos, "Hash Algorithm Distribution")

    # Protocol distribution
    protocols = results.get('protocol_distribution', {})
    if protocols:
        print_bar_chart(protocols, "Protocol Distribution (All Subresources)")

    # Top SRI domains
    sri_domains = results.get('top_sri_domains', {})
    if sri_domains:
        print_bar_chart(
            dict(list(sri_domains.items())[:15]),
            "Top 15 Domains Serving Subresources with SRI"
        )

    # Resource types
    resource_types = results.get('resource_types_with_sri', {})
    if resource_types:
        print_bar_chart(resource_types, "Resource Types Using SRI")

    # Temporal analysis
    temporal = results.get('temporal_analysis', {})
    if temporal:
        print_temporal_chart(temporal)

    # Country comparison
    country_stats = results.get('country_statistics', {})
    if country_stats:
        print_country_comparison(country_stats)

    # Security score distribution
    score_dist = results.get('security_score_distribution', {})
    if score_dist:
        print_bar_chart(score_dist, "Security Score Distribution (0-10)")

    # Key findings
    print("\n" + "="*80)
    print("KEY FINDINGS")
    print("="*80)

    findings = []

    # Compare with paper findings
    adoption_rate = float(summary.get('sri_adoption_rate', '0%').rstrip('%'))
    if adoption_rate < 3.4:
        findings.append(f"• SRI adoption ({adoption_rate:.2f}%) is LOWER than the 3.40% reported in the WWW 2020 paper")
    elif adoption_rate > 3.4:
        findings.append(f"• SRI adoption ({adoption_rate:.2f}%) is HIGHER than the 3.40% reported in the WWW 2020 paper")
    else:
        findings.append(f"• SRI adoption ({adoption_rate:.2f}%) is similar to the 3.40% reported in the WWW 2020 paper")

    # CSP findings
    csp_rate = float(summary.get('csp_adoption_rate', '0%').rstrip('%'))
    csp_sri_rate = float(summary.get('csp_require_sri_rate', '0%').rstrip('%'))
    if csp_rate > 0:
        findings.append(f"• CSP adoption: {csp_rate:.2f}%")
        if csp_sri_rate > 0:
            findings.append(f"• CSP with require-sri-for: {csp_sri_rate:.2f}% (paper found 0.02%)")

    # HSTS findings
    hsts_rate = float(summary.get('hsts_adoption_rate', '0%').rstrip('%'))
    if hsts_rate > 0:
        findings.append(f"• HSTS adoption: {hsts_rate:.2f}%")

    # Security posture
    avg_score = float(summary.get('avg_security_score', '0'))
    if avg_score > 0:
        findings.append(f"• Average security score: {avg_score:.2f}/10")

    # External vs internal
    ext_rate = float(summary.get('external_sri_rate', '0%').rstrip('%'))
    int_rate = float(summary.get('internal_sri_rate', '0%').rstrip('%'))
    if ext_rate > int_rate:
        findings.append(f"• External subresources have higher SRI adoption ({ext_rate:.2f}%) than internal ({int_rate:.2f}%)")
    else:
        findings.append(f"• Internal subresources have higher SRI adoption ({int_rate:.2f}%) than external ({ext_rate:.2f}%)")

    # Hash algorithms
    if hash_algos:
        most_common_algo = max(hash_algos.items(), key=lambda x: x[1])[0]
        findings.append(f"• Most common hash algorithm: {most_common_algo}")

        if 'sha384' in hash_algos:
            findings.append(f"  - sha384 is used {hash_algos['sha384']} times (consistent with paper - used by Bootstrap)")

    # Malformed
    malformed = summary.get('total_malformed_integrity', 0)
    if malformed > 0:
        total_with_sri = summary.get('external_with_sri', 0) + summary.get('internal_with_sri', 0)
        if total_with_sri > 0:
            malformed_rate = (malformed / total_with_sri) * 100
            findings.append(f"• {malformed_rate:.1f}% of integrity attributes are malformed")

    # CDN usage
    if sri_domains:
        cdn_domains = [d for d in sri_domains.keys() if 'cdn' in d.lower() or 'cloudflare' in d.lower()]
        if cdn_domains:
            findings.append(f"• CDN domains are prominent in SRI usage (e.g., {cdn_domains[0]})")

    for finding in findings:
        print(finding)

    print("\n" + "="*80)
    print("END OF REPORT")
    print("="*80 + "\n")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python visualize.py <results.json>")
        print("\nExample: python visualize.py results/sri_analysis_20240205_120000.json")
        return

    json_file = Path(sys.argv[1])

    if not json_file.exists():
        print(f"Error: File {json_file} not found")
        return

    generate_report(json_file)


if __name__ == '__main__':
    main()
