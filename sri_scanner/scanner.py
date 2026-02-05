#!/usr/bin/env python3
"""
Enhanced Subresource Integrity (SRI) Scanner
Includes HTTP header analysis (CSP, HSTS, security headers)
Based on methodology from WWW 2020 paper by Chapuis et al.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, Counter
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime


class CSPPolicy:
    """Parses and analyzes Content Security Policy"""

    def __init__(self, csp_header: str):
        self.raw = csp_header
        self.directives = self._parse_directives()

    def _parse_directives(self) -> Dict[str, List[str]]:
        """Parse CSP directive string into dictionary"""
        if not self.raw:
            return {}

        directives = {}
        # Split by semicolon, then parse each directive
        parts = self.raw.split(';')

        for part in parts:
            part = part.strip()
            if not part:
                continue

            tokens = part.split()
            if tokens:
                directive_name = tokens[0].lower()
                values = tokens[1:] if len(tokens) > 1 else []
                directives[directive_name] = values

        return directives

    def has_require_sri_for(self) -> bool:
        """Check if CSP has require-sri-for directive"""
        return 'require-sri-for' in self.directives

    def get_require_sri_for_targets(self) -> List[str]:
        """Get targets for require-sri-for (script, style)"""
        return self.directives.get('require-sri-for', [])

    def has_upgrade_insecure_requests(self) -> bool:
        """Check if CSP upgrades HTTP to HTTPS"""
        return 'upgrade-insecure-requests' in self.directives

    def get_script_src_policy(self) -> List[str]:
        """Get script-src directive values"""
        return self.directives.get('script-src', [])

    def allows_unsafe_inline(self) -> bool:
        """Check if CSP allows unsafe-inline scripts"""
        script_src = self.get_script_src_policy()
        return "'unsafe-inline'" in script_src or '"unsafe-inline"' in script_src


class SecurityHeaders:
    """Analyzes HTTP security headers"""

    def __init__(self, headers_dict: Dict[str, str]):
        self.raw_headers = headers_dict
        self.original_headers = self._extract_original_headers()
        self.csp = self._parse_csp()

    def _extract_original_headers(self) -> Dict[str, str]:
        """Extract x-archive-orig-* headers (original site headers)"""
        orig = {}
        for key, value in self.raw_headers.items():
            if key.startswith('x-archive-orig-'):
                # Remove the prefix to get original header name
                orig_key = key.replace('x-archive-orig-', '')
                orig[orig_key] = value
        return orig

    def _parse_csp(self) -> Optional[CSPPolicy]:
        """Parse Content-Security-Policy header"""
        csp_value = self.original_headers.get('content-security-policy')
        if csp_value:
            return CSPPolicy(csp_value)
        return None

    def has_csp(self) -> bool:
        """Check if site has CSP header"""
        return self.csp is not None

    def has_hsts(self) -> bool:
        """Check if site has HSTS (Strict-Transport-Security)"""
        return 'strict-transport-security' in self.original_headers

    def get_hsts_max_age(self) -> Optional[int]:
        """Get HSTS max-age value"""
        hsts = self.original_headers.get('strict-transport-security', '')
        match = re.search(r'max-age=(\d+)', hsts)
        if match:
            return int(match.group(1))
        return None

    def has_frame_options(self) -> bool:
        """Check for X-Frame-Options (clickjacking protection)"""
        return 'x-frame-options' in self.original_headers

    def has_xss_protection(self) -> bool:
        """Check for X-XSS-Protection"""
        return 'x-xss-protection' in self.original_headers

    def has_content_type_options(self) -> bool:
        """Check for X-Content-Type-Options (MIME sniffing protection)"""
        return 'x-content-type-options' in self.original_headers

    def get_referrer_policy(self) -> Optional[str]:
        """Get Referrer-Policy value"""
        return self.original_headers.get('referrer-policy')

    def calculate_security_score(self, has_sri: bool = False) -> int:
        """
        Calculate security score (0-10)
        Based on presence of security headers and SRI
        """
        score = 0

        # CSP (2 points, 3 if has require-sri-for)
        if self.has_csp():
            score += 2
            if self.csp.has_require_sri_for():
                score += 1

        # HSTS (2 points)
        if self.has_hsts():
            score += 2

        # SRI usage (2 points)
        if has_sri:
            score += 2

        # Other security headers (1 point each, max 3)
        other_score = 0
        if self.has_frame_options():
            other_score += 1
        if self.has_xss_protection():
            other_score += 1
        if self.has_content_type_options():
            other_score += 1
        score += min(other_score, 3)

        return min(score, 10)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        result = {
            'has_csp': self.has_csp(),
            'has_hsts': self.has_hsts(),
            'has_frame_options': self.has_frame_options(),
            'has_xss_protection': self.has_xss_protection(),
            'has_content_type_options': self.has_content_type_options(),
            'referrer_policy': self.get_referrer_policy(),
        }

        if self.has_csp():
            result['csp_details'] = {
                'has_require_sri_for': self.csp.has_require_sri_for(),
                'require_sri_for_targets': self.csp.get_require_sri_for_targets(),
                'has_upgrade_insecure_requests': self.csp.has_upgrade_insecure_requests(),
                'allows_unsafe_inline': self.csp.allows_unsafe_inline()
            }

        if self.has_hsts():
            result['hsts_max_age'] = self.get_hsts_max_age()

        return result


class SubresourceInfo:
    """Information about a subresource found in an HTML page"""

    def __init__(self, tag_name: str, url: str, has_integrity: bool,
                 integrity_value: str = None, crossorigin: str = None,
                 resource_type: str = None):
        self.tag_name = tag_name
        self.url = url
        self.has_integrity = has_integrity
        self.integrity_value = integrity_value
        self.crossorigin = crossorigin
        self.resource_type = resource_type
        self.hash_algorithms = self._parse_hash_algorithms() if integrity_value else []
        self.is_external = self._is_external_resource()
        self.protocol = self._extract_protocol()
        self.is_malformed = self._check_malformed() if has_integrity else False

    def _parse_hash_algorithms(self) -> List[str]:
        """Extract hash algorithms from integrity attribute"""
        if not self.integrity_value:
            return []

        algorithms = []
        parts = self.integrity_value.strip().split()
        for part in parts:
            if '-' in part:
                algo = part.split('-')[0].lower()
                algorithms.append(algo)
        return algorithms

    def _is_external_resource(self) -> bool:
        """Check if resource is external (cross-domain)"""
        if not self.url:
            return False
        if self.url.startswith('/') or not self.url.startswith('http'):
            return False
        parsed = urlparse(self.url)
        return bool(parsed.netloc)

    def _extract_protocol(self) -> str:
        """Extract protocol (HTTP/HTTPS)"""
        if not self.url:
            return 'none'
        if self.url.startswith('https'):
            return 'https'
        elif self.url.startswith('http'):
            return 'http'
        elif self.url.startswith('//'):
            return 'protocol-relative'
        else:
            return 'relative'

    def _check_malformed(self) -> bool:
        """Check if integrity attribute is malformed"""
        if not self.integrity_value:
            return False

        valid_algos = {'sha256', 'sha384', 'sha512'}
        if not self.integrity_value.strip():
            return True

        parts = self.integrity_value.strip().split()
        for part in parts:
            if '-' not in part:
                return True
            algo, hash_value = part.split('-', 1)
            algo = algo.lower()
            if algo not in valid_algos:
                return True
            if not hash_value:
                return True
        return False

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'tag_name': self.tag_name,
            'url': self.url,
            'has_integrity': self.has_integrity,
            'integrity_value': self.integrity_value,
            'crossorigin': self.crossorigin,
            'resource_type': self.resource_type,
            'hash_algorithms': self.hash_algorithms,
            'is_external': self.is_external,
            'protocol': self.protocol,
            'is_malformed': self.is_malformed
        }


class HTMLSnapshot:
    """Represents a single HTML snapshot with headers"""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.country = None
        self.domain = None
        self.year = None
        self.timestamp = None
        self._parse_metadata()
        self.subresources: List[SubresourceInfo] = []
        self.csp_header = None
        self.uses_https = False
        self.security_headers: Optional[SecurityHeaders] = None
        self.headers_file = self._find_headers_file()

    def _parse_metadata(self):
        """Extract metadata from file path"""
        parts = self.file_path.parts

        if len(parts) >= 3:
            for i, part in enumerate(parts):
                if len(part) == 2 and part.isupper():
                    self.country = part
                    if i + 1 < len(parts):
                        self.domain = parts[i + 1]
                    break

        filename = self.file_path.stem
        match = re.match(r'(\d{4})_.*_(\d{14})', filename)
        if match:
            self.year = int(match.group(1))
            self.timestamp = match.group(2)

    def _find_headers_file(self) -> Optional[Path]:
        """Find corresponding headers JSON file"""
        if not self.timestamp:
            return None

        # Convert: YEAR_index_domain_TIMESTAMP.html -> YEAR_headers_domain_TIMESTAMP.json
        html_filename = self.file_path.name
        headers_filename = html_filename.replace('_index_', '_headers_').replace('.html', '.json')
        headers_path = self.file_path.parent / headers_filename

        if headers_path.exists():
            return headers_path
        return None

    def load_headers(self) -> bool:
        """Load and parse HTTP headers from JSON file"""
        if not self.headers_file:
            return False

        try:
            with open(self.headers_file, 'r', encoding='utf-8') as f:
                headers_dict = json.load(f)

            self.security_headers = SecurityHeaders(headers_dict)

            # Update CSP from headers (more reliable than meta tags)
            if self.security_headers.has_csp():
                self.csp_header = self.security_headers.csp.raw

            return True
        except Exception as e:
            print(f"Warning: Failed to load headers from {self.headers_file}: {e}")
            return False

    def parse(self) -> bool:
        """Parse HTML file and extract subresources"""
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            soup = BeautifulSoup(content, 'html.parser')
            self.uses_https = 'https://' in content.lower()

            # Extract scripts
            for script in soup.find_all('script', src=True):
                self._extract_subresource(script, 'script', script.get('src'))

            # Extract stylesheets
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href')
                if href:
                    self._extract_subresource(link, 'link', href)

            # Extract images with integrity (rare but possible)
            for img in soup.find_all('img', src=True):
                integrity = img.get('integrity')
                if integrity:
                    self._extract_subresource(img, 'img', img.get('src'))

            # Check for CSP in meta tags (fallback if no headers)
            if not self.csp_header:
                for meta in soup.find_all('meta', attrs={'http-equiv': True}):
                    if meta.get('http-equiv', '').lower() == 'content-security-policy':
                        self.csp_header = meta.get('content', '')

            return True

        except Exception as e:
            print(f"Error parsing {self.file_path}: {e}")
            return False

    def _extract_subresource(self, tag, tag_name: str, url: str):
        """Extract subresource information from a tag"""
        integrity = tag.get('integrity')
        crossorigin = tag.get('crossorigin')

        if tag_name == 'script':
            resource_type = 'script'
        elif tag_name == 'link':
            resource_type = 'stylesheet'
        elif tag_name == 'img':
            resource_type = 'image'
        else:
            resource_type = 'unknown'

        subresource = SubresourceInfo(
            tag_name=tag_name,
            url=url,
            has_integrity=bool(integrity),
            integrity_value=integrity,
            crossorigin=crossorigin,
            resource_type=resource_type
        )

        self.subresources.append(subresource)

    def get_statistics(self) -> Dict:
        """Get statistics for this snapshot"""
        total_subresources = len(self.subresources)
        with_integrity = sum(1 for s in self.subresources if s.has_integrity)
        external_resources = sum(1 for s in self.subresources if s.is_external)
        external_with_integrity = sum(1 for s in self.subresources
                                     if s.is_external and s.has_integrity)

        hash_algos = []
        for s in self.subresources:
            if s.has_integrity:
                hash_algos.extend(s.hash_algorithms)

        malformed_count = sum(1 for s in self.subresources if s.is_malformed)

        # Security score
        has_sri = with_integrity > 0
        security_score = 0
        if self.security_headers:
            security_score = self.security_headers.calculate_security_score(has_sri)

        stats = {
            'file': str(self.file_path),
            'country': self.country,
            'domain': self.domain,
            'year': self.year,
            'timestamp': self.timestamp,
            'uses_https': self.uses_https,
            'has_csp': bool(self.csp_header) or (self.security_headers and self.security_headers.has_csp()),
            'total_subresources': total_subresources,
            'subresources_with_integrity': with_integrity,
            'external_subresources': external_resources,
            'external_with_integrity': external_with_integrity,
            'uses_sri': with_integrity > 0,
            'hash_algorithms': Counter(hash_algos),
            'malformed_integrity_count': malformed_count,
            'protocols': Counter([s.protocol for s in self.subresources]),
            'resource_types': Counter([s.resource_type for s in self.subresources]),
            'has_headers_file': self.headers_file is not None,
            'security_score': security_score
        }

        # Add security header details if available
        if self.security_headers:
            stats['security_headers'] = self.security_headers.to_dict()

        return stats


class SRIScanner:
    """Main scanner class for analyzing SRI adoption with header analysis"""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.snapshots: List[HTMLSnapshot] = []
        self.statistics = defaultdict(list)

    def scan_directory(self, directory: Path, limit: int = None) -> int:
        """Scan a directory for HTML files"""
        count = 0
        html_files = list(directory.rglob('*.html'))

        if limit:
            html_files = html_files[:limit]

        total = len(html_files)
        print(f"Found {total} HTML files to process")

        for i, html_file in enumerate(html_files, 1):
            if i % 100 == 0:
                print(f"Processing {i}/{total} ({i*100//total}%)")

            snapshot = HTMLSnapshot(html_file)

            # Load headers first
            snapshot.load_headers()

            # Then parse HTML
            if snapshot.parse():
                self.snapshots.append(snapshot)
                count += 1

        print(f"Successfully processed {count} files")

        # Report header coverage
        with_headers = sum(1 for s in self.snapshots if s.headers_file)
        print(f"Found headers for {with_headers}/{count} files ({with_headers*100//count if count > 0 else 0}%)")

        return count

    def analyze(self) -> Dict:
        """Analyze all scanned snapshots and generate statistics"""
        print("\nAnalyzing snapshots...")

        total_pages = len(self.snapshots)
        pages_with_sri = sum(1 for s in self.snapshots if any(sub.has_integrity for sub in s.subresources))

        # Header statistics
        pages_with_headers = sum(1 for s in self.snapshots if s.security_headers)
        pages_with_csp = sum(1 for s in self.snapshots if s.security_headers and s.security_headers.has_csp())
        pages_with_hsts = sum(1 for s in self.snapshots if s.security_headers and s.security_headers.has_hsts())
        pages_with_csp_require_sri = sum(1 for s in self.snapshots
                                        if s.security_headers and s.security_headers.has_csp()
                                        and s.security_headers.csp.has_require_sri_for())

        # Per-country statistics
        country_stats = defaultdict(lambda: {'total': 0, 'with_sri': 0, 'with_csp': 0, 'with_hsts': 0})
        year_stats = defaultdict(lambda: {'total': 0, 'with_sri': 0, 'with_csp': 0, 'with_hsts': 0})

        all_hash_algorithms = []
        total_external = 0
        external_with_sri = 0
        total_internal = 0
        internal_with_sri = 0
        protocol_counts = Counter()
        total_malformed = 0
        sri_domains = Counter()
        resource_types_with_sri = Counter()

        # Security score distribution
        security_scores = []

        for snapshot in self.snapshots:
            stats = snapshot.get_statistics()

            if stats['uses_sri']:
                pages_with_sri += 1

            # Per country
            if snapshot.country:
                country_stats[snapshot.country]['total'] += 1
                if stats['uses_sri']:
                    country_stats[snapshot.country]['with_sri'] += 1
                if snapshot.security_headers and snapshot.security_headers.has_csp():
                    country_stats[snapshot.country]['with_csp'] += 1
                if snapshot.security_headers and snapshot.security_headers.has_hsts():
                    country_stats[snapshot.country]['with_hsts'] += 1

            # Per year
            if snapshot.year:
                year_stats[snapshot.year]['total'] += 1
                if stats['uses_sri']:
                    year_stats[snapshot.year]['with_sri'] += 1
                if snapshot.security_headers and snapshot.security_headers.has_csp():
                    year_stats[snapshot.year]['with_csp'] += 1
                if snapshot.security_headers and snapshot.security_headers.has_hsts():
                    year_stats[snapshot.year]['with_hsts'] += 1

            # Security scores
            if stats['security_score'] > 0:
                security_scores.append(stats['security_score'])

            # Analyze subresources
            for sub in snapshot.subresources:
                if sub.is_external:
                    total_external += 1
                    if sub.has_integrity:
                        external_with_sri += 1
                        if sub.url:
                            parsed = urlparse(sub.url)
                            if parsed.netloc:
                                sri_domains[parsed.netloc] += 1
                        resource_types_with_sri[sub.resource_type] += 1
                else:
                    total_internal += 1
                    if sub.has_integrity:
                        internal_with_sri += 1

                if sub.has_integrity:
                    all_hash_algorithms.extend(sub.hash_algorithms)
                    if sub.is_malformed:
                        total_malformed += 1

                protocol_counts[sub.protocol] += 1

        # Calculate security score statistics
        avg_security_score = sum(security_scores) / len(security_scores) if security_scores else 0
        security_score_distribution = Counter(security_scores)

        # Compile results
        results = {
            'summary': {
                'total_pages_analyzed': total_pages,
                'pages_with_sri': pages_with_sri,
                'sri_adoption_rate': f"{pages_with_sri/total_pages*100:.2f}%" if total_pages > 0 else "0%",
                'total_external_subresources': total_external,
                'external_with_sri': external_with_sri,
                'external_sri_rate': f"{external_with_sri/total_external*100:.2f}%" if total_external > 0 else "0%",
                'total_internal_subresources': total_internal,
                'internal_with_sri': internal_with_sri,
                'internal_sri_rate': f"{internal_with_sri/total_internal*100:.2f}%" if total_internal > 0 else "0%",
                'total_malformed_integrity': total_malformed,
                # Header statistics
                'pages_with_headers': pages_with_headers,
                'pages_with_csp': pages_with_csp,
                'csp_adoption_rate': f"{pages_with_csp/total_pages*100:.2f}%" if total_pages > 0 else "0%",
                'pages_with_hsts': pages_with_hsts,
                'hsts_adoption_rate': f"{pages_with_hsts/total_pages*100:.2f}%" if total_pages > 0 else "0%",
                'pages_with_csp_require_sri': pages_with_csp_require_sri,
                'csp_require_sri_rate': f"{pages_with_csp_require_sri/total_pages*100:.2f}%" if total_pages > 0 else "0%",
                'avg_security_score': f"{avg_security_score:.2f}",
            },
            'country_statistics': dict(country_stats),
            'temporal_analysis': dict(sorted(year_stats.items())),
            'hash_algorithm_distribution': dict(Counter(all_hash_algorithms)),
            'protocol_distribution': dict(protocol_counts),
            'top_sri_domains': dict(sri_domains.most_common(20)),
            'resource_types_with_sri': dict(resource_types_with_sri),
            'security_score_distribution': dict(sorted(security_score_distribution.items()))
        }

        return results

    def generate_detailed_report(self, output_file: Path):
        """Generate detailed CSV report of all findings"""
        import csv

        print(f"\nGenerating detailed report: {output_file}")

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Country', 'Domain', 'Year', 'Timestamp', 'Uses_HTTPS',
                'Has_CSP', 'Has_HSTS', 'CSP_Require_SRI', 'Total_Subresources', 'With_Integrity',
                'External_Resources', 'External_With_Integrity',
                'Hash_Algorithms', 'Malformed_Count', 'Security_Score'
            ])

            for snapshot in self.snapshots:
                stats = snapshot.get_statistics()
                hash_algos = ','.join([f"{k}:{v}" for k, v in stats['hash_algorithms'].items()])

                csp_require_sri = False
                if snapshot.security_headers and snapshot.security_headers.has_csp():
                    csp_require_sri = snapshot.security_headers.csp.has_require_sri_for()

                writer.writerow([
                    stats['country'],
                    stats['domain'],
                    stats['year'],
                    stats['timestamp'],
                    stats['uses_https'],
                    stats['has_csp'],
                    snapshot.security_headers.has_hsts() if snapshot.security_headers else False,
                    csp_require_sri,
                    stats['total_subresources'],
                    stats['subresources_with_integrity'],
                    stats['external_subresources'],
                    stats['external_with_integrity'],
                    hash_algos,
                    stats['malformed_integrity_count'],
                    stats['security_score']
                ])

        print(f"Report saved to {output_file}")

    def save_results(self, output_file: Path, results: Dict):
        """Save analysis results to JSON file"""
        print(f"\nSaving results to {output_file}")

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        print(f"Results saved to {output_file}")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Scan archived web snapshots for Subresource Integrity (SRI) and security headers'
    )
    parser.add_argument(
        'input_dir',
        type=Path,
        help='Input directory containing HTML snapshots'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('./results'),
        help='Output directory for results (default: ./results)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Limit number of files to process (for testing)'
    )
    parser.add_argument(
        '--country',
        type=str,
        default=None,
        help='Process only specific country (e.g., AE, BA)'
    )

    args = parser.parse_args()

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Determine scan directory
    if args.country:
        scan_dir = args.input_dir / args.country
        if not scan_dir.exists():
            print(f"Error: Country directory {scan_dir} does not exist")
            return
    else:
        scan_dir = args.input_dir

    # Create scanner
    scanner = SRIScanner(args.input_dir)

    # Scan files
    print(f"Scanning directory: {scan_dir}")
    file_count = scanner.scan_directory(scan_dir, limit=args.limit)

    if file_count == 0:
        print("No files processed. Exiting.")
        return

    # Analyze
    results = scanner.analyze()

    # Print summary
    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    print(f"Total pages analyzed: {results['summary']['total_pages_analyzed']}")
    print(f"Pages using SRI: {results['summary']['pages_with_sri']}")
    print(f"SRI adoption rate: {results['summary']['sri_adoption_rate']}")

    print(f"\n--- Security Headers ---")
    print(f"Pages with CSP: {results['summary']['pages_with_csp']}")
    print(f"CSP adoption rate: {results['summary']['csp_adoption_rate']}")
    print(f"Pages with CSP require-sri-for: {results['summary']['pages_with_csp_require_sri']}")
    print(f"CSP require-sri-for rate: {results['summary']['csp_require_sri_rate']}")
    print(f"Pages with HSTS: {results['summary']['pages_with_hsts']}")
    print(f"HSTS adoption rate: {results['summary']['hsts_adoption_rate']}")
    print(f"Average security score: {results['summary']['avg_security_score']}/10")

    print(f"\n--- Subresource Integrity ---")
    print(f"External subresources with SRI: {results['summary']['external_with_sri']} / {results['summary']['total_external_subresources']}")
    print(f"External SRI rate: {results['summary']['external_sri_rate']}")
    print(f"\nMalformed integrity attributes: {results['summary']['total_malformed_integrity']}")

    if results['hash_algorithm_distribution']:
        print(f"\nHash algorithms used:")
        for algo, count in sorted(results['hash_algorithm_distribution'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {algo}: {count}")

    if results['top_sri_domains']:
        print(f"\nTop 10 domains serving subresources with SRI:")
        for domain, count in list(results['top_sri_domains'].items())[:10]:
            print(f"  {domain}: {count}")

    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = args.output_dir / f'sri_analysis_{timestamp}.json'
    csv_file = args.output_dir / f'sri_detailed_{timestamp}.csv'

    scanner.save_results(json_file, results)
    scanner.generate_detailed_report(csv_file)

    print("\n" + "="*60)
    print("Analysis complete!")
    print("="*60)


if __name__ == '__main__':
    main()
