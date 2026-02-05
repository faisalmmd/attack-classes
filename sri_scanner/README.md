# SRI Scanner with Security Headers Analysis

Analyzes Subresource Integrity adoption and security headers in archived web snapshots. Based on methodology from Chapuis et al., "An Empirical Study of the Use of Integrity Verification Mechanisms for Web Subresources" (WWW 2020).

## Features

- **SRI Analysis**: Detects and validates integrity attributes on scripts, stylesheets, images
- **Security Headers**: Parses CSP, HSTS, X-Frame-Options, and other headers from JSON files
- **CSP Directives**: Analyzes `require-sri-for` (paper found 0.02% adoption)
- **Security Scoring**: 0-10 score based on SRI + CSP + HSTS + other headers
- **Temporal & Geographic Analysis**: Track adoption over time and across countries

## Installation

```bash
pip install -r requirements.txt
```

Requirements: Python 3.7+, beautifulsoup4, lxml

## Quick Start

```bash
# Scan test data
python scanner.py test_data/

# Scan specific country
python scanner.py /path/to/data --country AE

# Limit files for testing
python scanner.py test_data/ --limit 50

# Visualize results
python visualize.py results/sri_analysis_*.json
```

## Input Data Format

```
snapshot_data/
├── AE/                    # Country code
│   └── domain/
│       ├── 2020_index_domain_20200101120000.html      # HTML snapshot
│       └── 2020_headers_domain_20200101120000.json    # HTTP headers (optional)
├── BA/
└── CL/
```

**Naming patterns:**
- HTML: `YEAR_index_DOMAIN_TIMESTAMP.html` (required)
- Headers: `YEAR_headers_DOMAIN_TIMESTAMP.json` (optional, enables security header analysis)

Header JSON files should contain original site headers with `x-archive-orig-*` prefix:
```json
{
  "x-archive-orig-content-security-policy": "default-src 'self'; ...",
  "x-archive-orig-strict-transport-security": "max-age=31536000",
  "x-archive-orig-x-frame-options": "SAMEORIGIN"
}
```

## Usage Examples

### Basic Analysis

```bash
# Scan all files in directory
python scanner.py ../snapshot_data

# Scan specific country with custom output
python scanner.py ../snapshot_data --country CL --output-dir results_chile

# Test with limited files
python scanner.py test_data/ --limit 100
```

### Multi-Country Comparison

```bash
# Scan multiple countries
for country in AE CL DE JP; do
    python scanner.py ../snapshot_data --country $country --output-dir results_$country
done

# Compare results
for country in AE CL DE JP; do
    echo "=== $country ==="
    python visualize.py results_$country/sri_analysis_*.json | head -20
done
```

### Testing

```bash
# Test on sample files from multiple countries
python test_scanner.py

# Test specific country with N files
python test_scanner.py AE 20
```

## Output

### Console Summary
```
Total pages analyzed: 50
Pages using SRI: 16
SRI adoption rate: 32.00%

--- Security Headers ---
Pages with CSP: 1
CSP adoption rate: 2.00%
Pages with CSP require-sri-for: 0
CSP require-sri-for rate: 0.00%
Pages with HSTS: 3
HSTS adoption rate: 6.00%
Average security score: 2.55/10

--- Subresource Integrity ---
External subresources with SRI: 8 / 31
External SRI rate: 25.81%
```

### JSON Output (`sri_analysis_TIMESTAMP.json`)

Complete analysis including:
- Overall summary with SRI and security header statistics
- Per-country statistics (SRI, CSP, HSTS rates)
- Temporal analysis (year-by-year trends)
- Hash algorithm distribution
- Security score distribution
- Top CDN domains using SRI

### CSV Report (`sri_detailed_TIMESTAMP.csv`)

Per-snapshot data with columns:
- Country, Domain, Year, Timestamp
- Has_CSP, Has_HSTS, CSP_Require_SRI
- Total_Subresources, With_Integrity
- External_Resources, External_With_Integrity
- Security_Score (0-10)

## Key Metrics

**SRI Adoption Rate**: Percentage of pages with at least one integrity attribute

**External SRI Rate**: Percentage of external (CDN) resources with SRI

**CSP Adoption**: Percentage of pages with Content-Security-Policy headers

**CSP require-sri-for**: Percentage enforcing SRI via policy (WWW 2020 paper: 0.02%)

**HSTS Adoption**: Percentage with Strict-Transport-Security headers

**Security Score**: 0-10 based on SRI (2pts) + CSP (2-3pts) + HSTS (2pts) + other headers (3pts)

## Interpreting Results

### Hash Algorithms
```
sha256: 23    # Fast, commonly used
sha384: 45    # Most popular (Bootstrap default)
sha512: 8     # Most secure but less common
```

Multiple algorithms in one integrity attribute means stronger verification.

### Top Domains
```
cdnjs.cloudflare.com: 45
stackpath.bootstrapcdn.com: 28
code.jquery.com: 15
```

Shows which CDN providers offer SRI hashes. Cloudflare typically leads.

### Security Scores

- **0-2**: Minimal security (few headers)
- **3-5**: Basic security (some headers present)
- **6-8**: Good security (multiple headers + SRI)
- **9-10**: Excellent (CSP + HSTS + SRI + comprehensive headers)

### CSP require-sri-for

When present, this CSP directive **enforces** SRI - makes it mandatory rather than optional. The WWW 2020 paper found only 0.02% of sites use this. Finding any in your dataset is notable.

## Architecture

**SubresourceInfo**: Represents a subresource with SRI properties
- Parses hash algorithms
- Classifies external/internal
- Detects malformed attributes

**SecurityHeaders**: Parses and analyzes HTTP headers
- CSP directive parsing
- HSTS detection
- Security score calculation

**CSPPolicy**: Analyzes Content Security Policy
- require-sri-for detection
- script-src analysis
- upgrade-insecure-requests

**HTMLSnapshot**: Combines HTML + headers analysis
- Pairs HTML with header JSON files
- Extracts metadata (country, domain, year)
- Calculates comprehensive statistics

**SRIScanner**: Main analysis engine
- Scans directories
- Aggregates statistics
- Generates reports

## Comparison with WWW 2020 Paper

The paper analyzed 3B URLs from Common Crawl and found:
- 3.40% SRI adoption
- 0.02% use CSP `require-sri-for`
- External resources (CDN) are primary SRI use case

This tool extends the methodology with:
- HTTP header parsing (CSP, HSTS, security headers)
- CSP directive-level analysis
- Security score aggregation
- Multi-header correlation analysis

Your study of government/institutional sites enables unique comparisons with the general web baseline.

## Troubleshooting

### No headers found
```
Found headers for 0/50 files (0%)
```
Ensure JSON files follow pattern: `YEAR_headers_DOMAIN_TIMESTAMP.json`

### Header parsing errors
```
Warning: Failed to load headers from /path/to/file.json
```
Check JSON is valid. Scanner continues with HTML-only analysis.

### Low CSP detection
```
Pages with CSP: 0 (0.00%)
```
Verify header files contain `x-archive-orig-content-security-policy` key.

### Import errors
```
ModuleNotFoundError: No module named 'bs4'
```
Run: `pip install -r requirements.txt`

## Limitations

- Does not verify hash correctness (requires fetching original resources)
- Does not execute JavaScript or analyze dynamic content
- Security score is a heuristic, not a comprehensive audit
- Header analysis requires JSON files with `x-archive-orig-*` prefixes
- Assumes HTML files are UTF-8 or can be decoded with error='ignore'

## License

MIT
