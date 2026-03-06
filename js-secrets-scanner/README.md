# JS Secrets Scanner

Static analysis tool for detecting hardcoded secrets, API keys, and credentials in archived JavaScript files and HTML inline scripts.

## Why this exists

A recurring problem with government web portals is that secrets end up in client-side code - not always through negligence, but because embedded maps, analytics dashboards, and third-party integrations require API keys that developers drop directly into JavaScript bundles. Once those keys are in a page, they're also in the Wayback Machine's archive. They might have been revoked the same week, or they might still be live. Either way, understanding *which* secrets appeared, *when*, and *for how long* is exactly the kind of longitudinal signal this project was built to capture.

The research grounding comes from industry-scale secret scanning studies. Intruder (2025) scanned five million applications and found over 42,000 exposed tokens across 334 secret types. Escape.tech scanned 189 million URLs and found 18,000+ exposed API secrets. TruffleHog and Gitleaks have repeatedly shown that production JavaScript bundles - the same kind of files archived in this dataset - are a reliable source of leaked credentials. Google Maps API keys are by far the most common finding in government sites.

This tool treats the archive as a time machine for credential exposure: you can pinpoint the first snapshot where a secret appeared and the last one where it was present before being rotated.

## What it scans

| Source | Location |
|--------|----------|
| Standalone JS files | `snapshot_js_data/{COUNTRY}/{domain}/*.js` |
| Inline `<script>` blocks | `snapshot_data/{COUNTRY}/{domain}/*_index_*.html` |

## Pattern coverage

| Severity | Pattern | Notes |
|----------|---------|-------|
| CRITICAL | AWS Access Key ID (`AKIA...`) | Cloud account compromise |
| CRITICAL | Stripe Live Secret Key | Payment fraud |
| CRITICAL | GitHub PAT | Repo access |
| CRITICAL | Private Key (PEM block) | Asymmetric key material |
| HIGH | Google API Key (`AIza...`) | Most common in gov sites |
| HIGH | Firebase Config Block | Often left in JS bundles |
| HIGH | SendGrid / Mailgun Keys | Email account takeover |
| HIGH | Credentials in URL | Basic Auth embedded in code |
| HIGH | Hardcoded password (≥8 chars) | Internal system auth |
| HIGH | Mapbox Token | Common in GIS portals |
| MEDIUM | Stripe Publishable Key | Account identification |
| MEDIUM | Twilio Account SID | Telecom account |
| MEDIUM | JWT (hardcoded) | May be a live session token |
| MEDIUM | Generic API key assignment | Catches service-specific keys by naming |
| MEDIUM | Generic client/consumer secret | OAuth secrets |
| LOW | Generic access/auth token | Needs manual review |

All matched values are **redacted in output** - the tool logs a preview of the first 6 characters plus the match length. The raw secret is never written to disk.

## Wayback Machine noise filtering

Every JS file in the archive begins with the Wayback Machine's `_wb_wombat` wrapper - hundreds of lines of URL-rewriting infrastructure that would generate massive false positives if scanned. The scanner identifies these lines by known marker strings and skips them before applying any patterns.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan all JS files and inline scripts for one country
python main.py --country AE

# Scan everything
python main.py --all

# Only JS files (skip inline script extraction from HTML)
python main.py --country DE --no-html

# Only report HIGH and CRITICAL findings
python main.py --all --severity HIGH

# Custom output directory
python main.py --all --output /path/to/results
```

## Output

Each run creates a timestamped directory under `results/` containing:

| File | Contents |
|------|----------|
| `secrets_findings.csv` | One row per finding: country, domain, year, timestamp, source file, pattern label, severity, line number, redacted context |
| `secrets_summary.json` | Aggregate counts by severity, pattern type, country, and year |

### Example CSV row

```
country,domain,year,timestamp,source_file,source_type,pattern_id,pattern_label,severity,line_number,context,match_preview,match_length
AE,maps_gov_ae,2019,20191104121533,2019_20191104121533_script_3.js,js_file,google_api_key,Google API Key,HIGH,47,...apiKey: "[REDACTED:39]"...,AIza...[redacted],39
```

## Research notes

The longitudinal dimension here is particularly interesting. Government portals often embed Google Maps API keys for location services and boundary displays - these appear consistently across snapshots. Tracking the **first appearance** and **last appearance** of a given key prefix lets you estimate how long a credential was exposed in the archive before (presumably) being rotated. Some keys persist across multi-year windows, which is a meaningful finding on its own.

Cross-referencing with the SRI scanner output also makes sense: sites that load many external scripts without SRI and also embed API keys directly represent a doubly elevated risk surface.
