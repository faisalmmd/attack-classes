# Clickjacking Detection Tool

A Python-based static analysis tool for detecting clickjacking vulnerabilities in archived HTML files. Designed for longitudinal security research on government websites (2000-2025).

Based on the methodology from "Busting Frame Busting: A Study of Clickjacking Vulnerabilities on Popular Sites" (ASIACCS 2010).

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [CLI Usage](#cli-usage)
- [Input Formats](#input-formats)
- [Output Format](#output-format)
- [Detection Methodology](#detection-methodology)
- [Python API](#python-api)
- [Testing](#testing)
- [Project Structure](#project-structure)

## Overview

This tool performs **static analysis** on HTML files to detect:

1. **Transparent cross-domain iframes** - Hidden frames that could overlay legitimate content
2. **Overlapping clickable elements** - Frames positioned over buttons, links, or forms
3. **Missing defenses** - Absence of X-Frame-Options, CSP frame-ancestors, or frame-busting JavaScript

It's designed to process thousands of archived web pages efficiently and generate CSV reports suitable for temporal/longitudinal analysis.

## Installation

### Prerequisites

- Python 3.8+
- pip

### Setup

```bash
# Clone or navigate to the project
cd clickjacking_detector

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| beautifulsoup4 | HTML parsing |
| lxml | Fast HTML/XML parser |
| cssutils | CSS parsing and analysis |
| tldextract | Domain extraction for cross-origin detection |
| pandas | CSV/DataFrame handling |

## Quick Start

```bash
# Analyze a single HTML file
python main.py --input-file page.html

# Analyze a directory of HTML files
python main.py --input-dir ./archived_pages --output report.csv

# Analyze with verbose output
python main.py --input-dir ./data --output report.csv --verbose
```

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         main.py (CLI)                           │
│   - Argument parsing                                            │
│   - Directory scanning                                          │
│   - CSV/JSON report generation                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    analyzer.py (Orchestrator)                   │
│   - ClickjackingAnalyzer class                                  │
│   - Combines all detection modules                              │
│   - Calculates vulnerability scores                             │
│   - Generates VulnerabilityReport objects                       │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ frame_detector  │ │ overlap_checker │ │ defense_detector│
│                 │ │                 │ │                 │
│ - Extract frames│ │ - Find buttons, │ │ - X-Frame-Opts  │
│ - Parse CSS     │ │   links, inputs │ │ - CSP headers   │
│ - Check opacity │ │ - Calculate     │ │ - Frame-busting │
│ - Cross-domain  │ │   bounding boxes│ │   JavaScript    │
│   detection     │ │ - Find overlaps │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### Processing Pipeline

1. **Input Loading**: Read HTML file + optional headers file + optional metadata JSON
2. **Frame Extraction**: Find all `<iframe>` and `<frame>` elements
3. **CSS Analysis**: Parse inline styles + `<style>` blocks to compute opacity, position, z-index
4. **Transparency Detection**: Flag frames with opacity < 0.1, visibility: hidden, or display: none
5. **Cross-Domain Detection**: Compare frame src domain against page domain using tldextract
6. **Clickable Element Extraction**: Find `<a>`, `<button>`, `<input type="submit">`, etc.
7. **Overlap Detection**: Calculate bounding box intersections between frames and clickables
8. **Defense Detection**: Check HTTP headers and scan JavaScript for frame-busting patterns
9. **Risk Scoring**: Calculate vulnerability score and risk level
10. **Report Generation**: Output CSV/JSON with all findings

## CLI Usage

### Basic Commands

```bash
# Single file analysis
python main.py --input-file page.html

# Directory analysis (recursive by default)
python main.py --input-dir ./archive_data --output report.csv

# Non-recursive directory scan
python main.py --input-dir ./archive_data --output report.csv --no-recursive

# With JSON output for detailed results
python main.py --input-dir ./data -o report.csv --json-output detailed.json

# Verbose mode (shows progress)
python main.py --input-dir ./data -o report.csv --verbose

# Quiet mode (no summary)
python main.py --input-dir ./data -o report.csv --quiet
```

### Single File with Headers

```bash
# Provide headers file
python main.py --input-file page.html --headers headers.txt

# Provide inline metadata
python main.py --input-file page.html --metadata '{"url": "https://gov.example.com", "timestamp": "2020-01-15"}'

# Provide metadata from file
python main.py --input-file page.html --metadata-file page_metadata.json
```

### All Options

| Option | Short | Description |
|--------|-------|-------------|
| `--input-file` | `-f` | Single HTML file to analyze |
| `--input-dir` | `-d` | Directory containing HTML files |
| `--output` | `-o` | Output CSV path (default: clickjacking_report.csv) |
| `--json-output` | `-j` | Optional JSON output for detailed results |
| `--headers` | | Path to HTTP headers file |
| `--metadata` | | Inline JSON metadata string |
| `--metadata-file` | | Path to metadata JSON file |
| `--no-recursive` | `-nr` | Don't scan subdirectories |
| `--include-details` | | Include detailed JSON in CSV |
| `--verbose` | `-v` | Enable verbose logging |
| `--quiet` | `-q` | Suppress summary output |

## Input Formats

### HTML Files

Any `.html` or `.htm` file. The tool handles malformed HTML gracefully using BeautifulSoup's lxml parser.

### Headers File

Plain text with `Header-Name: value` format:

```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'self'
Content-Type: text/html
```

Or JSON format:

```json
{
  "X-Frame-Options": "SAMEORIGIN",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"
}
```

### Metadata JSON

```json
{
  "url": "https://www.government.gov/services",
  "timestamp": "2020-06-15T10:30:00Z",
  "capture_date": "2020-06-15",
  "source": "wayback_machine"
}
```

### File Association

The tool automatically looks for associated files based on naming conventions:

```
page.html           # Main HTML file
page.headers        # Headers file (auto-detected)
page.json           # Metadata file (auto-detected)
```

Alternative patterns also supported:
- `page_headers.txt`, `page.headers.json`
- `page_metadata.json`

## Output Format

### CSV Columns

| Column | Type | Description |
|--------|------|-------------|
| `url` | string | Page URL or file path |
| `timestamp` | string | Original capture timestamp |
| `capture_date` | string | Capture date (YYYY-MM-DD) |
| `vulnerable` | bool | True if risk_level is medium/high/critical |
| `risk_level` | string | none, low, medium, high, critical |
| `vulnerability_score` | int | 0-10+ score |
| `total_frames` | int | Total iframe/frame count |
| `transparent_frames` | int | Frames with opacity < 0.1 |
| `cross_domain_frames` | int | Frames from different domains |
| `suspicious_frames` | int | Transparent AND cross-domain |
| `overlapping_elements` | int | Click targets under suspicious frames |
| `high_value_targets_at_risk` | int | Login/payment buttons at risk |
| `has_xframe_options` | bool | X-Frame-Options header present |
| `xframe_options_value` | string | DENY, SAMEORIGIN, or ALLOW-FROM |
| `has_csp_frame_ancestors` | bool | CSP frame-ancestors present |
| `has_framebusting_js` | bool | Frame-busting JavaScript detected |
| `framebusting_patterns_count` | int | Number of JS patterns found |
| `defense_score` | int | 0-10 defense strength |
| `defense_level` | string | none, weak, moderate, strong |
| `analysis_date` | string | When analysis was performed |

### Example CSV Output

```csv
url,timestamp,vulnerable,risk_level,vulnerability_score,suspicious_frames,has_xframe_options,defense_level
https://gov.example.com,2020-01-15,False,none,0,0,True,strong
https://old.gov.example.com,2015-03-20,True,high,5,2,False,none
```

## Detection Methodology

### Vulnerability Scoring

| Condition | Points |
|-----------|--------|
| Each suspicious frame (transparent + cross-domain) | +3 |
| Overlapping clickable elements (max 3) | +2 each |
| High-value targets at risk (max 2) | +2 each |
| No defenses detected | +1 |
| Weak defenses only | +0.5 |
| Strong defenses present | -2 |
| Moderate defenses present | -1 |

### Risk Levels

| Score | Level |
|-------|-------|
| 0 | none |
| 1 | low |
| 2-3 | medium |
| 4-5 | high |
| 6+ | critical |

### Transparency Detection

An element is considered transparent if any of these conditions are met:

- `opacity < 0.1`
- `filter: alpha(opacity=0)` (IE legacy)
- `visibility: hidden`
- `display: none`
- `width: 0` or `height: 0`
- Positioned far off-screen (left/top < -1000px)

### Cross-Domain Detection

Uses tldextract to compare registered domains:

```
Page: https://www.gov.example.com/page
Frame: https://cdn.gov.example.com/widget  → Same domain (gov.example.com)
Frame: https://malicious.com/attack        → Cross-domain
Frame: /local/embed                        → Same domain (relative URL)
```

### Frame-Busting JavaScript Patterns

The tool detects 20+ patterns including:

```javascript
// Comparison patterns
if (top !== self)
if (window.top !== window.self)
if (parent !== self)

// Redirect patterns
top.location = self.location
top.location.replace(...)
parent.location = ...

// Frame counting
if (parent.frames.length > 0)

// Modern detection
window.frameElement
```

### Defense Effectiveness

| Mechanism | Effectiveness |
|-----------|---------------|
| X-Frame-Options: DENY | Strong |
| X-Frame-Options: SAMEORIGIN | Strong |
| X-Frame-Options: ALLOW-FROM | Moderate (deprecated) |
| CSP frame-ancestors 'none' | Strong |
| CSP frame-ancestors 'self' | Strong |
| CSP frame-ancestors * | Weak |
| Frame-busting JavaScript | Weak to Moderate (bypassable) |

## Python API

### Basic Usage

```python
from analyzer import ClickjackingAnalyzer

analyzer = ClickjackingAnalyzer()

# Analyze a page
html_content = open('page.html').read()
headers = {'X-Frame-Options': 'DENY'}
metadata = {'url': 'https://example.gov', 'timestamp': '2020-01-15'}

report = analyzer.analyze_page(html_content, headers, metadata)

print(f"Vulnerable: {report.vulnerable}")
print(f"Risk Level: {report.risk_level}")
print(f"Score: {report.vulnerability_score}")
print(f"Suspicious Frames: {report.suspicious_frames}")
```

### Batch Analysis

```python
from analyzer import BatchAnalyzer

batch = BatchAnalyzer()

pages = [
    {'html_content': html1, 'headers': {}, 'metadata': {'url': 'page1'}},
    {'html_content': html2, 'headers': {}, 'metadata': {'url': 'page2'}},
]

reports = batch.analyze_batch(pages)

# Get summary statistics
stats = batch.get_summary_statistics()
print(f"Vulnerability Rate: {stats['vulnerability_rate']:.1f}%")

# Get temporal analysis (grouped by year)
temporal = batch.get_temporal_analysis()
for year, data in temporal.items():
    print(f"{year}: {data['vulnerability_rate']:.1f}% vulnerable")
```

### Using Individual Modules

```python
from frame_detector import analyze_frames, get_suspicious_frames
from overlap_checker import extract_clickable_elements, find_overlapping_elements
from defense_detector import analyze_defenses

# Frame analysis
frames = analyze_frames(html_content, page_url)
suspicious = get_suspicious_frames(frames)

# Overlap analysis
clickables = extract_clickable_elements(html_content)
overlaps = find_overlapping_elements(suspicious, clickables)

# Defense analysis
defenses = analyze_defenses(headers, html_content)
print(f"Defense Level: {defenses.defense_level}")
```

## Testing

### Run All Tests

```bash
cd clickjacking_detector
python tests/test_analyzer.py
```

### Run with pytest (if installed)

```bash
pytest tests/test_analyzer.py -v
```

### Test Files

The `tests/test_pages/` directory contains sample HTML files:

| File | Description | Expected Result |
|------|-------------|-----------------|
| `benign.html` | Normal page with visible iframe | Not vulnerable |
| `transparent_iframe.html` | Hidden cross-domain iframes | Vulnerable (critical) |
| `with_defenses.html` | Page with X-Frame-Options + CSP + JS | Not vulnerable, strong defenses |
| `overlapping.html` | Transparent frames over buttons | Vulnerable (critical) |

## Project Structure

```
clickjacking_detector/
├── __init__.py           # Package exports
├── requirements.txt      # Python dependencies
├── README.md            # This documentation
│
├── frame_detector.py    # Frame extraction and CSS analysis
│   ├── extract_frames()
│   ├── analyze_frames()
│   ├── is_transparent()
│   ├── is_cross_domain()
│   └── get_suspicious_frames()
│
├── overlap_checker.py   # Clickable element detection
│   ├── extract_clickable_elements()
│   ├── check_overlap()
│   └── find_overlapping_elements()
│
├── defense_detector.py  # Security header/JS detection
│   ├── check_xframe_header()
│   ├── check_csp_frame_ancestors()
│   ├── detect_framebusting_js()
│   └── analyze_defenses()
│
├── analyzer.py          # Main orchestration
│   ├── ClickjackingAnalyzer
│   ├── BatchAnalyzer
│   └── VulnerabilityReport
│
├── main.py              # CLI entry point
│
└── tests/
    ├── test_analyzer.py # Unit tests (23 tests)
    └── test_pages/      # Sample HTML files
        ├── benign.html
        ├── transparent_iframe.html
        ├── with_defenses.html
        ├── with_defenses.headers
        ├── overlapping.html
        └── benign.json
```

## Performance

- Processes ~1000 HTML files in under 5 minutes on typical hardware
- Memory efficient: processes files one at a time
- Parallel processing not implemented (single-threaded)

## Limitations

1. **Static Analysis Only**: Cannot execute JavaScript or render pages
2. **Bounding Box Approximation**: Element positions are estimated from CSS, not actual layout
3. **External Stylesheets**: CSS from external files (link tags) is not analyzed
4. **Dynamic Content**: JavaScript-generated iframes are not detected
5. **Obfuscated Code**: Heavily obfuscated frame-busting JS may not be detected

## License

MIT License

## References

- Rui Wang et al., "Busting Frame Busting: A Study of Clickjacking Vulnerabilities on Popular Sites", IEEE S&P 2010
- OWASP Clickjacking Defense Cheat Sheet
- MDN Web Docs: X-Frame-Options, Content-Security-Policy
