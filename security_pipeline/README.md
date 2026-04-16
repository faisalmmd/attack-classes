# Web Archive Security Analysis Pipeline

Static security scanner for archived web files. Runs 19 custom tests across
JavaScript, CSS, XML/XSLT, and WebAssembly files.

## Quick Start

```bash
# Scan a directory
python driver.py /path/to/archived/site/

# JSON output, only HIGH+ severity
python driver.py /path/to/archived/site/ --format json --severity HIGH -o report.json

# CSV output
python driver.py /path/to/archived/site/ --format csv -o results.csv

# Scan only specific extensions
python driver.py /path/to/archived/site/ --ext .js .css
```

## No dependencies required

The pipeline uses only Python 3 standard library (re, os, json, csv, struct,
argparse, dataclasses). No pip install needed.

## Tests Included (19)

### JavaScript (.js .mjs .jsx .ts .tsx) — 9 tests
1. Prototype Pollution Scanner
2. Open Redirect Scanner  
3. High-Risk Browser API Detector
4. Dangerous Sink Usage (eval, innerHTML, document.write...)
5. JSONP Callback Injection
6. ReDoS (Regex Denial of Service)
7. Service Worker Scope Audit
8. Cryptominer Detection
9. postMessage Handler Audit

### CSS (.css) — 3 tests
10. Attribute Selector Data Exfiltration
11. @import Chain Exfiltration
12. Font Ligature Keylogging

### XML (.xml .xsl .xslt .soap .rss .atom) — 4 tests
13. XXE (XML External Entity) Patterns
14. XML Bomb / Billion Laughs
15. XPath Injection Indicators
16. XSLT Injection

### WebAssembly (.wasm) — 1 test
17. Cryptominer Module Detection

## Run Separately

### TruffleHog (credential scanning across ALL files)
```bash
trufflehog filesystem --directory /path/to/archived/site/
```

### Retire.js (vulnerable JS library detection)
```bash
retire --path /path/to/archived/site/ --outputformat json
```

## File Structure

```
security_pipeline/
├── driver.py                    # Main entry point
├── README.md
├── ATTACK_EXPLANATIONS.txt      # Detailed explanation of every attack
├── scanners/
│   ├── __init__.py
│   ├── js_scanner.py            # 9 JavaScript tests
│   ├── css_scanner.py           # 3 CSS tests
│   ├── xml_scanner.py           # 4 XML/XSLT tests
│   └── wasm_scanner.py          # 1 WASM test
└── test_samples/                # Test files with intentional vulnerabilities
    ├── test.js
    ├── test.css
    ├── test.xml
    └── test.xslt
```

## Exit Codes

- 0: No CRITICAL or HIGH findings
- 1: CRITICAL or HIGH findings detected
