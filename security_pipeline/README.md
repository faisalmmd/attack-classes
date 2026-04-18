# Web Archive Security Analysis Pipeline

Static security scanner for archived web files (JS, CSS, HTML, XML/XSLT, WASM).
Built for the regional longitudinal study of government web security across 16 countries
(2003-2024) via the Internet Archive Wayback Machine.

Runs 25 attack detectors and outputs a binary domain-by-attack matrix (0/1) plus
a full evidence report with file paths, line numbers, and matched code.

## Quick Start

```bash
# Scan a directory, print evidence to stdout
python driver.py /path/to/archived/site/

# Evidence report + binary matrix CSV
python driver.py /path/to/archived/site/ --output report.txt --matrix matrix.csv

# Single attack
python run_attack.py xxe
python run_attack.py css_attr_exfil
python run_attack.py --list        # show all attack names
```

## No dependencies required

Python 3 standard library only (re, os, json, csv, struct, argparse, dataclasses).
No pip install needed. BeautifulSoup is not used -- all parsing is regex/struct-based
to keep the pipeline portable on any archive machine.

## Output format

**Evidence report** (`--output report.txt`): one `[FOUND]` block per finding with file
path, line number, description, and the exact matched line of code.

**Matrix CSV** (`--matrix matrix.csv`): rows = domain subdirectories, columns = attack
types, cells = 1 if any finding of that attack was found in the domain, 0 otherwise.

```
domain,xxe,xml_bomb,css_attr_exfil,...
chatbot_moccae_gov_ae,0,0,1,...
portal_moi_gov_ae,1,0,0,...
```

## File structure

```
security_pipeline/
├── driver.py              -- main entry point, walks directory, routes files to scanners
├── run_attack.py          -- generic single-attack runner (outputs to results/<attack>/)
├── run_pp.py              -- prototype_pollution runner with detailed severity breakdown
├── test_runner.py         -- 55-assertion test suite against test_cases/
├── scanners/
│   ├── js_scanner.py      -- 9 JavaScript/TypeScript attack detectors
│   ├── css_scanner.py     -- 3 CSS attack detectors
│   ├── html_scanner.py    -- 7 HTML attack detectors + inline script/style delegation
│   ├── xml_scanner.py     -- 4 XML/XSLT attack detectors
│   ├── wasm_scanner.py    -- 1 WASM cryptominer detector
│   └── retire_scanner.py  -- vulnerable JS library detection (built-in CVE DB + retire CLI)
├── test_cases/            -- synthetic test files, one per attack
├── results/               -- per-attack output (summary.json tracked; bulk evidence gitignored)
├── verification/
│   └── VERIFICATION_GUIDE.md  -- methodology, references, false negative notes per attack
└── data/                  -- gitignored (place dataset here to run on real data)
```

## Attacks

### Verified and approved (14)

Methodology reviewed against primary sources, false negatives documented,
test assertions confirmed. Safe to use for analysis.

| Attack | File types | Key patterns |
|--------|-----------|-------------|
| `xxe` | XML | `<!ENTITY x SYSTEM "file:///...">`, parameter entities |
| `xml_bomb` | XML | Entity chain depth >=3, >=5 refs in one entity value |
| `xslt_injection` | XSLT | `document("file://...")`, `php:function()`, `<msxsl:script>` |
| `xpath_injection` | XSLT | `select="//user[$var]"`, `concat()` in XPath expressions |
| `prototype_pollution` | JS+HTML | `Object.prototype.x =`, `__proto__` assignment, `constructor.prototype`, `_.merge()`, `$.extend(true,...)` |
| `jsonp_callback` | JS+HTML | `?callback=`, `dataType:"jsonp"`, script tag with callback param |
| `postmessage_audit` | JS+HTML | `addEventListener("message",...)` without `event.origin ===` check |
| `cryptominer_js` | JS+HTML | CoinHive/CryptoLoot domains, `CoinHive.Anonymous()`, `cryptonight` |
| `service_worker` | JS+HTML | `serviceWorker.register()` with broad scope (`/`), `importScripts()` |
| `css_attr_exfil` | CSS+HTML | `[value^=x] { background: url(https://...) }` |
| `css_import_chain` | CSS+HTML | Multiple `@import 'https://...'` to same external domain |
| `missing_sri` | HTML | External `<script src>` or `<link rel=stylesheet>` without `integrity=` |
| `base_tag_hijack` | HTML | `<base href="https://external.com/">` |
| `vulnerable_library` | JS | Version string + CVE lookup (jQuery, Lodash, Angular, Bootstrap, etc.) |

### Pending review (11)

Implemented and test-passing but not yet approved. See `TEST_SUMMARY.md` for specific
open issues per attack.

`open_redirect`, `high_risk_api`, `dangerous_sink`, `redos`,
`css_font_keylog`, `wasm_cryptominer`, `clickjacking`, `meta_refresh_redirect`,
`form_action_hijack`, `dangling_markup`, `html_violation`

## Running on real data

Place the extracted dataset under `data/` (gitignored). Then:

```bash
# Full pipeline, all 25 attacks
python driver.py data/ --output results/evidence.txt --matrix results/matrix.csv

# Single attack with structured output
python run_attack.py xxe --data data/
```

Per-attack results land in `results/<attack_name>/`:
- `summary.json` -- domain counts, scan time, severity breakdown (tracked in git)
- `evidence.txt` -- full finding list with code snippets (gitignored, regenerate as needed)
- `domain_summary.csv` -- per-domain counts (gitignored)
- `attack_matrix.csv` -- binary 0/1 per domain (gitignored)

## Notes

- **TruffleHog** (hardcoded secrets): run separately via `js-secrets-scanner/` in archive-sec-analysis
- **WASM hash DB**: `KNOWN_MINER_HASHES` in `wasm_scanner.py` is empty -- string-based detection only
- **Retire CLI**: if `npm install -g retire` is available, the scanner prefers it; otherwise falls back to the built-in CVE database
- **Wayback preamble**: JS files from the Wayback Machine start with a `_____WB$wombat` wrapper (~25 lines); the JS scanner strips this before scanning
