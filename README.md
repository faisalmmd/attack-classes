# Web Archive Security Analysis Pipeline

Static security scanner for archived web files (JS, CSS, HTML, XML/XSLT, WASM).
Built for the regional longitudinal study of government web security across 16 countries
(2003-2024) via the Internet Archive Wayback Machine.

Runs 26 attack detectors and outputs a binary domain-by-attack matrix (0/1) plus
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

### All 26 attacks verified and approved

Methodology reviewed against primary sources, false positives documented,
test assertions confirmed (59/59). Safe to use for analysis.

| Attack | File types | Key patterns |
|--------|-----------|-------------|
| `xxe` | XML | `<!ENTITY x SYSTEM "file:///...">`, parameter entities |
| `xml_bomb` | XML | Entity chain depth >=3, >=5 refs in one entity value |
| `xslt_injection` | XSLT | `document("file://...")`, `php:function()`, `<msxsl:script>` |
| `xpath_injection` | XSLT | `select="//user[$var]"`, `concat()` in XPath expressions |
| `prototype_pollution` | JS+HTML | `Object.prototype.x =`, `__proto__` assignment, `constructor.prototype`, `_.merge()`, `$.extend(true,...)` |
| `open_redirect` | JS+HTML | `location.href/replace/assign`, `window.location =`, `window.open()`, `frame.src =` with variable arg |
| `high_risk_api` | JS+HTML | `navigator.geolocation`, `getUserMedia`, `clipboard.read`, `getBattery()`, `RTCPeerConnection`, Bluetooth/USB/Serial |
| `dangerous_sink` | JS+HTML | `eval()`, `innerHTML =`, `document.write()`, `setTimeout(string)`, `setAttribute('on*', var)` (Lekies et al. CCS 2013) |
| `redos` | JS+HTML | Star Height > 1 `(a+)+`, QOD `(a\|b)+` — syntactic heuristic (Davis et al. ESEC/FSE 2018); QOA not detected |
| `jsonp_callback` | JS+HTML | `?callback=`, `dataType:"jsonp"`, script tag with callback param |
| `postmessage_audit` | JS+HTML | `addEventListener("message",...)` without `event.origin ===` check |
| `cryptominer_js` | JS+HTML | CoinHive/CryptoLoot domains, `CoinHive.Anonymous()`, `cryptonight` |
| `service_worker` | JS+HTML | `serviceWorker.register()` with broad scope (`/`), `importScripts()` |
| `css_attr_exfil` | CSS+HTML | `[value^=x] { background: url(https://...) }` |
| `css_import_chain` | CSS+HTML | Multiple `@import 'https://...'` to same external domain |
| `css_font_keylog` | CSS+HTML | `@font-face` single-codepoint `unicode-range` + external `src: url(https://...)` |
| `wasm_cryptominer` | WASM | Byte-level signatures (`cryptonight`, `cn_slow_hash`, `stratum`, etc.); 3+ = CRITICAL |
| `missing_sri` | HTML | External `<script src>` or `<link rel=stylesheet>` without `integrity=` |
| `base_tag_hijack` | HTML | `<base href="https://external.com/">` |
| `clickjacking` | HTML | Hidden/transparent `<iframe>`; login page without frame-busting defense |
| `meta_refresh_redirect` | HTML | `<meta http-equiv="refresh" content="...;url=https://external...">` |
| `form_action_hijack` | HTML | `<form action="http://...">` (HTTP), external HTTPS action, `formaction` override |
| `dangling_markup` | HTML | `javascript:` URL in href/src/action (CRITICAL), `data:` URL in script/iframe (HIGH) |
| `html_violation` | HTML | Nested `<form>` (HIGH), duplicate IDs, block-in-inline, unclosed elements (MEDIUM) |
| `vulnerable_library` | JS | Version string + CVE lookup (jQuery, Lodash, Angular, Bootstrap, etc.) |
| `dom_clobbering` | HTML+JS | Named/ID'd elements shadowing window.X or document.X (HTML_SINK HIGH/CRITICAL), CHAIN when same name appears in inline JS (CRITICAL), two-level `<form id><input name>` (HIGH), JS_RELIANCE: `window[var]`, `document.scripts`, security globals in conditionals (Liu et al. USENIX Security 2025, Lekies et al. USENIX Security 2021, Khodayari & Pellegrino IEEE S&P 2023) |

## Known False Positives and Methodological Disclosures

Required disclosures for the paper methodology section. See `verification/VERIFICATION_GUIDE.md`
for full per-attack detail.

| Attack | FP / Limitation | Severity of FP concern |
|--------|----------------|------------------------|
| `clickjacking` | Pages defended by HTTP `X-Frame-Options` header appear unprotected — header is not in archived HTML. Systematic false positive for header-protected pages. | **High** — expect elevated MEDIUM rate on well-configured sites |
| `html_violation` | MEDIUM findings are very high-volume on real HTML: block-in-inline patterns (`<a>` wrapping `<div>`) are valid HTML5; unclosed `<p>`, `<li>` are standard; duplicate IDs from templating are common. Use only HIGH (nested forms) for strict analysis. | **High** — MEDIUM rate is noisy on real data |
| `form_action_hijack` | All `http://` form actions flagged as HIGH regardless of form purpose (search vs. login). All `formaction` attributes flagged as MEDIUM regardless of whether target is internal or external. | **Medium** — requires manual triage to separate login forms from benign forms |
| `dangling_markup` | Unclosed-attribute heuristic (HIGH/MEDIUM) may false-positive on multi-line attributes in real HTML. The `javascript:` and `data:` URL detections (CRITICAL/HIGH) are reliable. | **Medium** — affects only the heuristic sub-detector, not the URL patterns |
| `meta_refresh_redirect` | Legitimate intentional redirects to partner sites, updated domains, or affiliate pages flagged as HIGH. All findings require manual triage. | **Medium** — genuine redirects indistinguishable from malicious ones without context |
| `redos` | Syntactic heuristic only — detects Star Height and QOD anti-patterns; misses QOA (71% of SL regexes per Davis et al. ESEC/FSE 2018). All anti-patterns have 90–98% static FP rates. | **Medium** — describe as heuristic in paper |
| `wasm_cryptominer` | Common cryptographic library strings (`keccak`, `scrypt`, `argon2`) appear in legitimate TLS/crypto WASM modules. Generic export names (`hash`, `work`, `job`) are common in non-mining WASM. Multi-signature escalation (CRITICAL at 3+) reduces FP rate. Hash DB is empty — no hash-match detection. | **Low-Medium** — multi-signature threshold mitigates single-string FPs |
| `css_import_chain` | All external `@import` URLs flagged, including legitimate CDN imports (Google Fonts, etc.). Attack requires attacker-controlled server responding with branching imports — not detectable statically. | **Low-Medium** — flags opportunity, not active attack |
| `css_font_keylog` | Legitimate narrow-range font subsets may trigger (rare). Two-condition requirement (single-codepoint range AND external URL) substantially limits FPs. Source is PoC-only, no peer-reviewed paper. | **Low** |
| `postmessage_audit` | Pages using `message` listeners for legitimate cross-frame communication (e.g., OAuth flows, embedded widgets) flagged if no `event.origin` check is visible in the 15-line handler window. | **Low** |
| `dangerous_sink` | `setTimeout(varName, ...)` flagged as MEDIUM — callback reference vs. string argument is ambiguous statically. `setAttribute('on*', var)` flagged as HIGH — second argument may be a static string in practice. | **Low** |
| `missing_sri` | Wayback-rewritten URLs (`web.archive.org/web/...`) are treated as external — intentional, as they represent originally-external resources. | **Low** — by design |
| `dom_clobbering` | `window[variable]` HIGH fires on legitimate plugin loader patterns where the variable name is not attacker-controlled. Two-level (`<form id><input name>`) flags all such structures regardless of whether JS exploits the `form.input` access path. CHAIN detection is limited to inline scripts — gadgets spanning external JS files are not detected. | **Low-Medium** — `window[var]` and two-level patterns require manual triage; HTML_SINK findings for rare names (`scripts`, `nonce`) are high-precision |

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
