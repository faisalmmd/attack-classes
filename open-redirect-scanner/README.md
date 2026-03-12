# Open Redirect Scanner

Scans archived government website snapshots for JavaScript-based open redirect vulnerabilities. Detects redirect sinks, user-controllable URL sources, and confirmed source-to-sink chains where attacker-controlled input visibly flows into a navigation call in the same code statement.

## The attack

An open redirect fires when a web page reads a URL from user-controlled input - most often a query parameter or URL fragment - and navigates the browser to that URL without checking whether the destination is a trusted domain. The attack does not require breaking any authentication or bypassing any server-side control. The attacker crafts a link like:

```
https://gov.example.com/login?returnUrl=https://attacker.com/phish
```

The user sees a trusted `.gov` domain in the address bar before clicking. After authentication the site executes `window.location.href = params.get('returnUrl')` and delivers the user to the attacker page. Because the link origin is legitimate, this gets past email security filters, user suspicion, and sometimes even corporate proxy allowlists.

In government portals the risk is amplified. Login flows that redirect back to the requested page after authentication are the canonical pattern. If the redirect target is taken from the URL without validation, any authenticated session flow doubles as an open redirect.

## Papers

Lekies, Stock and Johns, "25 Million Flows Later: Large-scale Detection of DOM-based XSS," CCS 2013. This paper established the source/sink vocabulary for DOM-based vulnerabilities that the tool's pattern categories are built on directly. The same sources that feed DOM XSS - `location.search`, `location.hash`, `document.referrer`, `document.URL` - are the sources that feed open redirect. Only the sink class differs: navigation calls rather than HTML injection points.

Pellegrino, Johns, Koch and Backes, "Deemon: Detecting CSRF with Dynamic Analysis and Property Graphs," CCS 2017. Covers client-side navigation manipulation as part of cross-origin attack surface modeling. Provides framing for how attacker-controlled URL parameters reach `window.location` assignments in realistic application code.

OWASP Unvalidated Redirects and Forwards Cheat Sheet. Used as ground truth for the sink enumeration: `location.href`, `location.assign()`, `location.replace()`, `window.location =`, and `window.open()` with a variable URL.

## What we scan

**Sinks** (redirect triggers):
- `location.href = ...`
- `location.assign(...)`
- `location.replace(...)`
- `window.location = ...`
- `window.open(variable_url)`

**Sources** (attacker-controllable inputs):
- `location.search` - URL query string
- `location.hash` - URL fragment
- `document.URL` / `document.documentURI`
- `document.referrer`
- `new URLSearchParams(...)`
- Custom `getParam()` / `getUrlParam()` helpers

**Chains** (source directly in sink expression - CRITICAL severity):
- `location.href = ... location.search`
- `location.href = ... document.referrer`

**Defenses** (validation patterns):
- `.startsWith('/')` check on redirect target
- `new URL(...).origin` hostname validation
- Trusted domain allowlist variables

## Pattern categories and severity

| Category | What it means |
|---|---|
| CHAIN | Source expression visible in the same sink statement - high-confidence redirect |
| SINK | Redirect call present - needs cross-referencing with SOURCE findings |
| SOURCE | User-controllable URL read - flag when SINK also present in same domain/year |
| DEFENSIVE | Validation pattern present - inspect the logic to confirm it rejects external URLs |

## Output files

`redirect_findings.csv` - one row per finding with country, domain, year, category, severity, line number, and a code snippet around the match.

`domain_summary.csv` - one row per (country, domain, year) with:
- `sink_count`, `source_count`, `chain_count` - pattern counts by category
- `has_confirmed_chain` - boolean flag for high-confidence findings
- `sink_with_source` - true when both categories present in same domain/year
- `has_defense` - true when at least one validation pattern was found

`redirect_summary.json` - scan metadata, category totals, top patterns, and year-over-year breakdown.

## Usage

```bash
# Scan one country
python main.py --country AE

# Scan all countries
python main.py --all

# High-confidence only: chains where source flows directly into sink
python main.py --all --chains-only

# Sinks and chains only, skip defensive output
python main.py --all --no-defensive --category SINK

# HTML inline scripts only
python main.py --country DE --no-js

# Write results to a specific directory
python main.py --all --output /path/to/results
```

## Interpreting results

The most actionable findings are CHAIN findings - these show source expression directly inside a sink statement and represent near-certain open redirect unless a validation check wraps the whole expression. Run with `--chains-only` first to get the high-signal subset.

For SINK findings without a matching CHAIN, look at the domain_summary to see whether SOURCE patterns are also present for the same domain and year. Co-occurrence of sink and source in the same domain/year snapshot is circumstantial evidence that user input reaches the redirect. Manual review of the relevant file is needed to confirm or rule out a data flow.

Longitudinally, track the ratio of SINK-with-SOURCE to SINK-with-DEFENSE per year to see whether redirect validation improved over time across the government sector.

## Limitations

This is pattern-based static analysis. A CHAIN finding means the expressions co-occur in the same statement - it does not prove that attacker-controlled input actually reaches the source at runtime. Frameworks that abstract navigation (React Router, Angular Router) may produce SINK findings that are internally safe. Conversely, multi-step data flows where a source is stored in a variable and used later in a different function will not produce a CHAIN finding even if the redirect is exploitable.
