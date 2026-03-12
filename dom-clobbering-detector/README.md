# DOM Clobbering Detector

Scans archived government website snapshots for DOM clobbering vulnerabilities. Detects HTML elements whose `name` or `id` attribute could overwrite JavaScript global variables, JavaScript code that accesses those globals in susceptible ways, and confirmed collisions where both the clobberable element and the vulnerable JS code appear in the same HTML page.

## The attack

DOM clobbering exploits a browser legacy behavior: named HTML elements are promoted to properties on the `window` and `document` objects. A `<form name="config">` element makes `window.config` return the form element, not whatever the JavaScript code intended. Because HTML elements are truthy, any security check that reads the global and evaluates it as a boolean passes - even when the actual application value is false.

A concrete example. A page sets `window.isAdmin = false` in a script tag, then checks it later:

```html
<form name="isAdmin"></form>
<script>
  if (window.isAdmin) {
    showAdminPanel();  // runs, because HTMLFormElement is truthy
  }
</script>
```

If an attacker can inject HTML - through a stored input field, a CMS comment, or a misconfigured sanitizer - they can clobber any global the page relies on. The page's own JavaScript becomes the exploit gadget.

The two-level variant from Lekies et al. 2021 is more precise: `<form id="x"><input name="y">` makes `x.y` return the input element, allowing an attacker to forge nested property accesses like `config.csrfToken`.

In government portals this matters most for:
- Authorization checks that read a global flag set by a prior script
- CSP nonce values read from a global variable and applied to dynamic scripts
- Configuration objects that control API endpoints or feature flags

## Papers

Lekies, Jonker and Johns, "DOM Clobbering Strikes Back," USENIX Security 2021. The primary reference for this tool. Systematic study of DOM clobbering gadgets in real-world libraries and applications. Found exploitable chains in Chromium DevTools, DOMPurify, Gmail, and several major open source projects. Established the taxonomy of single-level (id/name to window) and two-level (form/input nesting) clobbering, and documented which HTML element and attribute combinations trigger namespace promotion in each major browser.

Khodayari and Pellegrino, "It's (DOM) Clobbering Time: Attack Techniques, Prevalence, and Defenses," IEEE S&P 2023. First large-scale measurement of DOM clobbering in the wild across 5,000 websites. Found clobberable gadgets in 9.8% of pages. Specifically demonstrated that CSP nonce checks can be bypassed via DOM clobbering when the nonce is read through a global variable rather than from the script element's own attribute.

## What we scan

**HTML_SINK** - HTML elements whose `name` or `id` attribute matches a known security-sensitive global name. Detected via BeautifulSoup parsing. Examples: `<form name="config">`, `<input id="isAdmin">`, `<a name="token">`.

**JS_RELIANCE** - JavaScript patterns that access globals in clobbering-susceptible ways:
- `window[variable]` - dynamic bracket access on window
- `if (window.isAdmin)` / `if (typeof auth ...)` - conditional checks on security globals without explicit declaration
- `window.config`, `window.settings`, `document.data` - named property access on window/document for sensitive names
- CSP nonce access through globals

**CHAIN** - Named element and matching global access found in the same HTML document. This is the in-page collision: both the clobberable element and the vulnerable JS code exist in the same snapshot. Does not require injection.

**DEFENSIVE** - Code patterns that avoid namespace promotion reliance:
- `document.getElementById(...)` - explicit element access
- `document.querySelector(...)` / `document.querySelectorAll(...)`
- `Object.create(null)` - prototype-safe dictionary objects

## Sensitive name coverage

The scanner checks for collisions involving:
- Browser-defined globals that named elements shadow: `name`, `status`, `location`, `origin`, `parent`, `top`, `opener`
- Security-sensitive app globals: `config`, `settings`, `auth`, `token`, `csrf`, `nonce`, `isAdmin`, `admin`, `role`, `permissions`, `session`
- Common boolean flags: `isLoggedIn`, `isAuthenticated`, `initialized`, `enabled`, `trusted`

## Output files

`clobbering_findings.csv` - one row per finding with category, severity, the clobbered name, the HTML element tag (for HTML_SINK findings), line number, and a context snippet.

`domain_summary.csv` - one row per (country, domain, year) with:
- `html_sink_count`, `js_reliance_count`, `chain_count` - counts by category
- `has_chain` - boolean: named element and matching JS access in same page
- `has_defense` - boolean: explicit getElementById/querySelector usage present
- `unique_clobbered_names` - distinct sensitive names involved
- `clobbered_names` - pipe-separated list of those names
- `element_tags_seen` - which HTML element types carried the sensitive names

`clobbering_summary.json` - scan metadata, category totals, top clobbered names by frequency, and year breakdown.

## Usage

```bash
# Scan one country
python main.py --country AE

# Scan all countries
python main.py --all

# Only chain findings: confirmed in-page element/JS collisions
python main.py --all --chains-only

# HTML only (no standalone JS files)
python main.py --all --no-js

# Filter to HTML_SINK category: see all named elements with sensitive values
python main.py --country DE --category HTML_SINK

# Write results to a specific directory
python main.py --all --output /path/to/results
```

## Interpreting results

**CHAIN findings** are the most actionable. They show a page where a named HTML element and JavaScript code that accesses the matching global name coexist. Even if the HTML element was placed intentionally by the site's own developer, the collision indicates a code pattern that would be exploitable if an attacker could inject that element name elsewhere on the page.

**HTML_SINK without CHAIN** - a sensitive named element exists but no inline script was found accessing that name as a global. The JS code may be in an external file. Cross-reference the domain's JS files to see if the global is accessed there.

**JS_RELIANCE without CHAIN** - the JavaScript accesses a global in a susceptible way but no named element with that name was found in the same HTML page. The element could be injected (stored XSS, CMS input, sanitizer bypass) or may exist in a different page of the same site.

**DEFENSIVE findings** indicate the developer used explicit DOM methods. Track the ratio of defensive to reliance patterns over time to see whether government portals moved toward explicit getElementById usage as the CMS ecosystem matured.

## Limitations

The HTML_SINK scan only catches elements present in the archived snapshot. Dynamically-inserted elements (added by JavaScript after page load) will not appear in the HTML and will not be detected. The JS_RELIANCE patterns cannot perform scope analysis, so they flag any access to a sensitive global name regardless of whether a `var`/`let`/`const` declaration is present in a non-visible scope. False positive rate for `JS_RELIANCE` is moderate; the `CHAIN` category has much higher precision.
