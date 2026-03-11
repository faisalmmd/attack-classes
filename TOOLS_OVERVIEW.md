# Security Analysis Pipeline - Tools Overview

**Project:** Longitudinal Security Analysis of Government Web Snapshots
**Dataset:** ~91,570 archived snapshots, 16 countries, 2003-2024 (Internet Archive Wayback Machine)
**Purpose:** This document describes each tool in the pipeline, the attack or weakness it detects, and the research that backs it. Prepared for expert review before full-scale analysis runs.

---

## Dataset Structure (Quick Reference)

All tools operate exclusively on files already on disk. No live HTTP requests are made during analysis.

```
snapshot_data/{CC}/{domain}/
    {year}_headers_{domain}_{timestamp}.json   <- HTTP response headers
    {year}_index_{domain}_{timestamp}.html     <- Full archived HTML page

snapshot_js_data/{CC}/{domain}/
    {year}_{timestamp}_script_N.js             <- Extracted JavaScript files
```

Original site headers are stored by the Wayback Machine with an `x-archive-orig-` prefix. All tools strip this prefix before analysis so results reflect what the live site was actually sending.

---

## Table of Contents

1. [SRI Scanner](#1-sri-scanner)
2. [Clickjacking Detector](#2-clickjacking-detector)
3. [HTML Violation Analyzer](#3-html-violation-analyzer)
4. [Retire.js - Vulnerable Library Detector](#4-retirejs---vulnerable-library-detector)
5. [JS Secrets Scanner](#5-js-secrets-scanner)
6. [Cookie Attribute Auditor](#6-cookie-attribute-auditor)
7. [Third-Party Tracker Mapper](#7-third-party-tracker-mapper)
8. [High-Risk Browser API Detector](#8-high-risk-browser-api-detector)
9. [Prototype Pollution Scanner](#9-prototype-pollution-scanner)
10. [Cross-Tool Relationships](#10-cross-tool-relationships)

---

## 1. SRI Scanner

**Directory:** `sri_scanner/`
**Input files:** HTML snapshots + header JSON files

### What it detects

Subresource Integrity (SRI) is a browser security mechanism that lets a page declare a cryptographic hash of every external script or stylesheet it loads. If the fetched file doesn't match the hash, the browser refuses to execute it. Without SRI, any external resource the page loads - jQuery from a CDN, a Google Analytics snippet, a third-party widget - can be silently replaced by a compromised or hijacked CDN and the browser will execute it without question.

The scanner checks every `<script src="...">` and `<link rel="stylesheet">` tag for the presence of a valid `integrity` attribute. It also parses the HTTP response headers for the full security header stack: Content Security Policy (including whether the policy enforces SRI via `require-sri-for`), HTTP Strict Transport Security, X-Frame-Options, X-Content-Type-Options, and X-XSS-Protection. Each snapshot gets a 0-10 security score based on which of these are present.

### The attack it guards against

A CDN compromise or domain expiry (Nikiforakis et al. showed that third-party JS providers frequently go offline or change ownership) allows an attacker to serve arbitrary JavaScript to every site that loads from that provider. Without SRI, the browser has no way to detect the substitution. With SRI, the hash mismatch causes the browser to block execution entirely.

### Supporting research

Chapuis et al., *"An Empirical Study of the Use of Integrity Verification Mechanisms for Web Subresources"* (WWW 2020) - analyzed 3 billion URLs from Common Crawl. Found 3.40% SRI adoption overall and 0.02% use of `require-sri-for` in CSP. External CDN resources are the primary use case. This is the direct methodological basis for the scanner.

### What the output shows

- SRI adoption rate per country and year
- Per-snapshot: how many external resources had SRI vs. how many didn't
- CSP presence and quality (does it have `require-sri-for`? `unsafe-inline`?)
- HSTS adoption timeline
- Security score distribution across countries and years

---

## 2. Clickjacking Detector

**Directory:** `clickjacking_detector/`
**Input files:** HTML snapshots + header JSON files

### What it detects

Clickjacking is an attack where a malicious page embeds the target site in a transparent or hidden iframe, positioned so that a user's click on what appears to be the malicious page's content actually registers on the target site underneath. Classic targets are "click to confirm" buttons - fund transfers, account deletion, permission grants. The attack requires no code injection into the target site; it exploits the browser's willingness to load any URL in an iframe.

The tool runs three separate analyses on each HTML snapshot:

**Frame analysis** - finds all `<iframe>` and `<frame>` elements, parses their CSS (inline styles and `<style>` blocks) to compute opacity, position, z-index, and visibility. Flags frames that are transparent (`opacity < 0.1`), off-screen, or zero-dimension, and cross-checks whether the frame's domain differs from the page's domain.

**Overlap analysis** - identifies clickable elements on the page (buttons, form submits, links, input fields) and calculates whether they are geometrically positioned under any suspicious frame. Flags high-value targets specifically: login buttons, payment forms, confirmation inputs.

**Defense analysis** - checks whether the site deployed any of the three standard defenses: `X-Frame-Options: DENY/SAMEORIGIN` in headers, `frame-ancestors` in CSP, or frame-busting JavaScript (`if (top !== self) top.location = self.location`). Notes that JavaScript-based frame-busting has well-documented bypasses and is classified as weak.

### The attack it guards against

A fully transparent cross-domain iframe positioned over a government portal's "approve transaction" or "submit application" button allows an attacker to trick authenticated citizens into performing actions they didn't intend. Government e-service portals handling benefits applications, tax submissions, or document renewals are high-value targets for this class of attack.

### Supporting research

Wang et al., *"Busting Frame Busting: A Study of Clickjacking Vulnerabilities on Popular Sites"* (IEEE S&P 2010) - demonstrated that JavaScript frame-busting, the most common defense at the time, was bypassable in all major browsers using a `<iframe security="restricted">` or `onbeforeunload` trick. Measured clickjacking vulnerability rates across popular sites and established the defense effectiveness hierarchy that this tool implements.

### What the output shows

- Risk level per snapshot (none / low / medium / high / critical) with scoring breakdown
- Count of suspicious frames, overlapping elements, and high-value targets at risk
- Defense posture per site: which mechanism (if any) was deployed and how strong it was
- Longitudinal view of when X-Frame-Options and CSP frame-ancestors adoption emerged

---

## 3. HTML Violation Analyzer

**Directory:** `html-violation-analyzer/`
**Input files:** HTML snapshots

### What it detects

This tool checks for structural HTML violations - cases where the markup deviates from the HTML specification in ways that browsers handle inconsistently. Browser parsing differences have historically been a significant attack surface: an attacker who knows that Browser A and Browser B parse malformed HTML differently can craft input that one browser treats as safe and the other executes as a script.

The rules are organized into four groups:

**DE (Document Errors)** - structural document problems:
- `DE1`: Unclosed `<textarea>` tag (reaches end of file without closing)
- `DE2`: Unclosed `<option>` element
- `DE3`: Various unclosed element variants
- `DE4`: Nested `<form>` elements - one form inside another, which the HTML spec forbids but browsers handle unpredictably

**DM (Document Misplacement)** - elements appearing outside their allowed section:
- `DM1`: `<meta http-equiv>` outside `<head>` - can affect page behavior when misplaced
- `DM2`: `<base>` tag outside `<head>` - the base tag changes how all relative URLs on the page are resolved; misplacing it produces inconsistent behavior across browsers
- `DM3`: Duplicate attribute names on the same element

**FB (Format/Bracket errors)** - malformed tag syntax:
- `FB1`: Slash used instead of space between attributes
- `FB2`: Missing spaces between attributes in a tag

**HF (Head/Footer violations)** - head/body boundary violations:
- `HF1`: Non-standard content in `<head>`
- `HF2`: Content between `</head>` and `<body>` that gets handled differently per browser
- `HF3`: Two `<body>` opening tags
- `HF4`: Invalid content inside `<table>` elements
- `HF5`: Various head element ordering violations

### Why these matter for security

HTML parsing violations are the foundation of many historical XSS bypass techniques. When a browser's error-recovery parser handles malformed markup differently from a WAF or server-side sanitizer, payloads that appear safe to the validator reach the browser in executable form. The longitudinal view here is about measuring how many government sites were serving structurally broken HTML - which indicates both low development quality and elevated parser-confusion risk.

### Supporting research

The rules implement behavior documented across:
Weinberger et al., *"A Systematic Analysis of XSS Sanitization in Web Application Frameworks"* (ESORICS 2011) - demonstrated how parser discrepancies between sanitization and rendering create XSS bypass vectors.
WHATWG HTML Living Standard parsing specification - defines the normative error-recovery behavior that browsers are required to implement.

### What the output shows

- Per-rule violation counts by country and year
- Which rule categories are most violated (DE vs. DM vs. FB vs. HF)
- Whether violation rates decreased over time as HTML tooling improved
- Year-by-year quality signal for each country's government web presence

---

## 4. Retire.js - Vulnerable Library Detector

**Directory:** `retire-custom/`
**Input files:** JavaScript files + HTML snapshots

### What it detects

Retire.js maintains a database of JavaScript library versions with known CVEs - jQuery 1.x with XSS vulnerabilities, AngularJS versions with sandbox escapes, Moment.js with ReDoS vulnerabilities, Bootstrap with XSS gadgets, and hundreds of others. The tool scans extracted JS files and inline scripts, identifies library version strings, and cross-references them against the vulnerability database.

The wrapper here extends the core Retire.js CLI with structured output - JSON and CSV reports organized by country, domain, year, and severity - making it tractable for longitudinal analysis across 91,570 snapshots.

### The attack it guards against

Vulnerable library inclusion is consistently one of the most common findings in web security assessments. A site running jQuery 1.6.4 is vulnerable to `$.html()` XSS. A site with Lodash 4.17.4 is vulnerable to prototype pollution (CVE-2019-10744). A site with Bootstrap 3.3.5 has a known XSS gadget in its tooltip component. These are not theoretical - they are documented, public vulnerabilities with proof-of-concept exploits, in libraries that government sites included for years after the patches were available.

The longitudinal angle is particularly compelling: you can see exactly when vulnerable versions appear in the archive, whether they persisted for months or years after the patch was released, and whether they were eventually updated.

### Supporting research

Lauinger et al., *"Thou Shalt Not Depend on Me: Analysing the Use of Outdated JavaScript Libraries on the Web"* (NDSS 2017) - scanned 133,000 websites and found 37% included at least one library with a known vulnerability. More than half of sites with jQuery included a version with a known XSS vulnerability. Showed that library update lag is measured in years, not weeks.

Nikiforakis et al., *"You Are What You Include"* (CCS 2012) - established that third-party JS inclusion represents a transitive trust relationship; a vulnerable library is an attack surface regardless of whether it was written in-house or loaded from a CDN.

### What the output shows

- Vulnerable library findings with CVE IDs, severity, and version
- Which libraries are most commonly found in vulnerable versions across the dataset
- Longitudinal view: how long specific vulnerable versions persisted per domain
- Country-level comparison of update hygiene

---

## 5. JS Secrets Scanner

**Directory:** `js-secrets-scanner/`
**Input files:** JavaScript files + HTML inline scripts

### What it detects

Hardcoded credentials, API keys, and secrets embedded directly in client-side JavaScript. This happens because production code that runs in the browser needs to authenticate against external services - mapping APIs, analytics platforms, payment processors, cloud services - and developers frequently embed those credentials directly in the JS bundle. Once embedded, the credentials are visible to anyone who opens browser devtools or, in our case, anyone who queries the Wayback Machine.

The scanner applies 17 regex patterns across two severity tiers:

**Format-specific patterns** (low false positive rate - the match structure itself implies the type):
- AWS access key IDs: `AKIA[0-9A-Z]{16}`
- Google API keys: `AIza[0-9A-Za-z-_]{35}` (Maps, Firebase, YouTube, Places)
- Firebase config blocks (the `apiKey:` field in `initializeApp()` calls)
- Stripe live secret keys: `sk_live_...`
- GitHub personal access tokens: `ghp_...`
- PEM private key headers: `-----BEGIN PRIVATE KEY-----`
- Mapbox tokens: `pk.eyJ1...`
- SendGrid and Mailgun keys

**Context-based patterns** (variable name signals the intent):
- `apiKey = "long_value"`, `client_secret: "value"`, `password = "value"` (8+ chars)
- JWT tokens in assignment context
- Generic `access_token` / `auth_token` assignments

The Wayback Machine's JavaScript wrapper (`_wb_wombat`) appears at the start of every archived JS file and would generate massive false positives. The scanner identifies these lines by known markers and skips them before applying patterns. All matched values are redacted in output - only the first 6 characters and the match length are logged.

### The attack it guards against

A leaked Google Maps API key can be used by anyone to make billable API calls at the site's expense. A leaked AWS access key can mean full cloud account compromise. A leaked Stripe secret key enables direct payment fraud. A leaked Firebase API key + project configuration can expose a cloud database if the Firebase security rules are misconfigured (common). Government portals embedding these keys - particularly for mapping services, which are extremely prevalent - have inadvertently published credentials to the public archive.

### Supporting research

Intruder Security Research (2025) - scanned 5 million applications, found 42,000+ exposed tokens across 334 secret types. JavaScript bundles are consistently the highest-yield source.
Escape.tech research - scanned 189.5 million URLs, found 18,000+ exposed API secrets in client-side code.
TruffleHog and Gitleaks - open-source secret scanners whose combined ruleset forms the basis for the patterns implemented here.

### What the output shows

- Per-finding CSV: country, domain, year, timestamp, source file, pattern type, severity, line number, redacted context
- Summary by severity, pattern type, country, and year
- The longitudinal framing is key: first appearance and last appearance of a given key prefix estimates the exposure window

---

## 6. Cookie Attribute Auditor

**Directory:** `cookie-attribute-auditor/`
**Input files:** Header JSON files

### What it detects

Every `Set-Cookie` header in the archived HTTP responses is parsed and checked for three security attributes:

**HttpOnly** - prevents JavaScript from reading the cookie via `document.cookie`. Without it, any XSS vulnerability on the page can steal the session cookie in one line of code. This is the most directly impactful attribute for XSS-to-account-takeover escalation.

**Secure** - instructs the browser to only transmit the cookie over HTTPS connections. Without it, a session cookie sent over a plain HTTP request (even as a redirect or a mixed-content subrequest) travels in cleartext.

**SameSite** - controls whether the browser attaches the cookie to cross-site requests. `SameSite=Lax` (now the browser default in modern Chrome) blocks cookies on cross-site POST requests, which eliminates most CSRF attacks without requiring explicit token management. `SameSite=None` explicitly opts out of this protection. The absence of any SameSite value in older snapshots means the cookie was fully cross-site accessible.

Session-named cookies (PHPSESSID, JSESSIONID, ASP.NET_SessionId, `session`, `auth`, `token`, `jwt`, `userid`, `remember_me`, and variants) are flagged separately because the consequences of losing them are account takeover rather than preference leakage.

The tool also correctly strips the `x-archive-orig-` prefix from headers and filters out the Wayback Machine's own injected `Permissions-Policy: interest-cohort=()` header to avoid false attribution.

### The attack it guards against

Session cookie theft via XSS (HttpOnly prevents this), session cookie interception via network MITM on HTTP (Secure prevents this), and Cross-Site Request Forgery where an attacker's page forces an authenticated citizen's browser to submit a government form (SameSite prevents this). These are not exotic attacks - they are standard post-exploitation techniques that work on any session-managed application that doesn't configure its cookies correctly.

### Supporting research

Khodayari & Pellegrino, *"The State of the SameSite: Studying the Usage, Effectiveness, and Adequacy of SameSite Cookies"* (IEEE S&P 2022) - tracked SameSite adoption across Alexa top 500K sites from 2019 to 2021. Found only 18.94% of sites had adopted any SameSite value by 2021. 3.7% explicitly used `SameSite=None`, opting out of cross-site protection. The direct longitudinal measurement basis.

Barth, Jackson & Mitchell, *"Robust Defenses for Cross-Site Request Forgery"* (ACM CCS 2008) - the canonical CSRF paper. Analyzed the three standard defenses (secret tokens, Referer validation, custom request headers) and proposed the Origin header. Provides the theoretical framework for why SameSite matters.

### What the output shows

- Per-cookie findings with all attributes and risk flags
- `adoption_over_time.csv`: year-by-year table showing what percentage of cookies for each country had HttpOnly, Secure, and SameSite - the primary longitudinal dataset
- The table starts at 0% for all three attributes in the early 2000s and tracks adoption through to 2024, which is exactly the kind of temporal trajectory this project is built to capture

---

## 7. Third-Party Tracker Mapper

**Directory:** `thirdparty-tracker-mapper/`
**Input files:** HTML snapshots

### What it detects

Every `<script src="...">` tag in every HTML snapshot is extracted, its URL unwrapped from the Wayback Machine's rewriting (`web.archive.org/web/{timestamp}/https://original.com/...` → `https://original.com/...`), and classified into one of:

- **First-party** - same domain or subdomain as the page
- **CDN** - known trusted hosting provider (jsDelivr, cdnjs, unpkg, Bootstrap CDN, etc.)
- **ANALYTICS** - Google Analytics, Google Tag Manager, Adobe Analytics, Yandex Metrica, Hotjar, Heap, etc.
- **ADVERTISING** - DoubleClick, AdSense, LinkedIn Insight, Criteo, Bing Ads, Amazon Ads
- **SOCIAL** - Facebook Connect, Twitter Platform, AddThis, ShareThis
- **SUPPORT** - Intercom, chat widgets
- **Unknown third-party** - external but not in any known list

Additionally, inline `<script>` blocks are scanned for tracker initialization patterns (`gtag(`, `fbq('init',`, `_gaq.push(`, `dataLayer.push(`, `ym(`, etc.) that indicate an active tracker even when the include isn't visible in the static HTML.

### The attack it guards against

Two distinct risk dimensions:

**Privacy** - analytics and advertising trackers on government sites collect citizen behavioral data on behalf of third parties. A citizen accessing a benefits portal, a tax filing service, or a health department page while Google Tag Manager is running means their visit metadata (IP, browser, timing, page visited) is transmitted to Google. Government sites have no advertising business model justifying this. Any advertising tracker found is at minimum a policy question.

**Security** - every third-party script inclusion is a trust delegation. If the script provider's CDN is compromised, if their domain expires and gets re-registered, or if they are served malicious content by an upstream provider, the government site executes that code with full page privileges. Without SRI (cross-referenced with the SRI scanner), there is no verification whatsoever. Nikiforakis et al. documented the attack chain in detail.

### Supporting research

Nikiforakis et al., *"You Are What You Include: Large-Scale Evaluation of Remote JavaScript Inclusions"* (ACM CCS 2012) - mapped trust chains across 3 million pages. Found 88.45% of Alexa top 10,000 sites include at least one remote JS file. Identified expired-domain, typosquatting, and IP-based inclusion as attack vectors. Core threat model.

Lerner et al., *"Internet Jones and the Raiders of the Lost Trackers: An Archaeological Study of Web Tracking from 1996 to 2016"* (USENIX Security 2016) - **this paper also used the Wayback Machine on a longitudinal dataset**, which is essentially the same methodology used here. Found tracker prevalence grew from ~5% of pages in the early 2000s to ~40% by 2016. Traced the rise and fall of individual trackers as companies were acquired or shut down. The direct methodological predecessor.

### What the output shows

- `script_inclusions.csv`: every script tag, classified, with SRI presence flag
- `tracker_prevalence.csv`: year × tracker × occurrence count × unique domains - the primary longitudinal table, analogous to what Lerner et al. produced
- `thirdparty_summary.csv`: per year/country, what percentage of pages had at least one tracker
- AE pilot: 483 tracker inclusions, 1,480 inline tracker calls. Google Tag Manager present across 33 unique AE government domains, growing year-over-year from 2020 to 2025

---

## 8. High-Risk Browser API Detector

**Directory:** `high-risk-api-detector/`
**Input files:** JavaScript files + HTML inline scripts + header JSON files

### What it detects

Scans for JavaScript usage of browser APIs that carry elevated privacy or security risk when deployed on government-facing portals. The APIs are drawn from Snyder et al.'s cost-benefit analysis and grouped by risk category:

**PRIVACY** - APIs that expose user data without clear necessity:
- Geolocation (`navigator.geolocation.getCurrentPosition`) - physical location
- WebRTC PeerConnection (`new RTCPeerConnection()`) - real IP address disclosure, bypasses VPNs and proxies

**SECURITY** - APIs that access sensitive device capabilities:
- getUserMedia (`navigator.mediaDevices.getUserMedia`) - camera and microphone access
- getDisplayMedia - screen capture
- Web Bluetooth (`navigator.bluetooth.requestDevice`) - nearby Bluetooth devices
- Clipboard read (`navigator.clipboard.readText`) - silent clipboard access

**FINGERPRINTING** - APIs historically used as covert tracking channels:
- Battery Status API (`navigator.getBattery`) - removed from most browsers after fingerprinting research exposed the risk
- Vibration API (`navigator.vibrate`) - namesake of the Snyder et al. paper; no legitimate use on a government portal
- Device Motion/Orientation events - accelerometer and gyroscope data

**SECURITY/PAYMENT:**
- Payment Request API (`new PaymentRequest`) - hooks into browser-stored payment methods

The tool also parses `Permissions-Policy` and `Feature-Policy` headers to check whether the server is explicitly restricting these APIs at the HTTP level, and whether it does so for features the JS code is actually using. An important implementation note: the Wayback Machine injects its own `Permissions-Policy: interest-cohort=()` header on every archived response (their FLoC opt-out). The tool filters this out and only trusts `x-archive-orig-permissions-policy` for the original site's policy.

### The attack it guards against

Government portals that request geolocation, camera, or microphone access are collecting sensitive biometric or location data. If that data is also being sent to third-party trackers (cross-reference with the tracker mapper), the privacy implications compound. WebRTC specifically is used in targeted attacks to de-anonymize users behind VPNs - finding it on a government portal is a priority finding. The absence of `Permissions-Policy` headers means the server is not restricting any of these APIs even on pages that don't use them.

### Supporting research

Snyder, Taylor & Kanich, *"Most Websites Don't Need to Vibrate: A Cost-Benefit Approach to Improving Browser Security"* (ACM CCS 2017) - evaluated 74 Web API standards on CVE risk vs. usage utility. Found that blocking 15 of those 74 APIs would eliminate 52% of CVE-related browser code without breaking 94.7% of sites. Provides the risk classification framework directly implemented here.

### What the output shows

- `api_findings.csv`: per finding with API label, category, severity, line number, context
- `permissions_policy.csv`: per header file, which features the policy restricts and which sensitive features are absent from the policy
- AE pilot: 29 findings across 6 domains - 16 getUserMedia, 11 geolocation, 1 notifications, 1 device sensors. Only 57/1,305 header files had the original site's Permissions-Policy

---

## 9. Prototype Pollution Scanner

**Directory:** `prototype-pollution-scanner/`
**Input files:** JavaScript files + HTML inline scripts

### What it detects

Prototype pollution is a JavaScript vulnerability where an attacker injects properties into `Object.prototype` by controlling the keys of a merge or assignment operation. Because every JavaScript object inherits from `Object.prototype`, any property added there becomes visible across the entire runtime. An attacker who can set `Object.prototype.isAdmin = true` through a URL parameter like `?__proto__[isAdmin]=true` - if the application passes that input to an unguarded recursive merge function - has effectively injected a property into every object on the page.

The scanner identifies three categories of patterns:

**VULNERABLE** - code structures that are dangerous if user-controlled input reaches them:
- For-in loop with bracket-notation assignment (`for (var k in src) { dst[k] = src[k]; }`) - the canonical unsafe merge pattern
- jQuery `.extend(true, ...)` deep merge - vulnerable before version 3.4.0 (CVE-2019-11358)
- Lodash `merge()` and `defaultsDeep()` - vulnerable before 4.17.11 (CVE-2019-10744)
- `Object.prototype[key] = value` direct assignment with a variable key
- JSON.parse output fed directly into a merge operation

**INDICATOR** - not inherently exploitable but worth reviewing:
- `__proto__` string references
- `.constructor.prototype` access (the second pollution pathway)
- `Object.assign` calls (safe alone, but often adjacent to vulnerable recursive branches)

**DEFENSIVE** - patterns showing prototype-awareness (positive signals):
- `Object.freeze(Object.prototype)` - strongest available defense
- `Object.create(null)` - null-prototype dictionaries
- `hasOwnProperty.call()` guards in loops
- Explicit key blocklist checks (`key !== '__proto__'`)

The scanner operates on the full file text rather than line-by-line, which is important for minified JavaScript where entire codebases are compressed to a single line. The Wayback Machine wrapper is stripped before scanning.

### The attack it guards against

A successful prototype pollution attack on a government portal can lead to XSS (if the polluted property reaches a DOM sink), CSRF bypass (if authentication checks inherit a spoofed property), cookie manipulation, or denial of service (if a function or configuration object inherits an unexpected property that breaks execution). Kang et al. found that of their 2,738 vulnerable sites, 48 had gadget chains leading to XSS and 736 to cookie manipulation. Government sites from 2015-2019 are in exactly the era when vulnerable lodash and jQuery versions were widely deployed.

### Supporting research

Kang, Li & Cao, *"Probe the Proto: Measuring Client-Side Prototype Pollution Vulnerabilities of One Million Real-world Websites"* (NDSS 2022) - the first large-scale measurement of client-side prototype pollution. Found 2,738 vulnerable sites in the Alexa top 1M, including 10 in the top 1,000. Classified impacts: 48 → XSS, 736 → cookie manipulation, 830 → URL manipulation. Direct methodological basis.

Shcherbakov & Balliu, *"Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js"* (USENIX Security 2023) - extended the attack to server-side Node.js, demonstrating RCE via prototype pollution through static taint analysis. The taint analysis concepts inform the pattern selection.

CVE-2019-11358 (jQuery < 3.4.0) and CVE-2019-10744 (Lodash < 4.17.11) - the specific library vulnerabilities that make the jQuery and Lodash patterns VULNERABLE-rated rather than INDICATOR-rated.

### What the output shows

- `pollution_findings.csv`: per-pattern match with category (VULNERABLE/INDICATOR/DEFENSIVE), severity, context
- `domain_summary.csv`: per (country, domain, year) aggregated counts of vulnerable vs. defensive patterns - the primary longitudinal table
- AE pilot: 717 VULNERABLE patterns, 1,750 INDICATOR patterns, 332 DEFENSIVE patterns across 48 domains. 598 unsafe for-in bracket assignments, 114 jQuery deep extends

---

## 10. Cross-Tool Relationships

The tools are designed to complement each other. Several findings only become meaningful when two tools are cross-referenced.

### High-confidence compound findings

| Tool A finding | Tool B finding | Combined significance |
|----------------|----------------|----------------------|
| Tracker mapper: script loaded without SRI | SRI scanner: no SRI policy | Unverified third-party code with no enforcement mechanism |
| Secrets scanner: Google API key in JS | Tracker mapper: GTM or analytics present | Credentials exposed to third-party telemetry |
| Cookie auditor: session cookie missing HttpOnly | HTML violation analyzer: malformed HTML | XSS-facilitating HTML on a page with stealable session cookies |
| Prototype pollution: vulnerable for-in merge | Retire.js: Lodash < 4.17.11 detected | Confirmed library version makes the pattern exploitable |
| API detector: getUserMedia + geolocation | Tracker mapper: advertising trackers present | Sensitive device data accessible to third-party scripts |
| Clickjacking: no X-Frame-Options | Cookie auditor: session cookies present | Authenticated session is clickjackable |
| Prototype pollution: vulnerable patterns, no defense | Retire.js: jQuery < 3.4.0 | CVE-2019-11358 is directly applicable |

### Longitudinal signal hierarchy

For tracking security posture over time, the richest longitudinal signals are:

1. **Cookie attribute adoption** (`adoption_over_time.csv`) - clear year-by-year trajectory from 0% to partial adoption
2. **Tracker prevalence** (`tracker_prevalence.csv`) - shows which trackers appeared, grew, and disappeared
3. **Prototype pollution** (`domain_summary.csv`) - vulnerable vs. defensive pattern counts per year
4. **Retire.js findings** - specific library CVEs with version and year of first/last appearance
5. **SRI adoption** - year-by-year adoption rate against the 3.40% global baseline from WWW 2020

### Running the full pipeline

Each tool is independent and can be run in any order. A full country sweep runs all tools against all data for a single country code:

```bash
# From archive-sec-analysis/
cd sri_scanner         && python scanner.py ../snapshot_data --country AE
cd ../clickjacking_detector && python main.py --input-dir ../snapshot_data/AE
cd ../html-violation-analyzer && python main.py --module local_files
cd ../retire-custom    && node retire-analyzer.js --path ../../snapshot_js_data/AE
cd ../js-secrets-scanner       && python main.py --country AE
cd ../cookie-attribute-auditor && python main.py --country AE
cd ../thirdparty-tracker-mapper && python main.py --country AE
cd ../high-risk-api-detector   && python main.py --country AE
cd ../prototype-pollution-scanner && python main.py --country AE
```

All tools except clickjacking_detector use `--all` to sweep all 16 countries.

---

*Document prepared for expert review. Dataset: 91,570 snapshots, 16 countries (AE, BA, BO, CL, DE, EG, GE, ID, JP, MA, NG, PK, RO, SG, UA, ZA), 2003-2024.*
