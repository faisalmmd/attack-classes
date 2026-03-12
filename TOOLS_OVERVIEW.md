# Security Analysis Pipeline - Tools Overview

**Project:** Longitudinal Security Analysis of Government Web Snapshots
**Dataset:** ~91,570 archived snapshots, 16 countries, 2003-2024 (Internet Archive Wayback Machine)

---

## Dataset Structure (Quick Reference)

```
snapshot_data/{CC}/{domain}/
    {year}_headers_{domain}_{timestamp}.json   <- HTTP response headers
    {year}_index_{domain}_{timestamp}.html     <- Full archived HTML page

snapshot_js_data/{CC}/{domain}/
    {year}_{timestamp}_script_N.js             <- Extracted JavaScript files
```

---

## Tools

### 1. SRI Scanner
**Directory:** `sri_scanner/`

Checks every external script and stylesheet tag for a cryptographic integrity hash (SRI), and audits the full security header stack (CSP, HSTS, X-Frame-Options) per snapshot to produce a 0-10 security score.

**Paper:** Chapuis et al., "An Empirical Study of the Use of Integrity Verification Mechanisms for Web Subresources," WWW 2020.

---

### 2. Clickjacking Detector
**Directory:** `clickjacking_detector/`

Detects transparent or hidden cross-domain iframes positioned over high-value interactive elements (login buttons, form submits), and checks whether the site deployed any frame-embedding defense via headers or JS frame-busting.

**Paper:** Wang et al., "Busting Frame Busting: A Study of Clickjacking Vulnerabilities on Popular Sites," IEEE S&P 2010.

---

### 3. HTML Violation Analyzer
**Directory:** `html-violation-analyzer/`

Flags structural HTML spec violations (unclosed elements, misplaced tags, malformed attributes, nested forms) that cause inconsistent browser parsing behavior and have historically enabled XSS filter bypasses.

**Paper:** Weinberger et al., "A Systematic Analysis of XSS Sanitization in Web Application Frameworks," ESORICS 2011.

---

### 4. Retire.js - Vulnerable Library Detector
**Directory:** `retire-custom/`

Identifies JavaScript library version strings in JS files and inline scripts and cross-references them against a CVE database of known-vulnerable versions (jQuery, AngularJS, Lodash, Bootstrap, and hundreds of others).

**Paper:** Lauinger et al., "Thou Shalt Not Depend on Me: Analysing the Use of Outdated JavaScript Libraries on the Web," NDSS 2017.

---

### 5. JS Secrets Scanner
**Directory:** `js-secrets-scanner/`

Scans JavaScript files and inline scripts for hardcoded credentials and API keys using 17 format-specific and context-based regex patterns covering AWS, Google, Firebase, Stripe, GitHub, Mapbox, and generic token assignment patterns.

**Reference:** Intruder Security Research (2025); TruffleHog and Gitleaks open-source secret scanner rulesets.

---

### 6. Cookie Attribute Auditor
**Directory:** `cookie-attribute-auditor/`

Parses every Set-Cookie header in the archived responses and checks for the presence of HttpOnly, Secure, and SameSite attributes, with session-named cookies flagged separately for higher-impact risk assessment.

**Papers:** Khodayari & Pellegrino, "The State of the SameSite," IEEE S&P 2022. Barth, Jackson & Mitchell, "Robust Defenses for Cross-Site Request Forgery," ACM CCS 2008.

---

### 7. Third-Party Tracker Mapper
**Directory:** `thirdparty-tracker-mapper/`

Classifies every external script inclusion and inline tracker initialization call (GTM, GA, fbq, etc.) per page into analytics, advertising, social, CDN, or unknown categories to map third-party trust delegation and surveillance presence over time.

**Papers:** Nikiforakis et al., "You Are What You Include," ACM CCS 2012. Lerner et al., "Internet Jones and the Raiders of the Lost Trackers," USENIX Security 2016.

---

### 8. High-Risk Browser API Detector
**Directory:** `high-risk-api-detector/`

Detects JavaScript usage of privacy- and security-sensitive browser APIs (geolocation, WebRTC, getUserMedia, battery status, vibration, clipboard read) and checks whether Permissions-Policy headers restrict those APIs at the server level.

**Paper:** Snyder, Taylor & Kanich, "Most Websites Don't Need to Vibrate: A Cost-Benefit Approach to Improving Browser Security," ACM CCS 2017.

---

### 9. Prototype Pollution Scanner
**Directory:** `prototype-pollution-scanner/`

Identifies unsafe merge patterns, vulnerable jQuery and Lodash deep-merge calls, and direct Object.prototype assignments that allow attacker-controlled input to inject properties inherited by every object in the runtime, alongside defensive countermeasures like Object.freeze and hasOwnProperty guards.

**Papers:** Kang, Li & Cao, "Probe the Proto: Measuring Client-Side Prototype Pollution Vulnerabilities of One Million Real-world Websites," NDSS 2022. Shcherbakov & Balliu, "Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js," USENIX Security 2023.

---

### 10. Open Redirect Scanner
**Directory:** `open-redirect-scanner/`

Detects JavaScript redirect sinks (location.href, location.replace, location.assign), user-controllable URL sources (location.search, location.hash, URLSearchParams), and confirmed source-to-sink chains where attacker input flows directly into a navigation call without domain validation.

**Papers:** Lekies, Stock & Johns, "25 Million Flows Later: Large-scale Detection of DOM-based XSS," ACM CCS 2013. Pellegrino, Johns, Koch & Backes, "Deemon: Detecting CSRF with Dynamic Analysis and Property Graphs," ACM CCS 2017.

---

### 11. DOM Clobbering Detector
**Directory:** `dom-clobbering-detector/`

Finds HTML elements whose name or id attribute matches a security-sensitive JavaScript global, JS code that accesses those globals in clobbering-susceptible ways, and confirmed in-page collisions where both the named element and the vulnerable JS access coexist in the same HTML snapshot.

**Papers:** Lekies, Jonker & Johns, "DOM Clobbering Strikes Back," USENIX Security 2021. Khodayari & Pellegrino, "It's (DOM) Clobbering Time: Attack Techniques, Prevalence, and Defenses," IEEE S&P 2023.

---

## Cross-Tool Relationships

| Tool A finding | Tool B finding | Combined signal |
|---|---|---|
| Tracker mapper: script without SRI | SRI scanner: no SRI policy | Unverified third-party code with no enforcement |
| Secrets scanner: API key in JS | Tracker mapper: GTM or analytics present | Credentials exposed to third-party telemetry |
| Cookie auditor: session cookie missing HttpOnly | HTML violation analyzer: malformed HTML | XSS-facilitating markup on a page with stealable cookies |
| Prototype pollution: vulnerable merge | Retire.js: Lodash < 4.17.11 | CVE-2019-10744 directly applicable |
| API detector: getUserMedia + geolocation | Tracker mapper: advertising trackers | Sensitive device data accessible to third parties |
| Clickjacking: no X-Frame-Options | Cookie auditor: session cookies present | Authenticated session is clickjackable |
| Open redirect: CHAIN finding | Cookie auditor: session cookies present | Redirect exploitable in authenticated login flow |
| DOM clobbering: CHAIN finding | Prototype pollution: VULNERABLE patterns | Two independent paths to global state manipulation |

---

## Running the full pipeline

```bash
cd sri_scanner              && python scanner.py ../snapshot_data --country AE
cd ../clickjacking_detector && python main.py --country AE
cd ../html-violation-analyzer && python main.py --country AE
cd ../retire-custom         && node retire-analyzer.js --path ../../snapshot_js_data/AE
cd ../js-secrets-scanner    && python main.py --country AE
cd ../cookie-attribute-auditor && python main.py --country AE
cd ../thirdparty-tracker-mapper && python main.py --country AE
cd ../high-risk-api-detector && python main.py --country AE
cd ../prototype-pollution-scanner && python main.py --country AE
cd ../open-redirect-scanner && python main.py --country AE
cd ../dom-clobbering-detector && python main.py --country AE
```

---

*Dataset: 91,570 snapshots, 16 countries (AE, BA, BO, CL, DE, EG, GE, ID, JP, MA, NG, PK, RO, SG, UA, ZA), 2003-2024.*
