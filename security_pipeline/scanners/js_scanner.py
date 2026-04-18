"""
JavaScript Security Scanner
Tests: prototype pollution, open redirect, high-risk APIs, dangerous sinks,
       JSONP callback, ReDoS, service worker, cryptominer, postMessage
"""

import re
import os
from dataclasses import dataclass, field
from typing import List

@dataclass
class Finding:
    test_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path: str
    line_number: int
    line_content: str
    description: str


class JavaScriptScanner:
    """Runs all JavaScript security tests on a single file."""

    # File extensions this scanner handles
    EXTENSIONS = {".js", ".mjs", ".jsx", ".ts", ".tsx"}

    def scan(self, file_path: str) -> List[Finding]:
        """Run all JS tests on one file. Returns list of findings."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return []

        lines = content.split("\n")
        findings = []

        findings.extend(self._test_prototype_pollution(file_path, lines))
        findings.extend(self._test_open_redirect(file_path, lines))
        findings.extend(self._test_high_risk_apis(file_path, lines))
        findings.extend(self._test_dangerous_sinks(file_path, lines))
        findings.extend(self._test_jsonp_callback(file_path, lines))
        findings.extend(self._test_redos(file_path, lines, content))
        findings.extend(self._test_service_worker(file_path, lines))
        findings.extend(self._test_cryptominer(file_path, lines, content))
        findings.extend(self._test_postmessage(file_path, lines, content))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 1: Prototype Pollution
    # Sources:
    #   Kang et al., "Probe the Proto: Measuring Client-Side Prototype
    #   Pollution Vulnerabilities of One Million Real-world Websites,"
    #   NDSS 2022.
    #   Shcherbakov & Balliu, "Silent Spring: Prototype Pollution Leads to
    #   Remote Code Execution in Node.js," USENIX Security 2023.
    # ------------------------------------------------------------------ #

    # Wayback Machine wombat preamble noise - strip before scanning
    _WB_NOISE = re.compile(r'_____WB\$wombat|self\._wb_wombat|__WB_pmw', re.IGNORECASE)

    @staticmethod
    def _strip_wayback_preamble(text: str) -> str:
        lines = text.split('\n')
        clean = []
        for i, line in enumerate(lines):
            if i < 25 and JavaScriptScanner._WB_NOISE.search(line):
                continue
            clean.append(line)
        return '\n'.join(clean)

    @staticmethod
    def _char_to_line(text: str, pos: int) -> int:
        return text[:pos].count('\n') + 1

    def _test_prototype_pollution(self, fp: str, lines: list) -> List[Finding]:
        """
        Detect prototype pollution patterns using both line-level and full-text
        (DOTALL) scanning so minified single-line JS is covered.

        Pattern classes (following Kang et al. NDSS 2022 taxonomy):
          CRITICAL - direct Object.prototype mutation
          HIGH     - known-vulnerable library calls; constructor.prototype path;
                     unsafe for-in bracket-assign; JSON.parse-into-merge chain
          MEDIUM   - __proto__ bare property reference; __proto__ as string key
        """
        findings = []
        content = '\n'.join(lines)
        content = self._strip_wayback_preamble(content)
        seen = set()  # (pattern_id, line_number) to deduplicate

        def add(severity, line_num, line_text, desc, pat_id):
            key = (pat_id, line_num)
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    "prototype_pollution", severity, fp,
                    line_num, line_text.strip()[:200], desc
                ))

        # ── CRITICAL: direct Object.prototype mutation ──────────────────
        for pat, desc in [
            (r'Object\.prototype\s*\[',
             "Direct Object.prototype bracket assignment"),
            (r'Object\.prototype\s*\.\s*\w+\s*=',
             "Direct Object.prototype named property assignment"),
        ]:
            for m in re.finditer(pat, content):
                ln = self._char_to_line(content, m.start())
                add("CRITICAL", ln, lines[ln-1] if ln <= len(lines) else m.group(), desc, pat)

        # ── HIGH: known-vulnerable library merge calls ───────────────────
        lib_patterns = [
            (r'\$\.extend\s*\(\s*true\s*,',
             "jQuery $.extend(true,...) - prototype pollution in jQuery < 3.4.0 (CVE-2019-11358)",
             "jquery_extend"),
            (r'(?:_|lodash)\.merge\s*\(',
             "Lodash _.merge() - vulnerable in versions < 4.17.12 (CVE-2018-3721)",
             "lodash_merge"),
            (r'(?:_|lodash)\.defaultsDeep\s*\(',
             "Lodash _.defaultsDeep() - prototype pollution (CVE-2019-10744)",
             "lodash_defaultsDeep"),
            (r'(?:_|lodash)\.set\s*\(',
             "Lodash _.set() - pollution if path is user-controlled",
             "lodash_set"),
        ]
        for pat, desc, pid in lib_patterns:
            for m in re.finditer(pat, content):
                ln = self._char_to_line(content, m.start())
                add("HIGH", ln, lines[ln-1] if ln <= len(lines) else m.group(), desc, pid)

        # ── HIGH: constructor.prototype access path ──────────────────────
        # Attacker sends ?constructor[prototype][x]=y to reach Object.prototype
        # via this chain. Absent from original scanner; flagged by Kang et al.
        for m in re.finditer(r'\.constructor\s*\.\s*prototype\b', content):
            ln = self._char_to_line(content, m.start())
            add("HIGH", ln,
                lines[ln-1] if ln <= len(lines) else m.group(),
                "constructor.prototype access - second common pollution pathway "
                "(?constructor[prototype][x]=y bypasses __proto__ filters)",
                "constructor_proto")

        # ── HIGH: unsafe for-in with bracket-assign (DOTALL for minified) ─
        # The canonical merge pattern: for(var k in src){dst[k]=src[k]}
        # Without hasOwnProperty guard, __proto__ key pollutes the chain.
        for m in re.finditer(
            r'for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+\w+\s*\)[^;{]{0,120}\[\s*\w+\s*\]\s*=',
            content, re.DOTALL
        ):
            ln = self._char_to_line(content, m.start())
            snippet = m.group().replace('\n', ' ')[:200]
            add("HIGH", ln, snippet,
                "Unsafe for-in with bracket-assign - classic merge pattern vulnerable "
                "to prototype pollution if no hasOwnProperty guard is present",
                "forin_bracket")

        # ── HIGH: JSON.parse result piped directly into merge/assign ────
        # If the JSON string is user-controlled, this is a complete attack chain.
        for m in re.finditer(
            r'JSON\.parse\s*\([^)]+\)[^;]{0,80}(?:Object\.assign|for\s*\(|\bmerge\s*\()',
            content, re.DOTALL
        ):
            ln = self._char_to_line(content, m.start())
            snippet = m.group().replace('\n', ' ')[:200]
            add("HIGH", ln, snippet,
                "JSON.parse result used directly in merge/assign - complete pollution "
                "chain if the JSON source is user-controlled",
                "json_parse_merge")

        # ── HIGH: __proto__ used in an assignment (clear attack) ─────────
        # Matches obj.__proto__.x = ... or obj.__proto__[k] = ...
        for m in re.finditer(r'__proto__\s*[\.\[]\s*\w+.*?=', content):
            ln = self._char_to_line(content, m.start())
            add("HIGH", ln,
                lines[ln-1] if ln <= len(lines) else m.group(),
                "__proto__ property/bracket assignment - direct prototype pollution",
                "dunder_proto_assign")

        # ── MEDIUM: __proto__ bare property reference ────────────────────
        for m in re.finditer(r'__proto__', content):
            ln = self._char_to_line(content, m.start())
            add("MEDIUM", ln,
                lines[ln-1] if ln <= len(lines) else m.group(),
                "Reference to __proto__ property - direct pollution vector or "
                "input validation point; review context",
                "dunder_proto")

        # ── MEDIUM: __proto__ as quoted string key ───────────────────────
        # Catches obj["__proto__"] access and key-blocklist checks
        for m in re.finditer(r'["\']__proto__["\']', content):
            ln = self._char_to_line(content, m.start())
            add("MEDIUM", ln,
                lines[ln-1] if ln <= len(lines) else m.group(),
                "\"__proto__\" as string key - may be a pollution attempt or a "
                "defensive key-blocklist check; review context",
                "proto_string_key")

        return findings

    # ------------------------------------------------------------------ #
    # TEST 4: Open Redirect
    # ------------------------------------------------------------------ #
    def _test_open_redirect(self, fp: str, lines: list) -> List[Finding]:
        findings = []
        # Redirect sinks
        # Sources: Khodayari et al. NDSS 2025 Table II (20,898 confirmed flows)
        sink_patterns = [
            (r'location\s*\.\s*href\s*=\s*(?![\"\']https?://[^\s]*?[\"\'])', "location.href assigned from variable"),
            (r'location\s*\.\s*replace\s*\((?![\"\'])', "location.replace() with variable argument"),
            (r'location\s*\.\s*assign\s*\((?![\"\'])', "location.assign() with variable argument"),
            (r'window\s*\.\s*open\s*\((?![\"\'])', "window.open() with variable argument"),
            # window.location = url (direct assignment, no .href) -- 996 confirmed flows in NDSS 2025
            (r'window\s*\.\s*location\s*=\s*(?![\"\'])', "window.location direct assignment from variable"),
            # frame/iframe .src assignment -- 367 confirmed flows in NDSS 2025
            (r'(?:iframe|frame)\s*\.\s*src\s*=\s*(?![\"\'])', "iframe/frame.src assigned from variable"),
        ]
        # User-controllable sources near sinks
        source_indicators = [
            'location.hash', 'location.search', 'location.href',
            'document.referrer', 'window.name', 'URLSearchParams',
            'getParameter', 'url_params', 'query_string', 'req.query',
            'document.URL', 'location.pathname',
        ]
        for i, line in enumerate(lines, 1):
            for pat, desc in sink_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    # Check if source indicators are nearby (within 5 lines)
                    context = "\n".join(lines[max(0, i-6):i+4])
                    has_source = any(src in context for src in source_indicators)
                    severity = "HIGH" if has_source else "MEDIUM"
                    extra = " (user-controllable source nearby)" if has_source else ""
                    findings.append(Finding(
                        "open_redirect", severity, fp, i,
                        line.strip()[:200], desc + extra
                    ))
        return findings

    # ------------------------------------------------------------------ #
    # TEST 5: High-Risk Browser APIs
    # ------------------------------------------------------------------ #
    def _test_high_risk_apis(self, fp: str, lines: list) -> List[Finding]:
        findings = []
        apis = [
            (r'navigator\s*\.\s*geolocation', "HIGH", "Geolocation API — exposes user physical location"),
            (r'navigator\s*\.\s*mediaDevices\s*\.\s*getUserMedia', "HIGH", "getUserMedia — camera/microphone access"),
            (r'new\s+RTCPeerConnection', "MEDIUM", "WebRTC — can leak local/private IP addresses"),
            (r'navigator\s*\.\s*clipboard\s*\.\s*read', "HIGH", "Clipboard read — access to copied sensitive data"),
            (r'navigator\s*\.\s*clipboard\s*\.\s*readText', "HIGH", "Clipboard readText — access to copied text"),
            (r'navigator\s*\.\s*credentials', "MEDIUM", "Credential Management API"),
            (r'new\s+PaymentRequest', "MEDIUM", "Payment Request API — financial data access"),
            (r'navigator\s*\.\s*bluetooth', "MEDIUM", "Web Bluetooth API — device access"),
            (r'navigator\s*\.\s*usb', "MEDIUM", "WebUSB API — device access"),
            (r'navigator\s*\.\s*serial', "MEDIUM", "Web Serial API — device access"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, desc in apis:
                if re.search(pat, line):
                    findings.append(Finding("high_risk_api", sev, fp, i, line.strip()[:200], desc))
        return findings

    # ------------------------------------------------------------------ #
    # TEST 6: Dangerous Sinks
    # ------------------------------------------------------------------ #
    def _test_dangerous_sinks(self, fp: str, lines: list) -> List[Finding]:
        findings = []
        sinks = [
            (r'(?:^|[^a-zA-Z_])eval\s*\(', "CRITICAL", "eval() — executes arbitrary code from string"),
            (r'new\s+Function\s*\(', "CRITICAL", "new Function() — creates function from string, equivalent to eval"),
            # String or template literal as first arg is direct eval equivalent
            (r'setTimeout\s*\(\s*[\'"`]', "CRITICAL",
             "setTimeout with string/template literal — directly equivalent to eval"),
            (r'setInterval\s*\(\s*[\'"`]', "CRITICAL",
             "setInterval with string/template literal — directly equivalent to eval"),
            # Variable as first arg is ambiguous (could be function ref or string var)
            (r'setTimeout\s*\(\s*(?!function|=>|\()\w+\s*[,\)]', "MEDIUM",
             "setTimeout with variable first arg — flag if variable could be a string"),
            (r'setInterval\s*\(\s*(?!function|=>|\()\w+\s*[,\)]', "MEDIUM",
             "setInterval with variable first arg — flag if variable could be a string"),
            (r'document\s*\.\s*write\s*\(', "HIGH", "document.write() — injects raw HTML into page"),
            (r'document\s*\.\s*writeln\s*\(', "HIGH", "document.writeln() — injects raw HTML into page"),
            (r'\.innerHTML\s*=\s*(?![\"\']<)', "HIGH", "innerHTML assignment from variable — XSS sink"),
            (r'\.outerHTML\s*=\s*(?![\"\']<)', "HIGH", "outerHTML assignment from variable — XSS sink"),
            (r'\.insertAdjacentHTML\s*\(', "MEDIUM", "insertAdjacentHTML() — injects parsed HTML"),
            (r'\.srcdoc\s*=', "MEDIUM", "iframe srcdoc assignment — can inject full HTML documents"),
            (r'\.src\s*=\s*(?![\'\"](https?://|data:image))',
             "MEDIUM", "Dynamic src assignment — possible script/iframe injection"),
            (r'createContextualFragment\s*\(', "MEDIUM",
             "createContextualFragment() — parses HTML string into DOM fragment"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, desc in sinks:
                if re.search(pat, line):
                    findings.append(Finding("dangerous_sink", sev, fp, i, line.strip()[:200], desc))
        return findings

    # ------------------------------------------------------------------ #
    # TEST 7: JSONP Callback Injection
    # ------------------------------------------------------------------ #
    def _test_jsonp_callback(self, fp: str, lines: list) -> List[Finding]:
        findings = []
        patterns = [
            (r'[?&]callback\s*=', "MEDIUM", "JSONP callback parameter in URL"),
            (r'[?&]jsonp\s*=', "MEDIUM", "JSONP parameter in URL"),
            (r'[?&]jsonpcallback\s*=', "MEDIUM", "JSONP callback parameter in URL"),
            (r'dataType\s*:\s*[\'"]jsonp[\'"]', "MEDIUM", "jQuery JSONP request configuration"),
            (r'jsonpCallback\s*:', "MEDIUM", "jQuery JSONP callback configuration"),
            (r'<script[^>]+src=[^>]*[?&]callback=', "HIGH",
             "Script tag loading JSONP endpoint — cross-domain data exposure"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, desc in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(Finding("jsonp_callback", sev, fp, i, line.strip()[:200], desc))
        return findings

    # ------------------------------------------------------------------ #
    # TEST 8: ReDoS (Regex Denial of Service)
    # ------------------------------------------------------------------ #
    def _test_redos(self, fp: str, lines: list, content: str) -> List[Finding]:
        findings = []
        # Find regex literals and RegExp constructors
        # Pattern: nested quantifiers like (a+)+, (a*)+, (a+)*, etc.
        redos_patterns = [
            (r'(\([^)]*[+*][^)]*\))[+*]', "Nested quantifier — potential catastrophic backtracking"),
            (r'(\([^)]*\|[^)]*\))[+*]', "Quantified alternation — potential backtracking"),
            (r'\([^)]*[+*]\)[+*]', "Nested quantifier in group — ReDoS candidate"),
        ]
        # Find regex literals: / ... /
        regex_literal = re.compile(r'(?<![/\w])/((?:[^/\\]|\\.)+)/[gimsuy]*')
        # Find RegExp constructors
        regexp_ctor = re.compile(r'new\s+RegExp\s*\(\s*[\'"](.+?)[\'"]\s*[,)]')

        for i, line in enumerate(lines, 1):
            # Extract regexes from this line
            regexes = []
            for m in regex_literal.finditer(line):
                regexes.append(m.group(1))
            for m in regexp_ctor.finditer(line):
                regexes.append(m.group(1))

            for regex_str in regexes:
                for pat, desc in redos_patterns:
                    if re.search(pat, regex_str):
                        findings.append(Finding(
                            "redos", "MEDIUM", fp, i,
                            line.strip()[:200],
                            f"{desc}: /{regex_str}/"
                        ))
                        break  # One finding per regex
        return findings

    # ------------------------------------------------------------------ #
    # TEST 9: Service Worker Scope Audit
    # ------------------------------------------------------------------ #
    def _test_service_worker(self, fp: str, lines: list) -> List[Finding]:
        findings = []
        patterns = [
            (r'serviceWorker\s*\.\s*register\s*\(',
             "MEDIUM", "Service worker registration detected"),
            (r'importScripts\s*\(',
             "MEDIUM", "importScripts() in service worker — check for external domains"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, desc in patterns:
                if re.search(pat, line):
                    # Check for broad scope
                    extra = ""
                    if 'register' in line:
                        scope_match = re.search(r'scope\s*:\s*[\'"]([^\'"]+)[\'"]', line)
                        if scope_match and scope_match.group(1) in ('/', '/*', '/.'):
                            sev = "HIGH"
                            extra = f" — BROAD SCOPE: '{scope_match.group(1)}'"
                        # Check for no scope (defaults to /)
                        if not scope_match and 'scope' not in line:
                            extra = " — no explicit scope (defaults to SW file directory)"
                    findings.append(Finding("service_worker", sev, fp, i, line.strip()[:200], desc + extra))
        return findings

    # ------------------------------------------------------------------ #
    # TEST 10: Cryptominer Detection (JS)
    # ------------------------------------------------------------------ #
    def _test_cryptominer(self, fp: str, lines: list, content: str) -> List[Finding]:
        findings = []
        # Known miner domains/URLs
        miner_domains = [
            'coinhive.com', 'coin-hive.com', 'coinhive.min.js',
            'cryptoloot.pro', 'crypto-loot.com', 'cryptoloot.min.js',
            'jsecoin.com', 'jsecoin.min.js',
            'webmine.cz', 'webminepool.com',
            'authedmine.com', 'authedmine.min.js',
            'mineralt.io', 'miner.pr0gramm.com',
            'webassembly.stream', 'wasm.stream',
            'ppoi.org', 'cryptonight.wasm',
            'minero.cc', 'webminerpool.com',
        ]
        # Known miner initialization patterns
        miner_patterns = [
            (r'CoinHive\.(?:Anonymous|Client|Token)', "CRITICAL", "Coinhive miner initialization"),
            (r'CryptoLoot\.(?:Anonymous|Client)', "CRITICAL", "CryptoLoot miner initialization"),
            (r'new\s+(?:Client|Miner)\s*\([\'"][a-zA-Z0-9]{20,}', "HIGH",
             "Miner client initialization with site key"),
            (r'miner\s*\.\s*start\s*\(', "MEDIUM", "Miner start() call"),
            (r'miner\s*\.\s*setThrottle\s*\(', "MEDIUM", "Miner throttle configuration"),
            (r'startMining|StartMining|start_mining', "MEDIUM", "Mining start function call"),
            (r'cryptonight|CryptoNight|stratum\+tcp', "HIGH", "CryptoNight algorithm or Stratum protocol reference"),
        ]

        content_lower = content.lower()
        # Check domains
        for domain in miner_domains:
            if domain.lower() in content_lower:
                # Find the line
                for i, line in enumerate(lines, 1):
                    if domain.lower() in line.lower():
                        findings.append(Finding(
                            "cryptominer_js", "CRITICAL", fp, i,
                            line.strip()[:200],
                            f"Known cryptominer domain/file: {domain}"
                        ))
                        break

        # Check patterns
        for i, line in enumerate(lines, 1):
            for pat, sev, desc in miner_patterns:
                if re.search(pat, line):
                    findings.append(Finding("cryptominer_js", sev, fp, i, line.strip()[:200], desc))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 11: postMessage Handler Audit
    # ------------------------------------------------------------------ #
    def _test_postmessage(self, fp: str, lines: list, content: str) -> List[Finding]:
        findings = []
        # Find message event listeners
        msg_listener_pattern = re.compile(
            r'addEventListener\s*\(\s*[\'"]message[\'"]\s*,\s*(?:function\s*\((\w+)\)|(\w+)\s*=>|(\w+))',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            match = msg_listener_pattern.search(line)
            if match:
                # Get the event parameter name
                event_param = match.group(1) or match.group(2) or match.group(3) or 'event'

                # Look ahead but stop at next addEventListener or end of block
                # Use a max of 15 lines or until next handler
                end_line = min(i + 15, len(lines))
                for j in range(i, end_line):
                    if j > i - 1 and 'addEventListener' in lines[j]:
                        end_line = j
                        break
                handler_block = "\n".join(lines[i-1:end_line])

                has_strict_origin = bool(re.search(
                    rf'(?<![a-zA-Z]){re.escape(event_param)}\s*\.\s*origin\s*===', handler_block
                ))
                has_weak_origin = bool(re.search(
                    rf'(?<![a-zA-Z]){re.escape(event_param)}\s*\.\s*origin\s*\.\s*(?:indexOf|includes|startsWith|match|search)\s*\(',
                    handler_block
                ))
                has_any_origin = bool(re.search(
                    rf'(?<![a-zA-Z]){re.escape(event_param)}\s*\.\s*origin', handler_block
                ))

                # Check if data flows into dangerous sinks (check both directions)
                has_data = bool(re.search(
                    rf'(?<![a-zA-Z]){re.escape(event_param)}\s*\.\s*data', handler_block
                ))
                has_sink = bool(re.search(
                    r'(?:innerHTML|outerHTML|eval\s*\(|document\.write|location\s*[.=]|\.src\s*=)',
                    handler_block
                ))
                data_to_sink = has_data and has_sink

                if not has_any_origin:
                    sev = "CRITICAL" if data_to_sink else "HIGH"
                    findings.append(Finding(
                        "postmessage_audit", sev, fp, i, line.strip()[:200],
                        "postMessage handler with NO origin validation"
                        + (" — data flows to dangerous sink!" if data_to_sink else "")
                    ))
                elif has_weak_origin and not has_strict_origin:
                    findings.append(Finding(
                        "postmessage_audit", "MEDIUM", fp, i, line.strip()[:200],
                        "postMessage handler with WEAK origin check "
                        "(indexOf/includes/startsWith — can be bypassed)"
                    ))


        # Also flag postMessage sends with wildcard origin
        for i, line in enumerate(lines, 1):
            if re.search(r'\.postMessage\s*\([^)]+,\s*[\'"]\*[\'"]', line):
                findings.append(Finding(
                    "postmessage_audit", "MEDIUM", fp, i, line.strip()[:200],
                    "postMessage sent with wildcard targetOrigin '*' — any page can receive it"
                ))

        return findings
