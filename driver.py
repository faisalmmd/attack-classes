#!/usr/bin/env python3
"""
==========================================================================
Web Archive Security Analysis Pipeline — Driver
==========================================================================

Usage:
    python driver.py /path/to/archived/files
    python driver.py /path/to/archived/files --output report.json
    python driver.py /path/to/archived/files --severity HIGH
    python driver.py /path/to/archived/files --ext .js .css
    python driver.py /path/to/archived/files --format json
    python driver.py /path/to/archived/files --format csv

This driver:
  1. Walks the given directory recursively
  2. Matches files by extension to the appropriate scanner
  3. Runs all applicable security tests
  4. Outputs findings as text, JSON, or CSV

Extensions handled:
  JavaScript:  .js  .mjs  .jsx  .ts  .tsx
  CSS:         .css
  XML:         .xml  .xsl  .xslt  .soap  .rss  .atom
  WebAssembly: .wasm
==========================================================================
"""

import os
import sys
import json
import csv
import time
import argparse
from io import StringIO
from dataclasses import dataclass, asdict
from typing import List, Dict
from collections import Counter

# Import scanners
from scanners.js_scanner import JavaScriptScanner, Finding as JSFinding
from scanners.css_scanner import CSSScanner, Finding as CSSFinding
from scanners.xml_scanner import XMLScanner, Finding as XMLFinding
from scanners.wasm_scanner import WASMScanner, Finding as WASMFinding
from scanners.html_scanner import HTMLScanner, Finding as HTMLFinding
from scanners.retire_scanner import RetireScanner, Finding as RetireFinding


# Unified Finding dataclass (all scanners use the same fields)
@dataclass
class Finding:
    test_name: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    description: str


# Severity ordering for sorting/filtering
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
}

# All supported extensions
ALL_EXTENSIONS = {
    ".html", ".htm",
    ".js", ".mjs", ".jsx", ".ts", ".tsx",
    ".css",
    ".xml", ".xsl", ".xslt", ".soap", ".rss", ".atom",
    ".wasm",
}


class PipelineDriver:
    """Orchestrates all scanners across a directory of archived web files."""

    def __init__(self):
        self.html_scanner = HTMLScanner()
        self.js_scanner = JavaScriptScanner()
        self.css_scanner = CSSScanner()
        self.xml_scanner = XMLScanner()
        self.wasm_scanner = WASMScanner()
        self.retire_scanner = RetireScanner()

        # Map extensions to scanners
        self.scanner_map = {}
        for ext in self.html_scanner.EXTENSIONS:
            self.scanner_map[ext] = self.html_scanner
        for ext in self.js_scanner.EXTENSIONS:
            self.scanner_map[ext] = self.js_scanner
        for ext in self.css_scanner.EXTENSIONS:
            self.scanner_map[ext] = self.css_scanner
        for ext in self.xml_scanner.EXTENSIONS:
            self.scanner_map[ext] = self.xml_scanner
        for ext in self.wasm_scanner.EXTENSIONS:
            self.scanner_map[ext] = self.wasm_scanner

    def collect_files(self, directory: str,
                      extensions: set = None) -> Dict[str, List[str]]:
        """Walk directory and collect files grouped by scanner type."""
        if extensions is None:
            extensions = ALL_EXTENSIONS

        files = {"html": [], "js": [], "css": [], "xml": [], "wasm": []}

        for root, dirs, filenames in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue
                full_path = os.path.join(root, fname)
                if ext in self.html_scanner.EXTENSIONS:
                    files["html"].append(full_path)
                elif ext in self.js_scanner.EXTENSIONS:
                    files["js"].append(full_path)
                elif ext in self.css_scanner.EXTENSIONS:
                    files["css"].append(full_path)
                elif ext in self.xml_scanner.EXTENSIONS:
                    files["xml"].append(full_path)
                elif ext in self.wasm_scanner.EXTENSIONS:
                    files["wasm"].append(full_path)

        return files

    def scan_all(self, directory: str,
                 extensions: set = None,
                 min_severity: str = None) -> List[Finding]:
        """
        Run all scanners on all matching files in directory.
        Returns list of unified Finding objects.
        """
        files = self.collect_files(directory, extensions)
        all_findings: List[Finding] = []

        total = sum(len(v) for v in files.values())
        scanned = 0
        start_time = time.time()

        print(f"\n{'='*70}")
        print(f"  WEB ARCHIVE SECURITY ANALYSIS PIPELINE")
        print(f"{'='*70}")
        print(f"  Target:   {os.path.abspath(directory)}")
        print(f"  Files:    {total} files to scan")
        print(f"    HTML:   {len(files['html'])}")
        print(f"    JS/TS:  {len(files['js'])}")
        print(f"    CSS:    {len(files['css'])}")
        print(f"    XML:    {len(files['xml'])}")
        print(f"    WASM:   {len(files['wasm'])}")
        print(f"{'='*70}\n")

        # --- HTML ---
        if files["html"]:
            print(f"[HTML] Scanning {len(files['html'])} HTML files...")
            for fp in files["html"]:
                scanned += 1
                raw = self.html_scanner.scan(fp)
                all_findings.extend(self._convert_findings(raw))
                if scanned % 100 == 0:
                    print(f"      ... {scanned}/{total} files processed")

        # --- JavaScript ---
        if files["js"]:
            print(f"[JS]  Scanning {len(files['js'])} JavaScript/TypeScript files...")
            for fp in files["js"]:
                scanned += 1
                raw = self.js_scanner.scan(fp)
                all_findings.extend(self._convert_findings(raw))
                if scanned % 100 == 0:
                    print(f"      ... {scanned}/{total} files processed")

        # --- CSS ---
        if files["css"]:
            print(f"[CSS] Scanning {len(files['css'])} CSS files...")
            for fp in files["css"]:
                scanned += 1
                raw = self.css_scanner.scan(fp)
                all_findings.extend(self._convert_findings(raw))

        # --- XML ---
        if files["xml"]:
            print(f"[XML] Scanning {len(files['xml'])} XML/XSLT files...")
            for fp in files["xml"]:
                scanned += 1
                raw = self.xml_scanner.scan(fp)
                all_findings.extend(self._convert_findings(raw))

        # --- Retire.js (vulnerable library detection on .js / .mjs) ---
        retire_files = [fp for fp in files["js"]
                        if os.path.splitext(fp)[1].lower() in {".js", ".mjs"}]
        if retire_files:
            print(f"[RET] Scanning {len(retire_files)} JS files for vulnerable libraries...")
            for fp in retire_files:
                raw = self.retire_scanner.scan(fp)
                all_findings.extend(self._convert_findings(raw))

        # --- WASM ---
        if files["wasm"]:
            print(f"[WASM] Scanning {len(files['wasm'])} WebAssembly files...")
            for fp in files["wasm"]:
                scanned += 1
                raw = self.wasm_scanner.scan(fp)
                all_findings.extend(self._convert_findings(raw))

        elapsed = time.time() - start_time

        # Filter by severity
        if min_severity:
            min_level = SEVERITY_ORDER.get(min_severity.upper(), 4)
            all_findings = [
                f for f in all_findings
                if SEVERITY_ORDER.get(f.severity, 4) <= min_level
            ]

        # Sort by severity
        all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

        print(f"\n{'='*70}")
        print(f"  SCAN COMPLETE")
        print(f"  Files scanned: {scanned}")
        print(f"  Time elapsed:  {elapsed:.2f}s")
        print(f"  Total findings: {len(all_findings)}")
        print(f"{'='*70}\n")

        return all_findings

    def _convert_findings(self, raw_findings) -> List[Finding]:
        """Convert scanner-specific Finding to unified Finding."""
        return [
            Finding(
                test_name=f.test_name,
                severity=f.severity,
                file_path=f.file_path,
                line_number=f.line_number,
                line_content=f.line_content,
                description=f.description,
            )
            for f in raw_findings
        ]


# ====================================================================== #
# ATTACK METADATA — maps test names to human-readable attack info
# ====================================================================== #

ATTACK_INFO = {
    "prototype_pollution": {
        "attack_name": "Prototype Pollution",
        "description": "Unsafe deep-merge or __proto__ access allows attacker to inject properties into Object.prototype, affecting every object in the runtime.",
        "impact": "Authentication bypass, XSS via template engines, remote code execution in Node.js",
        "exploitable_when": "User-controlled JSON is merged into objects without __proto__ filtering",
        "cwe": "CWE-1321",
    },
    "open_redirect": {
        "attack_name": "Open Redirect",
        "description": "User-controlled input flows into a navigation sink (location.href, location.replace) without domain validation.",
        "impact": "Phishing attacks using trusted domain, OAuth token theft, URL whitelist bypass",
        "exploitable_when": "URL parameters, hash, or referrer flow into redirect sinks",
        "cwe": "CWE-601",
    },
    "high_risk_api": {
        "attack_name": "High-Risk Browser API Usage",
        "description": "Privacy-sensitive browser APIs are invoked without corresponding Permissions-Policy restrictions.",
        "impact": "Location tracking, camera/mic surveillance, IP leak via WebRTC, clipboard theft",
        "exploitable_when": "Third-party scripts can invoke these APIs, or a compromised script inherits access",
        "cwe": "CWE-276",
    },
    "dangerous_sink": {
        "attack_name": "Dangerous Code Execution Sink",
        "description": "Functions that execute strings as code (eval, Function, innerHTML) are used with potentially attacker-controlled input.",
        "impact": "Cross-site scripting (XSS), arbitrary code execution, session hijacking",
        "exploitable_when": "User input from URL, postMessage, or API responses reaches these sinks",
        "cwe": "CWE-79 / CWE-95",
    },
    "jsonp_callback": {
        "attack_name": "JSONP Callback Injection",
        "description": "JSONP endpoints accept unsanitized callback parameters, or serve user data cross-origin without CSRF protection.",
        "impact": "Cross-domain data theft, reflected XSS via callback parameter",
        "exploitable_when": "Authenticated JSONP endpoints are reachable from attacker-controlled pages",
        "cwe": "CWE-352 / CWE-79",
    },
    "redos": {
        "attack_name": "Regular Expression Denial of Service (ReDoS)",
        "description": "Regex patterns with nested quantifiers cause exponential backtracking on crafted input.",
        "impact": "Client-side DoS (frozen browser tab), server-side DoS (blocked Node.js event loop)",
        "exploitable_when": "User input is tested against the vulnerable regex",
        "cwe": "CWE-1333",
    },
    "service_worker": {
        "attack_name": "Service Worker Security Issue",
        "description": "Service worker registered with broad scope, external importScripts, or cache-first strategy without validation.",
        "impact": "Persistent XSS surviving vulnerability patches, cache poisoning, request interception",
        "exploitable_when": "Attacker achieves XSS and registers a malicious SW, or SW caches poisoned responses",
        "cwe": "CWE-349",
    },
    "cryptominer_js": {
        "attack_name": "In-Browser Cryptocurrency Miner (JavaScript)",
        "description": "JavaScript code that mines cryptocurrency using visitor CPU resources.",
        "impact": "Unauthorized resource usage, degraded performance, elevated power consumption",
        "exploitable_when": "Miner script is present — it runs automatically when page loads",
        "cwe": "CWE-400",
    },
    "postmessage_audit": {
        "attack_name": "postMessage Handler Vulnerability",
        "description": "Message event handler missing or using weak origin validation, with message data flowing to dangerous sinks.",
        "impact": "Cross-origin XSS, data theft, state manipulation via crafted messages",
        "exploitable_when": "Target page is loaded in an iframe on attacker's site; attacker sends postMessage",
        "cwe": "CWE-346",
    },
    "css_attr_exfil": {
        "attack_name": "CSS Attribute Selector Data Exfiltration",
        "description": "CSS selectors probe input values character-by-character and leak them via background-image URL requests.",
        "impact": "CSRF token theft, password exfiltration — works even when CSP blocks all JavaScript",
        "exploitable_when": "Attacker can inject CSS (style tag or style attribute) on a page with sensitive form values",
        "cwe": "CWE-200",
    },
    "css_import_chain": {
        "attack_name": "CSS @import Chain Exfiltration",
        "description": "Chained @import rules to external domains enable single-injection-point data exfiltration without page reloads.",
        "impact": "Full token theft in <3 seconds via HTTP/2, persistent tracking via CSS",
        "exploitable_when": "Attacker can inject a <style> tag with @import; CSP allows style-src from external domains",
        "cwe": "CWE-200",
    },
    "css_font_keylog": {
        "attack_name": "CSS Font Ligature Keylogging",
        "description": "Custom @font-face with per-character unicode-range and external URLs leaks rendered text content.",
        "impact": "Exfiltration of displayed API keys, tokens, secrets, 2FA codes — no JavaScript needed",
        "exploitable_when": "Attacker can inject CSS targeting an element that displays sensitive text",
        "cwe": "CWE-200",
    },
    "xxe": {
        "attack_name": "XML External Entity (XXE) Injection",
        "description": "XML containing external entity definitions that reference local files, internal URLs, or parameter entities.",
        "impact": "Local file read (/etc/passwd), SSRF to internal services, out-of-band data exfiltration",
        "exploitable_when": "Server parses user-supplied XML with external entities enabled (most parsers default to enabled)",
        "cwe": "CWE-611",
    },
    "xml_bomb": {
        "attack_name": "XML Bomb / Billion Laughs",
        "description": "Nested entity definitions that expand exponentially, consuming gigabytes of memory from kilobytes of input.",
        "impact": "Denial of service — crashes the XML parser and potentially the entire server",
        "exploitable_when": "Server accepts XML input and parses it without entity expansion limits",
        "cwe": "CWE-776",
    },
    "xpath_injection": {
        "attack_name": "XPath Injection",
        "description": "XPath expressions built with unsanitized variables, allowing query manipulation.",
        "impact": "Authentication bypass, data extraction from XML stores, blind data theft",
        "exploitable_when": "User input is concatenated into XPath queries without parameterization",
        "cwe": "CWE-643",
    },
    "xslt_injection": {
        "attack_name": "XSLT Injection",
        "description": "Dangerous XSLT functions (document(), php:function(), msxsl:script) that enable file read, SSRF, or code execution.",
        "impact": "Remote code execution, arbitrary file read, SSRF, XSS via disable-output-escaping",
        "exploitable_when": "User can supply or influence XSLT stylesheets processed by the server",
        "cwe": "CWE-74",
    },
    "wasm_cryptominer": {
        "attack_name": "WebAssembly Cryptocurrency Miner",
        "description": "WASM binary containing cryptomining algorithm signatures (CryptoNight, Argon2, etc.).",
        "impact": "Unauthorized CPU mining at near-native speed, 10-20x faster than JS miners",
        "exploitable_when": "WASM module is loaded — it runs automatically with no user interaction",
        "cwe": "CWE-400",
    },
    "missing_sri": {
        "attack_name": "Missing Subresource Integrity (SRI)",
        "description": "External scripts/stylesheets loaded without integrity= hash, allowing CDN compromise to inject malicious code.",
        "impact": "Supply chain attack — compromised CDN serves malicious JS/CSS to all visitors",
        "exploitable_when": "External CDN serving the script/stylesheet is compromised or MITM'd",
        "cwe": "CWE-353",
    },
    "clickjacking": {
        "attack_name": "Clickjacking / Frame Injection",
        "description": "Page with interactive elements (forms, login) has no frame-busting defense, or contains hidden iframes overlaying clickable elements.",
        "impact": "User tricked into clicking attacker-controlled content, credential theft, unauthorized actions",
        "exploitable_when": "Target page can be loaded in an iframe on attacker's site",
        "cwe": "CWE-1021",
    },
    "base_tag_hijack": {
        "attack_name": "Base Tag Hijacking",
        "description": "<base href> tag pointing to external domain causes all relative URLs to resolve to attacker's server.",
        "impact": "Script injection, stylesheet hijacking, form submission redirect — all via relative URLs",
        "exploitable_when": "Attacker can inject a <base> tag (via HTML injection) before other relative URLs",
        "cwe": "CWE-79",
    },
    "meta_refresh_redirect": {
        "attack_name": "Meta Refresh Open Redirect",
        "description": "<meta http-equiv=refresh> redirects to external URL, potentially phishing or malware.",
        "impact": "Phishing via trusted domain, malware distribution, SEO spam redirect",
        "exploitable_when": "Meta refresh URL is external or user-controllable",
        "cwe": "CWE-601",
    },
    "form_action_hijack": {
        "attack_name": "Form Action Hijacking",
        "description": "Form submits over plain HTTP (leaking credentials) or to external domain, or button with formaction overrides destination.",
        "impact": "Credential theft via HTTP, form data sent to attacker's server",
        "exploitable_when": "Form handles sensitive data (login, payment) and action is HTTP or external",
        "cwe": "CWE-352",
    },
    "dangling_markup": {
        "attack_name": "Dangling Markup / JS-URL Injection",
        "description": "Unclosed HTML attributes that capture subsequent page content, or javascript:/data: URLs in href/src enabling XSS.",
        "impact": "Token theft via dangling markup, direct XSS via javascript: URLs",
        "exploitable_when": "Attacker has HTML injection point, or page contains javascript: URLs",
        "cwe": "CWE-79",
    },
    "html_violation": {
        "attack_name": "HTML Structural Violation",
        "description": "Unclosed elements, nested forms, block-in-inline, duplicate IDs causing inconsistent browser parsing.",
        "impact": "XSS filter bypass via parser confusion, DOM clobbering via duplicate IDs, form hijacking via nested forms",
        "exploitable_when": "Malformed HTML is processed by browser parsers that disagree on structure — attacker exploits the ambiguity",
        "cwe": "CWE-79",
    },
    "vulnerable_library": {
        "attack_name": "Vulnerable JavaScript Library",
        "description": "JavaScript library with known CVE — outdated jQuery, Lodash, AngularJS, Bootstrap, Handlebars, etc.",
        "impact": "Depends on CVE: XSS, prototype pollution, RCE, ReDoS. Many allow full session hijack.",
        "exploitable_when": "The vulnerable function is reachable with attacker-controlled input (varies by CVE)",
        "cwe": "varies",
    },
}


# ====================================================================== #
# OUTPUT FORMATTERS
# ====================================================================== #

def format_text(findings: List[Finding]) -> str:
    """Format findings as a full exploit report organized by attack type."""
    if not findings:
        return "=" * 70 + "\n  SECURITY REPORT: NO FINDINGS\n" + "=" * 70 + "\n\n  All scanned files passed. No vulnerabilities detected.\n"

    lines = []
    lines.append("=" * 70)
    lines.append("  WEB ARCHIVE SECURITY ANALYSIS REPORT")
    lines.append("=" * 70)

    # ---- EXECUTIVE SUMMARY ----
    total_files = len(set(f.file_path for f in findings))
    attack_types_detected = len(set(f.test_name for f in findings))

    lines.append(f"\n  EXECUTIVE SUMMARY")
    lines.append(f"  {'-'*50}")
    lines.append(f"  Attack types detected:    {attack_types_detected}")
    lines.append(f"  Files with findings:      {total_files}")
    lines.append(f"  Total evidence items:     {len(findings)}")

    # ---- ATTACK VECTOR SUMMARY TABLE ----
    lines.append(f"\n{'='*70}")
    lines.append(f"  ATTACK VECTORS DETECTED")
    lines.append(f"{'='*70}")

    # Group findings by test_name
    from collections import defaultdict
    by_attack = defaultdict(list)
    for f in findings:
        by_attack[f.test_name].append(f)

    # Sort attacks by worst severity, then count
    def attack_sort_key(item):
        test_name, attack_findings = item
        worst = min(SEVERITY_ORDER.get(f.severity, 4) for f in attack_findings)
        return (worst, -len(attack_findings))

    sorted_attacks = sorted(by_attack.items(), key=attack_sort_key)

    lines.append(f"\n  {'Attack':<42} {'Found?':<10} {'Evidence':>8}")
    lines.append(f"  {'-'*42} {'-'*10} {'-'*8}")

    for test_name, attack_findings in sorted_attacks:
        info = ATTACK_INFO.get(test_name, {})
        display_name = info.get("attack_name", test_name)
        lines.append(f"  {display_name:<42} {'YES':<10} {len(attack_findings):>8}")

    # ---- DETAILED FINDINGS BY ATTACK TYPE ----
    lines.append(f"\n{'='*70}")
    lines.append(f"  DETAILED FINDINGS BY ATTACK TYPE")
    lines.append(f"{'='*70}")

    for attack_idx, (test_name, attack_findings) in enumerate(sorted_attacks, 1):
        info = ATTACK_INFO.get(test_name, {})
        display_name = info.get("attack_name", test_name)
        description = info.get("description", "")
        impact = info.get("impact", "")
        exploitable_when = info.get("exploitable_when", "")
        cwe = info.get("cwe", "")

        status_label = "DETECTED"

        # Count evidence items for this attack
        affected_files = sorted(set(f.file_path for f in attack_findings))

        lines.append(f"\n{'─'*70}")
        lines.append(f"  ATTACK {attack_idx}: {display_name}")
        lines.append(f"  Status: {status_label}")
        if cwe:
            lines.append(f"  CWE: {cwe}")
        lines.append(f"{'─'*70}")

        if description:
            lines.append(f"\n  What: {description}")
        if impact:
            lines.append(f"  Impact: {impact}")
        if exploitable_when:
            lines.append(f"  Exploitable when: {exploitable_when}")

        lines.append(f"  Evidence items: {len(attack_findings)}")
        lines.append(f"  Affected files ({len(affected_files)}):")
        for af in affected_files[:20]:
            lines.append(f"    - {af}")
        if len(affected_files) > 20:
            lines.append(f"    ... and {len(affected_files) - 20} more")

        lines.append(f"\n  Vulnerable code locations:")
        lines.append(f"  {'─'*66}")

        # Group findings by file for cleaner output
        by_file = defaultdict(list)
        for f in attack_findings:
            by_file[f.file_path].append(f)

        finding_num = 0
        for fpath in sorted(by_file.keys()):
            file_findings = sorted(by_file[fpath], key=lambda f: (SEVERITY_ORDER.get(f.severity, 4), f.line_number))
            for f in file_findings:
                finding_num += 1
                lines.append(f"")
                lines.append(f"  [FOUND] Evidence {finding_num}")
                lines.append(f"    File: {f.file_path}")
                if f.line_number > 0:
                    lines.append(f"    Line: {f.line_number}")
                lines.append(f"    Why:  {f.description}")
                if f.line_content:
                    code = f.line_content[:120]
                    lines.append(f"    Code: {code}")

    # ---- FILES WITH MOST FINDINGS ----
    lines.append(f"\n{'='*70}")
    lines.append(f"  FILES WITH MOST FINDINGS")
    lines.append(f"{'='*70}")

    priority_files = Counter(f.file_path for f in findings)
    lines.append(f"\n  Files ranked by evidence count:")
    for fpath, count in priority_files.most_common(10):
        lines.append(f"    {count:>3} items  {fpath}")

    # ---- EXTERNAL TOOLS RECOMMENDED ----
    lines.append(f"\n{'='*70}")
    lines.append(f"  RECOMMENDED: RUN THESE EXTERNAL TOOLS TOO")
    lines.append(f"{'='*70}")
    lines.append(f"\n  TruffleHog (secret scanning across ALL files):")
    lines.append(f"    trufflehog filesystem --directory <your-archive-dir>")
    lines.append(f"    https://github.com/trufflesecurity/trufflehog")
    lines.append(f"\n  Retire.js (vulnerable JS library detection):")
    lines.append(f"    retire --path <your-archive-dir> --outputformat json")
    lines.append(f"    https://github.com/retirejs/retire.js")
    lines.append(f"\n  recheck (deep ReDoS analysis on extracted regexes):")
    lines.append(f"    https://github.com/nicolo-ribaudo/recheck")

    lines.append(f"\n{'='*70}")
    lines.append(f"  END OF REPORT")
    lines.append(f"{'='*70}")

    return "\n".join(lines)


def format_json(findings: List[Finding]) -> str:
    """Format findings as JSON with attack metadata."""
    from collections import defaultdict

    by_attack = defaultdict(list)
    for f in findings:
        by_attack[f.test_name].append(f)

    attacks = []
    for test_name, attack_findings in by_attack.items():
        info = ATTACK_INFO.get(test_name, {})
        worst_sev = min(attack_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 4)).severity
        attacks.append({
            "test_name": test_name,
            "attack_name": info.get("attack_name", test_name),
            "status": "EXPLOITABLE" if worst_sev in ("CRITICAL", "HIGH") else "REVIEW" if worst_sev == "MEDIUM" else "LOW_RISK",
            "worst_severity": worst_sev,
            "cwe": info.get("cwe", ""),
            "description": info.get("description", ""),
            "impact": info.get("impact", ""),
            "exploitable_when": info.get("exploitable_when", ""),
            "finding_count": len(attack_findings),
            "affected_files": sorted(set(f.file_path for f in attack_findings)),
            "severity_breakdown": dict(Counter(f.severity for f in attack_findings)),
        })

    attacks.sort(key=lambda a: SEVERITY_ORDER.get(a["worst_severity"], 4))

    data = {
        "summary": {
            "total_findings": len(findings),
            "exploitable_attacks": sum(1 for a in attacks if a["status"] == "EXPLOITABLE"),
            "review_needed": sum(1 for a in attacks if a["status"] == "REVIEW"),
            "files_with_findings": len(set(f.file_path for f in findings)),
            "by_severity": dict(Counter(f.severity for f in findings)),
        },
        "attacks": attacks,
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(data, indent=2)


def format_csv(findings: List[Finding]) -> str:
    """Format findings as CSV."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["test_name", "file_path", "line_number",
                      "description", "line_content"])
    for f in findings:
        writer.writerow([f.test_name, f.file_path,
                         f.line_number, f.description, f.line_content[:200]])
    return output.getvalue()


def format_matrix(findings: List[Finding], root_directory: str) -> str:
    """
    Binary 0/1 attack matrix CSV.
    Rows = first-level subdirectories of root_directory (one row per domain/subdir).
    Columns = each attack type (test_name) found anywhere in the scan.
    Cell = 1 if at least one finding of that attack exists in that directory, else 0.
    """
    root = os.path.abspath(root_directory)

    # All unique attack types in canonical order
    all_attack_types = sorted(set(f.test_name for f in findings))

    # Group by first-level subdirectory under root
    from collections import defaultdict
    dir_attacks: Dict[str, set] = defaultdict(set)

    for f in findings:
        try:
            file_abs = os.path.abspath(f.file_path)
            rel = os.path.relpath(file_abs, root)
        except ValueError:
            rel = f.file_path
        parts = rel.replace("\\", "/").split("/")
        subdir = parts[0] if len(parts) > 1 else "__root__"
        dir_attacks[subdir].add(f.test_name)

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["directory"] + all_attack_types)
    for subdir in sorted(dir_attacks.keys()):
        row = [subdir] + [1 if attack in dir_attacks[subdir] else 0
                          for attack in all_attack_types]
        writer.writerow(row)
    return output.getvalue()


# ====================================================================== #
# CLI
# ====================================================================== #

def main():
    parser = argparse.ArgumentParser(
        description="Web Archive Security Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python driver.py ./archived_site/
  python driver.py ./archived_site/ --output report.txt --matrix matrix.csv
  python driver.py ./archived_site/ --format json --output report.json
  python driver.py ./archived_site/ --ext .js .css
  python driver.py ./archived_site/ --format csv --output results.csv

Tests included:
  JavaScript (9 tests): prototype pollution, open redirect, high-risk APIs,
    dangerous sinks, JSONP callback, ReDoS, service worker, cryptominer,
    postMessage audit
  CSS (3 tests): attribute selector exfil, @import chaining, font ligature
    keylogging
  XML (4 tests): XXE, XML bomb, XPath injection, XSLT injection
  WASM (1 test): cryptominer detection

Note: Run TruffleHog separately for credential scanning:
  trufflehog filesystem --directory ./archived_site/

Note: Run Retire.js separately for vulnerable library detection:
  retire --path ./archived_site/ --outputformat json
        """
    )

    parser.add_argument("directory",
                        help="Path to directory containing archived web files")
    parser.add_argument("--output", "-o",
                        help="Output file path (default: stdout)")
    parser.add_argument("--format", "-f", choices=["text", "json", "csv"],
                        default="text",
                        help="Output format (default: text)")
    parser.add_argument("--severity", "-s",
                        choices=["CRITICAL", "HIGH", "MEDIUM"],
                        help="Minimum severity to report (default: all)")
    parser.add_argument("--ext", nargs="+",
                        help="Only scan these extensions (e.g., --ext .js .css)")
    parser.add_argument("--matrix", metavar="FILE",
                        help="Write binary 0/1 attack matrix CSV (dirs x attacks) to FILE")

    args = parser.parse_args()

    # Validate directory
    if not os.path.isdir(args.directory):
        print(f"Error: '{args.directory}' is not a directory", file=sys.stderr)
        sys.exit(1)

    # Parse extensions filter
    extensions = None
    if args.ext:
        extensions = set()
        for e in args.ext:
            if not e.startswith("."):
                e = "." + e
            e = e.lower()
            if e not in ALL_EXTENSIONS:
                print(f"Warning: '{e}' is not a supported extension, skipping",
                      file=sys.stderr)
            else:
                extensions.add(e)
        if not extensions:
            print("Error: no valid extensions specified", file=sys.stderr)
            sys.exit(1)

    # Run pipeline
    driver = PipelineDriver()
    findings = driver.scan_all(
        args.directory,
        extensions=extensions,
        min_severity=args.severity,
    )

    # Format output
    if args.format == "json":
        result = format_json(findings)
    elif args.format == "csv":
        result = format_csv(findings)
    else:
        result = format_text(findings)

    # Write evidence output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"Report written to: {args.output}")
    else:
        print(result)

    # Write binary matrix CSV
    if args.matrix:
        matrix_content = format_matrix(findings, args.directory)
        with open(args.matrix, "w", encoding="utf-8") as mf:
            mf.write(matrix_content)
        print(f"Attack matrix written to: {args.matrix}")

    # Exit code: 0 = clean, 1 = findings present
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
