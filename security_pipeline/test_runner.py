#!/usr/bin/env python3
"""
==========================================================================
Test Runner — Validates all 17 scanner tests against known test cases
==========================================================================

Usage:
    python test_runner.py
    python test_runner.py --verbose

This runner:
  1. Creates synthetic WASM test binaries (can't ship real binaries in text)
  2. Runs every scanner against each test case file
  3. Verifies expected findings are present (positive tests)
  4. Verifies unexpected findings are absent (negative tests)
  5. Prints a pass/fail summary
==========================================================================
"""

import os
import sys
import struct
import argparse
from collections import defaultdict

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners.js_scanner import JavaScriptScanner
from scanners.css_scanner import CSSScanner
from scanners.xml_scanner import XMLScanner
from scanners.wasm_scanner import WASMScanner
from scanners.html_scanner import HTMLScanner
from scanners.retire_scanner import RetireScanner


# ====================================================================== #
# TEST DEFINITIONS
# ====================================================================== #
# Each test: (file, test_name_substring, expected_severity, expected_count_min,
#             description)
# Use expected_count_min=0 to assert NO findings of that type

TESTS = []

def expect(file, test_name, severity, min_count, desc):
    TESTS.append((file, test_name, severity, min_count, desc))

# --- JS: Prototype Pollution ---
expect("test_cases/js/tc01_proto_pollution.js", "prototype_pollution", None, 5,
       "TC-PP-01..05: Should find 5+ prototype pollution patterns (any severity)")

# --- JS: Open Redirect ---
expect("test_cases/js/tc02_open_redirect.js", "open_redirect", "HIGH", 2,
       "TC-OR-01..02: Should find HIGH-severity open redirects with user sources")
expect("test_cases/js/tc02_open_redirect.js", "open_redirect", None, 3,
       "TC-OR-01..03,06: Should find 3+ total open redirect findings (any severity)")

# --- JS: High-Risk APIs ---
expect("test_cases/js/tc03_high_risk_api.js", "high_risk_api", "HIGH", 2,
       "TC-API-01..02,04: Should find HIGH-severity API usage (geolocation, camera, clipboard)")
expect("test_cases/js/tc03_high_risk_api.js", "high_risk_api", "MEDIUM", 2,
       "TC-API-03,07: Should find MEDIUM-severity API usage (WebRTC, Bluetooth)")

# --- JS: Dangerous Sinks ---
expect("test_cases/js/tc04_dangerous_sinks.js", "dangerous_sink", "CRITICAL", 2,
       "TC-DS-01..02,08: Should find CRITICAL sinks (eval, Function)")
expect("test_cases/js/tc04_dangerous_sinks.js", "dangerous_sink", "HIGH", 3,
       "TC-DS-03..06: Should find HIGH sinks (setTimeout, document.write, innerHTML)")

# --- JS: JSONP ---
expect("test_cases/js/tc05_jsonp.js", "jsonp_callback", "MEDIUM", 3,
       "TC-JP-01..03,06: Should find JSONP callback patterns")

# --- JS: ReDoS ---
expect("test_cases/js/tc06_redos.js", "redos", "MEDIUM", 2,
       "TC-RD-01..03: Should find 2+ ReDoS-vulnerable regex patterns")

# --- JS: Service Worker ---
expect("test_cases/js/tc07_service_worker.js", "service_worker", "HIGH", 1,
       "TC-SW-01: Should find broad-scope service worker registration")
expect("test_cases/js/tc07_service_worker.js", "service_worker", "MEDIUM", 2,
       "TC-SW-02..03: Should find default-scope registration and importScripts")

# --- JS: Cryptominer ---
expect("test_cases/js/tc08_cryptominer.js", "cryptominer_js", "CRITICAL", 1,
       "TC-CM-01: Should find Coinhive initialization as CRITICAL")
expect("test_cases/js/tc08_cryptominer.js", "cryptominer_js", "HIGH", 1,
       "TC-CM-05: Should find CryptoNight reference")

# --- JS: postMessage ---
expect("test_cases/js/tc09_postmessage.js", "postmessage_audit", "CRITICAL", 1,
       "TC-PM-01: Should find no-origin-check handler with innerHTML sink")
expect("test_cases/js/tc09_postmessage.js", "postmessage_audit", "HIGH", 1,
       "TC-PM-02: Should find no-origin-check handler without dangerous sink")
expect("test_cases/js/tc09_postmessage.js", "postmessage_audit", "MEDIUM", 2,
       "TC-PM-03..04: Should find weak origin check and wildcard postMessage")

# --- CSS: Attribute Selector Exfiltration ---
expect("test_cases/css/tc10_attr_exfil.css", "css_attr_exfil", "CRITICAL", 5,
       "TC-AE-01..03,06 + bulk: Should find CRITICAL exfiltration patterns")

# --- CSS: @import Chain ---
expect("test_cases/css/tc11_import_chain.css", "css_import_chain", "HIGH", 1,
       "TC-IC-02: Should find chaining pattern to same domain")
expect("test_cases/css/tc11_import_chain.css", "css_import_chain", "MEDIUM", 5,
       "TC-IC-01..05: Should find individual external imports")

# --- CSS: Font Ligature Keylogging ---
expect("test_cases/css/tc12_font_keylog.css", "css_font_keylog", "CRITICAL", 1,
       "TC-FK-02: Should find bulk keylogging pattern (5+ single-char @font-face)")
expect("test_cases/css/tc12_font_keylog.css", "css_font_keylog", "HIGH", 5,
       "TC-FK-01..02: Should find individual single-char @font-face blocks")

# --- XML: XXE ---
expect("test_cases/xml/tc13_xxe.xml", "xxe", "CRITICAL", 3,
       "TC-XXE-01..03: Should find SYSTEM entity, external URL, parameter entity")
expect("test_cases/xml/tc13_xxe_clean.xml", "xxe", "CRITICAL", 0,
       "TC-XXE-07: Clean XML should have ZERO CRITICAL XXE findings")

# --- XML: XML Bomb ---
expect("test_cases/xml/tc14_xml_bomb.xml", "xml_bomb", "CRITICAL", 2,
       "TC-XB-01..02: Should find exponential expansion and chain depth")
expect("test_cases/xml/tc14_xml_bomb_safe.xml", "xml_bomb", "CRITICAL", 0,
       "TC-XB-04: Safe single entity should have ZERO CRITICAL bomb findings")

# --- XML: XPath Injection ---
expect("test_cases/xml/tc15_xpath.xslt", "xpath_injection", "HIGH", 1,
       "TC-XP-01: Should find variable in XPath predicate")
expect("test_cases/xml/tc15_xpath.xslt", "xpath_injection", "MEDIUM", 1,
       "TC-XP-02..03: Should find concat or xpath attribute patterns")

# --- XML: XSLT Injection ---
expect("test_cases/xml/tc16_xslt_injection.xslt", "xslt_injection", "CRITICAL", 3,
       "TC-XI-01..02,06: Should find document(file://), php:function, msxsl:script")
expect("test_cases/xml/tc16_xslt_injection.xslt", "xslt_injection", "HIGH", 2,
       "TC-XI-04..05: Should find document($var) and disable-output-escaping")
expect("test_cases/xml/tc16_xslt_injection.xslt", "xslt_injection", "MEDIUM", 2,
       "TC-XI-03: Should find system-property() and document() general usage")


# --- HTML: Missing SRI ---
expect("test_cases/html/tc_html_attacks.html", "missing_sri", "MEDIUM", 2,
       "TC-SRI-01..02: Should find external script and stylesheet without integrity")

# --- HTML: Clickjacking ---
expect("test_cases/html/tc_html_attacks.html", "clickjacking", "HIGH", 1,
       "TC-CJ-01: Should find hidden iframe overlay")
expect("test_cases/html/tc_html_attacks.html", "clickjacking", "MEDIUM", 1,
       "TC-CJ-02: Should flag page with login but no frame-busting")

# --- HTML: Base Tag ---
expect("test_cases/html/tc_html_attacks.html", "base_tag_hijack", "HIGH", 1,
       "TC-BASE-01: Should find base tag pointing to external domain")

# --- HTML: Meta Refresh ---
expect("test_cases/html/tc_html_attacks.html", "meta_refresh_redirect", "HIGH", 1,
       "TC-MR-01: Should find meta refresh to external URL")

# --- HTML: Form Action ---
expect("test_cases/html/tc_html_attacks.html", "form_action_hijack", "HIGH", 1,
       "TC-FORM-01: Should find form submitting over HTTP")
expect("test_cases/html/tc_html_attacks.html", "form_action_hijack", "MEDIUM", 2,
       "TC-FORM-02..03: Should find external form + formaction override")

# --- HTML: Dangling Markup ---
expect("test_cases/html/tc_html_attacks.html", "dangling_markup", "CRITICAL", 1,
       "TC-DM-01: Should find javascript: URL in href")
expect("test_cases/html/tc_html_attacks.html", "dangling_markup", "HIGH", 1,
       "TC-DM-02: Should find data: URL in iframe src")

# --- HTML: Inline Script → JS Scanner Delegation ---
expect("test_cases/html/tc_html_attacks.html", "dangerous_sink", "CRITICAL", 1,
       "TC-INLINE-01: Inline eval() should trigger JS dangerous sink scanner")
expect("test_cases/html/tc_html_attacks.html", "cryptominer_js", "CRITICAL", 1,
       "TC-INLINE-01: Inline CoinHive should trigger JS cryptominer scanner")
expect("test_cases/html/tc_html_attacks.html", "postmessage_audit", "CRITICAL", 1,
       "TC-INLINE-01: Inline postMessage handler should trigger JS postMessage scanner")

# --- HTML: Inline Style → CSS Scanner Delegation ---
expect("test_cases/html/tc_html_attacks.html", "css_attr_exfil", "CRITICAL", 5,
       "TC-INLINE-02: Inline CSS exfil should trigger CSS attribute exfil scanner")

# --- HTML: Clean file ---
expect("test_cases/html/tc_html_clean.html", "dangling_markup", "CRITICAL", 0,
       "Clean HTML should have ZERO CRITICAL dangling markup findings")
expect("test_cases/html/tc_html_clean.html", "missing_sri", "MEDIUM", 0,
       "Clean HTML (local + SRI scripts) should have ZERO missing SRI findings")

# --- HTML: Violations ---
expect("test_cases/html/tc_html_violations.html", "html_violation", "HIGH", 1,
       "TC-HV-01: Should find nested form")
expect("test_cases/html/tc_html_violations.html", "html_violation", "MEDIUM", 5,
       "TC-HV-02..04: Should find duplicate IDs, block-in-inline, unclosed tags (5+)")

# --- JS: Vulnerable Library Detection (Retire.js) ---
expect("test_cases/js/tc_retire_jquery.js", "vulnerable_library", "CRITICAL", 2,
       "TC-RET-01: jQuery 1.9.1 should have 2+ CRITICAL CVEs")
expect("test_cases/js/tc_retire_jquery.js", "vulnerable_library", "HIGH", 2,
       "TC-RET-01: jQuery 1.9.1 should have 2+ HIGH CVEs")
expect("test_cases/js/tc_retire_lodash.js", "vulnerable_library", "CRITICAL", 2,
       "TC-RET-02: Lodash 4.17.4 should have 2+ CRITICAL CVEs")
expect("test_cases/js/tc_retire_lodash.js", "vulnerable_library", "HIGH", 3,
       "TC-RET-02: Lodash 4.17.4 should have 3+ HIGH CVEs")
expect("test_cases/js/tc_retire_clean.js", "vulnerable_library", "CRITICAL", 0,
       "TC-RET-03: Clean JS should have ZERO vulnerable library findings")


# ====================================================================== #
# WASM TEST BINARY GENERATOR
# ====================================================================== #

def create_wasm_test_binaries(test_dir):
    """Create synthetic WASM binaries for testing."""
    wasm_dir = os.path.join(test_dir, "test_cases", "wasm")
    os.makedirs(wasm_dir, exist_ok=True)

    # TC-WM-01..03: POSITIVE — WASM with mining signatures
    miner_wasm = bytearray()
    miner_wasm += b'\x00asm'           # magic
    miner_wasm += struct.pack('<I', 1) # version 1
    # Pad with some data then inject mining strings
    miner_wasm += b'\x00' * 100
    miner_wasm += b'cryptonight_hash_function'
    miner_wasm += b'\x00' * 50
    miner_wasm += b'CoinHive.Anonymous'
    miner_wasm += b'\x00' * 50
    miner_wasm += b'scratchpad_init'
    miner_wasm += b'\x00' * 50
    miner_wasm += b'stratum+tcp://pool.mining.com'
    miner_wasm += b'\x00' * 50
    miner_wasm += b'cn_slow_hash'
    miner_wasm += b'\x00' * 200

    miner_path = os.path.join(wasm_dir, "tc17_cryptominer.wasm")
    with open(miner_path, "wb") as f:
        f.write(miner_wasm)

    # TC-WM-04: POSITIVE — large WASM (size heuristic)
    large_wasm = bytearray()
    large_wasm += b'\x00asm'
    large_wasm += struct.pack('<I', 1)
    large_wasm += b'\x00' * (600 * 1024)  # 600KB

    large_path = os.path.join(wasm_dir, "tc17_large.wasm")
    with open(large_path, "wb") as f:
        f.write(large_wasm)

    # TC-WM-05: NEGATIVE — clean small WASM
    clean_wasm = bytearray()
    clean_wasm += b'\x00asm'
    clean_wasm += struct.pack('<I', 1)
    clean_wasm += b'\x00' * 200
    clean_wasm += b'add_numbers'
    clean_wasm += b'\x00' * 50
    clean_wasm += b'multiply'
    clean_wasm += b'\x00' * 100

    clean_path = os.path.join(wasm_dir, "tc17_clean.wasm")
    with open(clean_path, "wb") as f:
        f.write(clean_wasm)

    return miner_path, large_path, clean_path


# Add WASM tests (these reference files we'll create)
expect("test_cases/wasm/tc17_cryptominer.wasm", "wasm_cryptominer", "CRITICAL", 1,
       "TC-WM-01..03: Should find CRITICAL mining signatures (multiple hits)")
expect("test_cases/wasm/tc17_cryptominer.wasm", "wasm_cryptominer", "HIGH", 3,
       "TC-WM-01..03: Should find HIGH individual mining signature matches")
expect("test_cases/wasm/tc17_clean.wasm", "wasm_cryptominer", "HIGH", 0,
       "TC-WM-05: Clean WASM should have ZERO HIGH+ cryptominer findings")


# ====================================================================== #
# TEST RUNNER
# ====================================================================== #

def run_tests(verbose=False):
    """Run all test cases and report results."""
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Create WASM test binaries
    print("Creating synthetic WASM test binaries...")
    create_wasm_test_binaries(base_dir)

    # Initialize scanners
    js = JavaScriptScanner()
    css = CSSScanner()
    xml = XMLScanner()
    wasm = WASMScanner()
    html = HTMLScanner()
    retire = RetireScanner()

    scanner_map = {}
    for ext in html.EXTENSIONS:
        scanner_map[ext] = html
    for ext in js.EXTENSIONS:
        scanner_map[ext] = js
    for ext in css.EXTENSIONS:
        scanner_map[ext] = css
    for ext in xml.EXTENSIONS:
        scanner_map[ext] = xml
    for ext in wasm.EXTENSIONS:
        scanner_map[ext] = wasm

    # Cache scan results per file
    results_cache = {}

    def get_findings(rel_path):
        if rel_path not in results_cache:
            full_path = os.path.join(base_dir, rel_path)
            if not os.path.exists(full_path):
                print(f"  WARNING: File not found: {full_path}")
                results_cache[rel_path] = []
                return []
            ext = os.path.splitext(rel_path)[1].lower()
            scanner = scanner_map.get(ext)
            if scanner is None:
                print(f"  WARNING: No scanner for extension: {ext}")
                results_cache[rel_path] = []
                return []
            findings = scanner.scan(full_path)
            # Also run Retire.js on JS files
            if ext in retire.EXTENSIONS:
                findings.extend(retire.scan(full_path))
            results_cache[rel_path] = findings
        return results_cache[rel_path]

    # Run tests
    passed = 0
    failed = 0
    errors = []

    print(f"\n{'='*70}")
    print(f"  RUNNING {len(TESTS)} TEST ASSERTIONS")
    print(f"{'='*70}\n")

    for i, (file, test_name, severity, min_count, desc) in enumerate(TESTS, 1):
        findings = get_findings(file)

        # Count findings matching test_name and severity
        if severity is None:
            matching = [
                f for f in findings
                if test_name in f.test_name
            ]
        else:
            matching = [
                f for f in findings
                if test_name in f.test_name and f.severity == severity
            ]
        count = len(matching)

        if min_count == 0:
            # Negative test: should find NONE
            ok = count == 0
        else:
            # Positive test: should find at least min_count
            ok = count >= min_count

        status = "PASS" if ok else "FAIL"

        if ok:
            passed += 1
            if verbose:
                print(f"  [{status}] #{i:02d} {desc}")
                sev_label = severity if severity else "ANY"
                print(f"         Found {count} {sev_label} {test_name} "
                      f"(expected >= {min_count})")
        else:
            failed += 1
            errors.append((i, desc, count, min_count, severity, test_name, file))
            sev_label = severity if severity else "ANY"
            print(f"  [{status}] #{i:02d} {desc}")
            print(f"         Found {count} {sev_label} {test_name} "
                  f"(expected {'== 0' if min_count == 0 else '>= ' + str(min_count)})")
            if verbose and matching:
                for m in matching[:3]:
                    print(f"           → L{m.line_number}: {m.description[:80]}")

    # Summary
    total = passed + failed
    print(f"\n{'='*70}")
    print(f"  RESULTS: {passed}/{total} passed, {failed} failed")
    print(f"{'='*70}")

    if errors:
        print(f"\n  FAILURES:")
        for idx, desc, actual, expected, sev, tname, fpath in errors:
            exp_str = "== 0" if expected == 0 else f">= {expected}"
            sev_label = sev if sev else "ANY"
            print(f"    #{idx:02d} [{sev_label}] {tname} in {fpath}")
            print(f"         {desc}")
            print(f"         Got {actual}, expected {exp_str}")
        print()

    # Per-scanner summary
    print(f"\n  SCANNER COVERAGE:")
    scanner_tests = defaultdict(lambda: {"pass": 0, "fail": 0})
    for i, (file, test_name, severity, min_count, desc) in enumerate(TESTS, 1):
        ext = os.path.splitext(file)[1].lower()
        if ext in html.EXTENSIONS:
            group = "HTML"
        elif ext in js.EXTENSIONS:
            group = "JavaScript"
        elif ext in css.EXTENSIONS:
            group = "CSS"
        elif ext in xml.EXTENSIONS:
            group = "XML/XSLT"
        elif ext in wasm.EXTENSIONS:
            group = "WebAssembly"
        else:
            group = "Unknown"

        findings = get_findings(file)
        if severity is None:
            matching = [f for f in findings if test_name in f.test_name]
        else:
            matching = [f for f in findings if test_name in f.test_name and f.severity == severity]
        count = len(matching)
        ok = (count == 0) if min_count == 0 else (count >= min_count)

        if ok:
            scanner_tests[group]["pass"] += 1
        else:
            scanner_tests[group]["fail"] += 1

    for group in ["HTML", "JavaScript", "CSS", "XML/XSLT", "WebAssembly"]:
        stats = scanner_tests[group]
        total_g = stats["pass"] + stats["fail"]
        print(f"    {group:15s}: {stats['pass']}/{total_g} passed")

    print()

    # Generate output files in the same directory as this script
    sys.path.insert(0, base_dir)
    from driver import PipelineDriver, format_text, format_matrix

    test_cases_dir = os.path.join(base_dir, "test_cases")
    evidence_path = os.path.join(base_dir, "evidence_report.txt")
    matrix_path = os.path.join(base_dir, "attack_matrix.csv")

    print(f"\n  Generating output files...")
    driver = PipelineDriver()
    all_findings = driver.scan_all(test_cases_dir)

    with open(evidence_path, "w", encoding="utf-8") as f:
        f.write(format_text(all_findings))
    print(f"  Evidence report: {evidence_path}")

    with open(matrix_path, "w", encoding="utf-8") as f:
        f.write(format_matrix(all_findings, test_cases_dir))
    print(f"  Attack matrix:   {matrix_path}")

    return 0 if failed == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Security Pipeline Test Runner")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show details for passing tests too")
    args = parser.parse_args()

    exit_code = run_tests(verbose=args.verbose)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
