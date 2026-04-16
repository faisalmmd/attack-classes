#!/usr/bin/env bash
# Verification script — runs each scanner against its test file and checks
# that the expected findings are present and negatives are absent.
# Run from the security_pipeline/ directory:
#   bash verification/run_verification.sh

set -euo pipefail
cd "$(dirname "$0")/.."   # ensure we're in security_pipeline/

PASS=0
FAIL=0
ERRORS=()

# Helper: run a Python one-liner and count matching findings
count_findings() {
    local file="$1"
    local scanner_class="$2"
    local scanner_module="$3"
    local test_name_filter="$4"
    python3 -c "
import sys
sys.path.insert(0, '.')
from scanners.${scanner_module} import ${scanner_class}
s = ${scanner_class}()
findings = [f for f in s.scan('${file}') if '${test_name_filter}' in f.test_name]
print(len(findings))
"
}

check() {
    local label="$1"
    local actual="$2"
    local op="$3"     # ">=" or "==" or ">"
    local expected="$4"
    local ok=0
    if   [ "$op" = ">=" ] && [ "$actual" -ge "$expected" ]; then ok=1
    elif [ "$op" = "==" ] && [ "$actual" -eq "$expected" ]; then ok=1
    elif [ "$op" = ">"  ] && [ "$actual" -gt "$expected" ]; then ok=1
    fi
    if [ "$ok" -eq 1 ]; then
        echo "  [PASS] $label (got $actual)"
        PASS=$((PASS+1))
    else
        echo "  [FAIL] $label (got $actual, expected $op $expected)"
        FAIL=$((FAIL+1))
        ERRORS+=("$label")
    fi
}

echo ""
echo "======================================================================"
echo "  SECURITY PIPELINE — MANUAL VERIFICATION"
echo "======================================================================"

# ── 1. Prototype Pollution ─────────────────────────────────────────────
echo ""
echo "[JS-1] Prototype Pollution"
n=$(count_findings "test_cases/js/tc01_proto_pollution.js" "JavaScriptScanner" "js_scanner" "prototype_pollution")
check "tc01: >=5 prototype_pollution findings" "$n" ">=" 5

# ── 2. Open Redirect ───────────────────────────────────────────────────
echo ""
echo "[JS-2] Open Redirect"
n=$(count_findings "test_cases/js/tc02_open_redirect.js" "JavaScriptScanner" "js_scanner" "open_redirect")
check "tc02: >=3 open_redirect findings" "$n" ">=" 3

# ── 3. High-Risk Browser APIs ──────────────────────────────────────────
echo ""
echo "[JS-3] High-Risk Browser APIs"
n=$(count_findings "test_cases/js/tc03_high_risk_api.js" "JavaScriptScanner" "js_scanner" "high_risk_api")
check "tc03: >=7 high_risk_api findings" "$n" ">=" 7

# ── 4. Dangerous Sinks ─────────────────────────────────────────────────
echo ""
echo "[JS-4] Dangerous Sinks"
n=$(count_findings "test_cases/js/tc04_dangerous_sinks.js" "JavaScriptScanner" "js_scanner" "dangerous_sink")
check "tc04: >=7 dangerous_sink findings" "$n" ">=" 7

# ── 5. JSONP Callback ──────────────────────────────────────────────────
echo ""
echo "[JS-5] JSONP Callback"
n=$(count_findings "test_cases/js/tc05_jsonp.js" "JavaScriptScanner" "js_scanner" "jsonp_callback")
check "tc05: >=5 jsonp_callback findings" "$n" ">=" 5

# ── 6. ReDoS ───────────────────────────────────────────────────────────
echo ""
echo "[JS-6] ReDoS"
n=$(count_findings "test_cases/js/tc06_redos.js" "JavaScriptScanner" "js_scanner" "redos")
check "tc06: >=3 redos findings" "$n" ">=" 3

# ── 7. Service Worker ──────────────────────────────────────────────────
echo ""
echo "[JS-7] Service Worker"
n=$(count_findings "test_cases/js/tc07_service_worker.js" "JavaScriptScanner" "js_scanner" "service_worker")
check "tc07: >=3 service_worker findings" "$n" ">=" 3

# ── 8. Cryptominer JS ─────────────────────────────────────────────────
echo ""
echo "[JS-8] Cryptominer (JavaScript)"
n=$(count_findings "test_cases/js/tc08_cryptominer.js" "JavaScriptScanner" "js_scanner" "cryptominer_js")
check "tc08: >=4 cryptominer_js findings" "$n" ">=" 4

# ── 9. postMessage ─────────────────────────────────────────────────────
echo ""
echo "[JS-9] postMessage Handler"
n=$(count_findings "test_cases/js/tc09_postmessage.js" "JavaScriptScanner" "js_scanner" "postmessage_audit")
check "tc09: >=4 postmessage_audit findings" "$n" ">=" 4

# True-negative: strict origin check should NOT fire
n_neg=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.js_scanner import JavaScriptScanner
s = JavaScriptScanner()
# Count findings on lines 24-28 (the correct handler)
findings = [f for f in s.scan('test_cases/js/tc09_postmessage.js')
            if f.test_name == 'postmessage_audit' and f.line_number in range(24,30)]
print(len(findings))
")
check "tc09 negative: strict origin check NOT flagged" "$n_neg" "==" 0

# ── 10. CSS Attribute Exfil ────────────────────────────────────────────
echo ""
echo "[CSS-10] Attribute Selector Exfiltration"
n=$(count_findings "test_cases/css/tc10_attr_exfil.css" "CSSScanner" "css_scanner" "css_attr_exfil")
check "tc10: >=5 css_attr_exfil findings" "$n" ">=" 5

# ── 11. CSS @import Chain ─────────────────────────────────────────────
echo ""
echo "[CSS-11] @import Chain Exfiltration"
n=$(count_findings "test_cases/css/tc11_import_chain.css" "CSSScanner" "css_scanner" "css_import_chain")
check "tc11: >=6 css_import_chain findings" "$n" ">=" 6

# ── 12. Font Ligature Keylogging ───────────────────────────────────────
echo ""
echo "[CSS-12] Font Ligature Keylogging"
n=$(count_findings "test_cases/css/tc12_font_keylog.css" "CSSScanner" "css_scanner" "css_font_keylog")
check "tc12: >=7 css_font_keylog findings" "$n" ">=" 7

# True-negative: local font / no unicode-range should NOT fire
n_neg=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.css_scanner import CSSScanner
s = CSSScanner()
# NEGATIVE blocks start at line 36
findings = [f for f in s.scan('test_cases/css/tc12_font_keylog.css')
            if f.test_name == 'css_font_keylog' and f.line_number >= 36]
print(len(findings))
")
check "tc12 negative: local/no-range font NOT flagged" "$n_neg" "==" 0

# ── 13. XXE ────────────────────────────────────────────────────────────
echo ""
echo "[XML-13] XXE"
n=$(count_findings "test_cases/xml/tc13_xxe.xml" "XMLScanner" "xml_scanner" "xxe")
check "tc13: >=3 xxe findings" "$n" ">=" 3

n_clean=$(count_findings "test_cases/xml/tc13_xxe_clean.xml" "XMLScanner" "xml_scanner" "xxe")
check "tc13_clean: 0 CRITICAL xxe (true-negative)" "$n_clean" "==" 0

# ── 14. XML Bomb ───────────────────────────────────────────────────────
echo ""
echo "[XML-14] XML Bomb / Billion Laughs"
n=$(count_findings "test_cases/xml/tc14_xml_bomb.xml" "XMLScanner" "xml_scanner" "xml_bomb")
check "tc14: >=3 xml_bomb findings" "$n" ">=" 3

n_safe=$(count_findings "test_cases/xml/tc14_xml_bomb_safe.xml" "XMLScanner" "xml_scanner" "xml_bomb")
check "tc14_safe: 0 xml_bomb CRITICAL (true-negative)" "$n_safe" "==" 0

# ── 15. XPath Injection ────────────────────────────────────────────────
echo ""
echo "[XML-15] XPath Injection"
n=$(count_findings "test_cases/xml/tc15_xpath.xslt" "XMLScanner" "xml_scanner" "xpath_injection")
check "tc15: >=3 xpath_injection findings" "$n" ">=" 3

# ── 16. XSLT Injection ─────────────────────────────────────────────────
echo ""
echo "[XML-16] XSLT Injection"
n=$(count_findings "test_cases/xml/tc16_xslt_injection.xslt" "XMLScanner" "xml_scanner" "xslt_injection")
check "tc16: >=8 xslt_injection findings" "$n" ">=" 8

# ── 17. WASM Cryptominer ───────────────────────────────────────────────
echo ""
echo "[WASM-17] WASM Cryptominer"
# Regenerate WASM test binaries first
python3 -c "
import sys, struct, os
sys.path.insert(0,'.')
from test_runner import create_wasm_test_binaries
create_wasm_test_binaries(os.getcwd())
" 2>/dev/null

n=$(count_findings "test_cases/wasm/tc17_cryptominer.wasm" "WASMScanner" "wasm_scanner" "wasm_cryptominer")
check "tc17_miner: >=4 wasm_cryptominer findings" "$n" ">=" 4

n_clean=$(count_findings "test_cases/wasm/tc17_clean.wasm" "WASMScanner" "wasm_scanner" "wasm_cryptominer")
check "tc17_clean: 0 wasm_cryptominer HIGH+ (true-negative)" "$n_clean" "==" 0

# ── 18–24. HTML Attacks ────────────────────────────────────────────────
echo ""
echo "[HTML-18..24] HTML Attacks (all from tc_html_attacks.html)"

for test_name in missing_sri clickjacking base_tag_hijack meta_refresh_redirect form_action_hijack dangling_markup; do
    n=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
print(sum(1 for f in s.scan('test_cases/html/tc_html_attacks.html') if f.test_name == '${test_name}'))
")
    check "tc_html_attacks: ${test_name} >=1 findings" "$n" ">=" 1
done

# HTML violations
n=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
print(sum(1 for f in s.scan('test_cases/html/tc_html_violations.html') if f.test_name == 'html_violation'))
")
check "tc_html_violations: html_violation >=5 findings" "$n" ">=" 5

# True-negative: clean HTML
n_neg=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
print(sum(1 for f in s.scan('test_cases/html/tc_html_clean.html') if f.test_name in ('missing_sri','dangling_markup')))
")
check "tc_html_clean: 0 sri/dangling findings (true-negative)" "$n_neg" "==" 0

# ── 25. Vulnerable Library ─────────────────────────────────────────────
echo ""
echo "[RET-25] Vulnerable Library Detection"
n_jq=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.retire_scanner import RetireScanner
s = RetireScanner()
print(len(s.scan('test_cases/js/tc_retire_jquery.js')))
")
check "tc_retire_jquery: >=4 findings (CRITICAL+HIGH CVEs)" "$n_jq" ">=" 4

n_lo=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.retire_scanner import RetireScanner
s = RetireScanner()
print(len(s.scan('test_cases/js/tc_retire_lodash.js')))
")
check "tc_retire_lodash: >=5 findings (CRITICAL+HIGH CVEs)" "$n_lo" ">=" 5

n_clean=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.retire_scanner import RetireScanner
s = RetireScanner()
print(len(s.scan('test_cases/js/tc_retire_clean.js')))
")
check "tc_retire_clean: 0 vulnerable_library (true-negative)" "$n_clean" "==" 0

# ── 26. Inline Script/Style Delegation ────────────────────────────────
echo ""
echo "[HTML-26] Inline Script + Style Delegation"
n_inline=$(python3 -c "
import sys; sys.path.insert(0,'.')
from scanners.html_scanner import HTMLScanner
s = HTMLScanner()
findings = s.scan('test_cases/html/tc_html_attacks.html')
inline_js = [f for f in findings if 'INLINE SCRIPT' in f.description and f.test_name in ('dangerous_sink','cryptominer_js','postmessage_audit')]
print(len(inline_js))
")
check "tc_html_attacks: inline JS scanner catches eval+CoinHive+postMessage" "$n_inline" ">=" 3

# ── Summary ────────────────────────────────────────────────────────────
TOTAL=$((PASS+FAIL))
echo ""
echo "======================================================================"
echo "  VERIFICATION RESULTS: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "======================================================================"

if [ ${#ERRORS[@]} -gt 0 ]; then
    echo ""
    echo "  Failed checks:"
    for e in "${ERRORS[@]}"; do
        echo "    - $e"
    done
    echo ""
fi

exit $FAIL
