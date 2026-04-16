#!/usr/bin/env python3
"""
Generic per-attack runner for the security pipeline.

Usage:
    python run_attack.py <attack_name>
    python run_attack.py xxe
    python run_attack.py css_attr_exfil
    python run_attack.py --list

Outputs to results/<attack_name>/:
    evidence.txt     -- all matching findings with file, line, code snippet
    domain_summary.csv -- per-domain finding counts
    attack_matrix.csv  -- binary 0/1 per domain
    summary.json     -- totals and per-domain breakdown

The data directory is expected at security_pipeline/data/.
Run `python driver.py data/ --output ... --matrix ...` for all-attacks scans.
"""

import sys
import os
import json
import csv
import time
import argparse
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from driver import PipelineDriver

_JS   = {".js", ".mjs", ".jsx", ".ts", ".tsx"}
_HTML = {".html", ".htm"}
_CSS  = {".css"}
_XML  = {".xml", ".xsl", ".xslt", ".soap", ".rss", ".atom"}
_WASM = {".wasm"}

# Maps each attack to the file extensions it can fire on.
# JS/CSS attacks include HTML because the HTML scanner delegates
# inline <script>/<style> blocks to the JS/CSS scanners respectively.
ATTACK_EXTENSIONS = {
    # XML/XSLT -- XML files only
    "xxe":               _XML,
    "xml_bomb":          _XML,
    "xslt_injection":    _XML,
    "xpath_injection":   _XML,
    # JavaScript -- JS files + HTML (inline <script> delegation)
    "prototype_pollution":   _JS | _HTML,
    "open_redirect":         _JS | _HTML,
    "high_risk_api":         _JS | _HTML,
    "dangerous_sink":        _JS | _HTML,
    "jsonp_callback":        _JS | _HTML,
    "redos":                 _JS | _HTML,
    "service_worker":        _JS | _HTML,
    "cryptominer_js":        _JS | _HTML,
    "postmessage_audit":     _JS | _HTML,
    # CSS -- CSS files + HTML (inline <style> delegation)
    "css_attr_exfil":        _CSS | _HTML,
    "css_import_chain":      _CSS | _HTML,
    "css_font_keylog":       _CSS | _HTML,
    # HTML only
    "missing_sri":           _HTML,
    "base_tag_hijack":       _HTML,
    "meta_refresh_redirect": _HTML,
    "form_action_hijack":    _HTML,
    "dangling_markup":       _HTML,
    "html_violation":        _HTML,
    "clickjacking":          _HTML,
    # WASM only
    "wasm_cryptominer":      _WASM,
    # Vulnerable library -- JS files only (version strings live in library files, not inline)
    "vulnerable_library":    {".js", ".mjs"},
}

KNOWN_ATTACKS = sorted(ATTACK_EXTENSIONS.keys())


def main():
    parser = argparse.ArgumentParser(description="Run a single attack scanner on data/")
    parser.add_argument("attack", nargs="?", help="Attack name (e.g. xxe, css_attr_exfil)")
    parser.add_argument("--list", action="store_true", help="List all known attack names")
    parser.add_argument("--data", default=None,
                        help="Path to data directory (default: <script_dir>/data)")
    args = parser.parse_args()

    if args.list:
        print("Known attack names:")
        for a in KNOWN_ATTACKS:
            print(f"  {a}")
        return 0

    if not args.attack:
        parser.print_help()
        return 1

    attack = args.attack.strip()
    if attack not in KNOWN_ATTACKS:
        print(f"[!] Unknown attack '{attack}'. Run with --list to see valid names.")
        return 1

    base = os.path.dirname(os.path.abspath(__file__))
    data_dir = args.data or os.path.join(base, "data")

    if not os.path.isdir(data_dir):
        print(f"[!] Data directory not found: {data_dir}")
        print(f"    Extract the dataset to security_pipeline/data/ first.")
        return 1

    out_dir = os.path.join(base, "results", attack)
    os.makedirs(out_dir, exist_ok=True)

    extensions = ATTACK_EXTENSIONS[attack]

    print(f"[*] Attack   : {attack}")
    print(f"[*] Data dir : {data_dir}")
    print(f"[*] Output   : {out_dir}")
    print(f"[*] Scanning : {', '.join(sorted(extensions))} files only")
    print()

    t0 = time.time()
    driver = PipelineDriver()
    all_findings = driver.scan_all(data_dir, extensions=extensions)
    elapsed = time.time() - t0

    target = [f for f in all_findings if f.test_name == attack]
    all_domains = sorted(os.listdir(data_dir))

    by_domain = defaultdict(list)
    for f in target:
        rel = os.path.relpath(os.path.abspath(f.file_path), os.path.abspath(data_dir))
        domain = rel.replace("\\", "/").split("/")[0]
        by_domain[domain].append(f)

    # ── 1. Evidence report ───────────────────────────────────────────────
    evidence_lines = [
        "=" * 70,
        f"  {attack.upper().replace('_', ' ')} -- EVIDENCE REPORT",
        f"  Dataset  : {data_dir}  ({len(all_domains)} domains)",
        f"  Scan time: {elapsed:.1f}s",
        f"  Total findings   : {len(target)}",
        f"  Domains affected : {len(by_domain)} / {len(all_domains)}",
        "=" * 70,
    ]

    for domain in sorted(by_domain):
        findings = by_domain[domain]
        evidence_lines.append("")
        evidence_lines.append(f"DOMAIN: {domain}  ({len(findings)} findings)")
        evidence_lines.append("-" * 50)
        for f in sorted(findings, key=lambda x: (x.file_path, x.line_number)):
            rel_file = os.path.relpath(os.path.abspath(f.file_path), os.path.abspath(data_dir))
            evidence_lines.append(f"  [FOUND] [{f.severity}] {f.description}")
            evidence_lines.append(f"    File : {rel_file}")
            evidence_lines.append(f"    Line : {f.line_number}")
            evidence_lines.append(f"    Code : {f.line_content[:120]}")

    evidence_path = os.path.join(out_dir, "evidence.txt")
    with open(evidence_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(evidence_lines) + "\n")
    print(f"[*] Evidence written -> {evidence_path}")

    # ── 2. Per-domain CSV summary ────────────────────────────────────────
    csv_rows = []
    for domain in all_domains:
        domain_findings = by_domain.get(domain, [])
        sev_counts = defaultdict(int)
        for f in domain_findings:
            sev_counts[f.severity] += 1
        csv_rows.append({
            "domain": domain,
            "total_findings": len(domain_findings),
            "CRITICAL": sev_counts["CRITICAL"],
            "HIGH": sev_counts["HIGH"],
            "MEDIUM": sev_counts["MEDIUM"],
            "affected": 1 if domain_findings else 0,
        })

    csv_path = os.path.join(out_dir, "domain_summary.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["domain", "total_findings",
                                            "CRITICAL", "HIGH", "MEDIUM", "affected"])
        w.writeheader()
        w.writerows(csv_rows)
    print(f"[*] Domain summary  -> {csv_path}")

    # ── 3. Attack matrix ─────────────────────────────────────────────────
    matrix_path = os.path.join(out_dir, "attack_matrix.csv")
    with open(matrix_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["domain", attack])
        for domain in all_domains:
            w.writerow([domain, 1 if domain in by_domain else 0])
    print(f"[*] Attack matrix   -> {matrix_path}")

    # ── 4. JSON summary ──────────────────────────────────────────────────
    sev_totals = defaultdict(int)
    for f in target:
        sev_totals[f.severity] += 1

    summary = {
        "attack": attack,
        "data_directory": data_dir,
        "scan_time_seconds": round(elapsed, 1),
        "total_findings": len(target),
        "domains_affected": len(by_domain),
        "domains_total": len(all_domains),
        "by_severity": dict(sev_totals),
        "by_domain": {d: len(fs) for d, fs in sorted(by_domain.items())},
        "domains_clean": sorted(d for d in all_domains if d not in by_domain),
    }
    summary_path = os.path.join(out_dir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"[*] Summary JSON    -> {summary_path}")

    # ── Final summary ────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print(f"  {attack.upper().replace('_', ' ')} RESULTS")
    print("=" * 70)
    print(f"  Domains affected : {len(by_domain)} / {len(all_domains)}")
    print(f"  Total findings   : {len(target)}")
    print()
    print("  By severity:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if sev_totals.get(sev):
            print(f"    {sev:<10} {sev_totals[sev]}")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
