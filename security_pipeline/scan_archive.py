#!/usr/bin/env python3
"""
================================================================================
scan_archive.py — Scan output_web/{website}/{timestamp}/{files}
================================================================================

Usage:
    python scan_archive.py output_web/
    python scan_archive.py output_web/ --evidence-dir ./evidence
    python scan_archive.py output_web/ --severity HIGH
    python scan_archive.py output_web/ --site example.com
    python scan_archive.py output_web/ --report-dir ./reports

Directory structure expected:
    output_web/
    ├── example.com/
    │   ├── 20190315120000/
    │   │   ├── index.js
    │   │   ├── style.css
    │   │   └── config.xml
    │   ├── 20200601080000/
    │   │   └── app.min.js
    │   └── 20210912143000/
    │       └── bundle.js
    ├── another-site.org/
    │   └── 20220101000000/
    │       └── main.js
    └── ...

What it does:
    1. Discovers all websites and their timestamps
    2. Scans every file with all 17 security tests
    3. Shows real-time progress per website/timestamp
    4. Copies vulnerable files to an evidence folder
    5. Generates per-website reports + a master summary
    6. Prints full stats at the end
================================================================================
"""

import os
import sys
import json
import time
import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# ── Scanner imports ──────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanners.js_scanner import JavaScriptScanner
from scanners.css_scanner import CSSScanner
from scanners.xml_scanner import XMLScanner
from scanners.wasm_scanner import WASMScanner
from scanners.html_scanner import HTMLScanner
from scanners.retire_scanner import RetireScanner


# ── Constants ────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

ALL_EXTENSIONS = {
    ".html", ".htm",
    ".js", ".mjs", ".jsx", ".ts", ".tsx",
    ".css",
    ".xml", ".xsl", ".xslt", ".soap", ".rss", ".atom",
    ".wasm",
}

ATTACK_INFO = {
    "prototype_pollution":  {"name": "Prototype Pollution",                  "cwe": "CWE-1321"},
    "open_redirect":        {"name": "Open Redirect",                        "cwe": "CWE-601"},
    "high_risk_api":        {"name": "High-Risk Browser API Usage",          "cwe": "CWE-276"},
    "dangerous_sink":       {"name": "Dangerous Code Execution Sink",        "cwe": "CWE-79/95"},
    "jsonp_callback":       {"name": "JSONP Callback Injection",             "cwe": "CWE-352/79"},
    "redos":                {"name": "ReDoS (Regex Denial of Service)",      "cwe": "CWE-1333"},
    "service_worker":       {"name": "Service Worker Security Issue",        "cwe": "CWE-349"},
    "cryptominer_js":       {"name": "In-Browser Cryptominer (JS)",          "cwe": "CWE-400"},
    "postmessage_audit":    {"name": "postMessage Handler Vulnerability",    "cwe": "CWE-346"},
    "css_attr_exfil":       {"name": "CSS Attribute Selector Exfiltration",  "cwe": "CWE-200"},
    "css_import_chain":     {"name": "CSS @import Chain Exfiltration",       "cwe": "CWE-200"},
    "css_font_keylog":      {"name": "CSS Font Ligature Keylogging",         "cwe": "CWE-200"},
    "xxe":                  {"name": "XML External Entity (XXE)",            "cwe": "CWE-611"},
    "xml_bomb":             {"name": "XML Bomb / Billion Laughs",            "cwe": "CWE-776"},
    "xpath_injection":      {"name": "XPath Injection",                      "cwe": "CWE-643"},
    "xslt_injection":       {"name": "XSLT Injection",                      "cwe": "CWE-74"},
    "wasm_cryptominer":     {"name": "WASM Cryptominer",                     "cwe": "CWE-400"},
    "html_violation":       {"name": "HTML Structural Violation",             "cwe": "CWE-79"},
    "vulnerable_library":   {"name": "Vulnerable JS Library (Retire.js)",    "cwe": "varies"},
    "missing_sri":          {"name": "Missing Subresource Integrity (SRI)",  "cwe": "CWE-353"},
    "clickjacking":         {"name": "Clickjacking / Frame Injection",       "cwe": "CWE-1021"},
    "base_tag_hijack":      {"name": "Base Tag Hijacking",                   "cwe": "CWE-79"},
    "meta_refresh_redirect":{"name": "Meta Refresh Open Redirect",           "cwe": "CWE-601"},
    "form_action_hijack":   {"name": "Form Action Hijacking",                "cwe": "CWE-352"},
    "dangling_markup":      {"name": "Dangling Markup / JS-URL Injection",   "cwe": "CWE-79"},
}


@dataclass
class Finding:
    test_name: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    description: str
    website: str = ""
    timestamp: str = ""
    relative_path: str = ""


# ── Progress Printer ─────────────────────────────────────────────────────

class Progress:
    """Handles all terminal output with live progress updates."""

    def __init__(self):
        self.start_time = time.time()
        self._last_line_len = 0

    def elapsed(self) -> str:
        s = int(time.time() - self.start_time)
        m, s = divmod(s, 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}h{m:02d}m{s:02d}s"
        elif m:
            return f"{m}m{s:02d}s"
        return f"{s}s"

    def overwrite(self, msg: str):
        """Print on same line, overwriting previous."""
        padded = msg.ljust(self._last_line_len)
        print(f"\r{padded}", end="", flush=True)
        self._last_line_len = len(msg)

    def newline(self, msg: str):
        """Print with newline, clearing any overwrite."""
        if self._last_line_len:
            print()
            self._last_line_len = 0
        print(msg)

    def done(self):
        if self._last_line_len:
            print()
            self._last_line_len = 0


# ── Directory Discovery ──────────────────────────────────────────────────

def discover_structure(
    root_dir: str,
    site_filter: str = None,
) -> Dict[str, Dict[str, List[str]]]:
    """
    Walk output_web/{website}/{timestamp}/{files} and return:
    {
        "example.com": {
            "20190315120000": ["/full/path/to/file.js", ...],
            ...
        },
    }
    """
    structure = {}

    if not os.path.isdir(root_dir):
        print(f"ERROR: '{root_dir}' is not a directory")
        sys.exit(1)

    # Level 1: websites
    for website in sorted(os.listdir(root_dir)):
        website_path = os.path.join(root_dir, website)
        if not os.path.isdir(website_path):
            continue
        if website.startswith('.'):
            continue
        if site_filter and site_filter.lower() not in website.lower():
            continue

        structure[website] = {}

        # Level 2: timestamps
        for timestamp in sorted(os.listdir(website_path)):
            ts_path = os.path.join(website_path, timestamp)
            if not os.path.isdir(ts_path):
                continue
            if timestamp.startswith('.'):
                continue

            # Level 3: collect all scannable files recursively
            files = []
            for dirpath, dirnames, filenames in os.walk(ts_path):
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]
                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in ALL_EXTENSIONS:
                        files.append(os.path.join(dirpath, fname))

            if files:
                structure[website][timestamp] = sorted(files)

        # Remove website if no timestamps with files
        if not structure[website]:
            del structure[website]

    return structure


def format_timestamp(ts: str) -> str:
    """Try to make timestamp human-readable."""
    try:
        if len(ts) == 14 and ts.isdigit():
            dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass
    return ts


# ── Core Scanner ─────────────────────────────────────────────────────────

class ArchiveScanner:
    """Scans the full output_web structure."""

    def __init__(self):
        self.js = JavaScriptScanner()
        self.css = CSSScanner()
        self.xml = XMLScanner()
        self.wasm = WASMScanner()
        self.html = HTMLScanner()
        self.retire = RetireScanner()

        self.scanner_map = {}
        for ext in self.html.EXTENSIONS:
            self.scanner_map[ext] = self.html
        for ext in self.js.EXTENSIONS:
            self.scanner_map[ext] = self.js
        for ext in self.css.EXTENSIONS:
            self.scanner_map[ext] = self.css
        for ext in self.xml.EXTENSIONS:
            self.scanner_map[ext] = self.xml
        for ext in self.wasm.EXTENSIONS:
            self.scanner_map[ext] = self.wasm

    def scan_file(self, filepath: str) -> List[Finding]:
        ext = os.path.splitext(filepath)[1].lower()
        scanner = self.scanner_map.get(ext)
        if not scanner:
            return []
        raw = scanner.scan(filepath)

        # Also run Retire.js scanner on JS files
        if ext in self.retire.EXTENSIONS:
            raw.extend(self.retire.scan(filepath))

        return [
            Finding(
                test_name=f.test_name, severity=f.severity,
                file_path=f.file_path, line_number=f.line_number,
                line_content=f.line_content, description=f.description,
            )
            for f in raw
        ]

    def scan_archive(
        self,
        structure: Dict[str, Dict[str, List[str]]],
        root_dir: str,
        min_severity: str = None,
        progress: Progress = None,
    ) -> List[Finding]:
        """Scan everything. Returns all findings with website/timestamp metadata."""

        if not progress:
            progress = Progress()

        # Count totals for progress
        total_sites = len(structure)
        total_timestamps = sum(len(ts) for ts in structure.values())
        total_files = sum(
            len(files)
            for site in structure.values()
            for files in site.values()
        )

        progress.newline(f"{'='*70}")
        progress.newline(f"  WEB ARCHIVE SECURITY SCANNER")
        progress.newline(f"{'='*70}")
        progress.newline(f"  Root:       {os.path.abspath(root_dir)}")
        progress.newline(f"  Websites:   {total_sites}")
        progress.newline(f"  Snapshots:  {total_timestamps}")
        progress.newline(f"  Files:      {total_files}")
        progress.newline(f"{'='*70}")
        progress.newline("")

        all_findings = []
        files_scanned = 0
        sites_done = 0

        for website, timestamps in structure.items():
            sites_done += 1
            site_findings_count = 0
            site_files = sum(len(f) for f in timestamps.values())

            progress.newline(
                f"[{sites_done}/{total_sites}] {website} "
                f"({len(timestamps)} snapshots, {site_files} files)"
            )

            for ts_idx, (timestamp, files) in enumerate(sorted(timestamps.items()), 1):
                ts_display = format_timestamp(timestamp)

                for file_idx, filepath in enumerate(files, 1):
                    files_scanned += 1
                    fname = os.path.basename(filepath)

                    progress.overwrite(
                        f"    [{ts_display}] "
                        f"({file_idx}/{len(files)}) {fname}  "
                        f"[{files_scanned}/{total_files} total | {progress.elapsed()}]"
                    )

                    findings = self.scan_file(filepath)

                    # Annotate with metadata
                    rel = os.path.relpath(filepath, root_dir)
                    for f in findings:
                        f.website = website
                        f.timestamp = timestamp
                        f.relative_path = rel

                    all_findings.extend(findings)
                    site_findings_count += len(findings)

                progress.done()

            # Site summary line
            if site_findings_count > 0:
                crit = sum(1 for f in all_findings if f.website == website and f.severity == "CRITICAL")
                high = sum(1 for f in all_findings if f.website == website and f.severity == "HIGH")
                progress.newline(
                    f"    => {site_findings_count} findings "
                    f"(CRITICAL={crit}, HIGH={high})"
                )
            else:
                progress.newline(f"    => Clean — no findings")
            progress.newline("")

        # Filter by severity
        if min_severity:
            min_level = SEVERITY_ORDER.get(min_severity.upper(), 4)
            all_findings = [
                f for f in all_findings
                if SEVERITY_ORDER.get(f.severity, 4) <= min_level
            ]

        all_findings.sort(key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 4),
            f.website,
            f.timestamp,
            f.file_path,
        ))

        progress.newline(f"{'='*70}")
        progress.newline(f"  SCAN COMPLETE | {files_scanned} files | {progress.elapsed()}")
        progress.newline(f"  Total findings: {len(all_findings)}")
        progress.newline(f"{'='*70}")

        return all_findings


# ── Evidence Extractor ────────────────────────────────────────────────

CONTEXT_LINES = 5  # Lines of context above and below the vulnerable line

def extract_evidence(
    findings: List[Finding],
    root_dir: str,
    evidence_dir: str,
    progress: Progress,
):
    """
    Extract vulnerable code snippets with attack annotations.

    Instead of copying full files, this:
    1. Groups findings by source file
    2. Reads each file once
    3. Extracts the vulnerable lines + surrounding context
    4. Merges overlapping snippets
    5. Annotates each snippet with attack name, severity, CWE, description
    6. Writes one .evidence.txt per source file
    """

    by_file = defaultdict(list)
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            by_file[f.file_path].append(f)

    if not by_file:
        progress.newline("\n  No evidence to extract (no CRITICAL/HIGH/MEDIUM findings).")
        return

    progress.newline(f"\n  Extracting evidence from {len(by_file)} files to: {evidence_dir}/")
    os.makedirs(evidence_dir, exist_ok=True)
    files_written = 0

    for filepath in sorted(by_file.keys()):
        file_findings = by_file[filepath]
        website = file_findings[0].website
        timestamp = file_findings[0].timestamp
        relpath = file_findings[0].relative_path

        is_binary = filepath.endswith(".wasm")

        if is_binary:
            evidence_text = _build_binary_evidence(filepath, file_findings, relpath)
        else:
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    source_lines = fh.readlines()
            except Exception as e:
                progress.newline(f"    ERROR reading {relpath}: {e}")
                continue
            evidence_text = _build_text_evidence(
                source_lines, file_findings, filepath, relpath, website, timestamp
            )

        dest_path = os.path.join(evidence_dir, relpath + ".evidence.txt")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "w", encoding="utf-8") as fh:
            fh.write(evidence_text)

        files_written += 1
        progress.overwrite(f"    [{files_written}/{len(by_file)}] {relpath}.evidence.txt")

    progress.done()
    progress.newline(f"    => {files_written} evidence files written to {evidence_dir}/")


def _build_text_evidence(
    source_lines: list,
    file_findings: list,
    filepath: str,
    relpath: str,
    website: str,
    timestamp: str,
) -> str:
    """Build annotated evidence for a text file (JS, CSS, XML, XSLT)."""

    total_lines = len(source_lines)
    file_findings = sorted(file_findings, key=lambda f: (f.line_number, SEVERITY_ORDER.get(f.severity, 4)))

    # Build snippet regions: merge findings that are close together
    regions = []
    for f in file_findings:
        if f.line_number <= 0:
            continue
        start = max(1, f.line_number - CONTEXT_LINES)
        end = min(total_lines, f.line_number + CONTEXT_LINES)
        if regions and start <= regions[-1][1] + 2:
            regions[-1] = (regions[-1][0], max(regions[-1][1], end), regions[-1][2] + [f])
        else:
            regions.append((start, end, [f]))

    file_level = [f for f in file_findings if f.line_number <= 0]

    # Header
    out = []
    out.append("=" * 72)
    out.append("EVIDENCE FILE")
    out.append("=" * 72)
    out.append(f"Source:    {relpath}")
    out.append(f"Website:   {website}")
    out.append(f"Snapshot:  {format_timestamp(timestamp)}")
    out.append(f"Findings:  {len(file_findings)}")

    sev_counts = Counter(f.severity for f in file_findings)
    sev_str = ", ".join(f"{s}={sev_counts[s]}" for s in ["CRITICAL", "HIGH", "MEDIUM"] if sev_counts.get(s))
    out.append(f"Severity:  {sev_str}")

    attacks = sorted(set(f.test_name for f in file_findings))
    attack_names = [ATTACK_INFO.get(a, {}).get("name", a) for a in attacks]
    out.append(f"Attacks:   {', '.join(attack_names)}")
    out.append("=" * 72)

    # File-level findings (no specific line — e.g., bulk CSS detection)
    if file_level:
        out.append("")
        out.append("-" * 72)
        out.append("FILE-LEVEL FINDINGS (pattern detected across the file)")
        out.append("-" * 72)
        for f in file_level:
            info = ATTACK_INFO.get(f.test_name, {})
            out.append(f"")
            out.append(f"  [{f.severity}] {info.get('name', f.test_name)}")
            if info.get("cwe"):
                out.append(f"  CWE:    {info['cwe']}")
            out.append(f"  Detail: {f.description}")

    # Code regions with annotations
    for region_idx, (start, end, region_findings) in enumerate(regions, 1):
        out.append("")
        out.append("-" * 72)
        out.append(f"VULNERABLE CODE — Region {region_idx} (lines {start}-{end})")
        out.append("-" * 72)

        # Map line numbers to findings for annotation
        vuln_lines = defaultdict(list)
        for f in region_findings:
            vuln_lines[f.line_number].append(f)

        # Print what's wrong in this region
        for f in region_findings:
            info = ATTACK_INFO.get(f.test_name, {})
            out.append(f"")
            out.append(f"  >> [{f.severity}] {info.get('name', f.test_name)} — line {f.line_number}")
            if info.get("cwe"):
                out.append(f"     CWE:    {info['cwe']}")
            out.append(f"     Detail: {f.description}")

        # Print the code
        out.append("")
        for line_num in range(start, end + 1):
            if line_num < 1 or line_num > total_lines:
                continue
            line_text = source_lines[line_num - 1].rstrip("\n\r")

            if line_num in vuln_lines:
                line_findings = vuln_lines[line_num]
                worst = min(line_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 4))
                tag = worst.severity[:4]

                # Short labels for inline annotation
                labels = sorted(set(
                    ATTACK_INFO.get(f.test_name, {}).get("name", f.test_name)[:30]
                    for f in line_findings
                ))

                out.append(f" >>>{tag}  {line_num:>5} | {line_text}")
                out.append(f"          {'':>{len(str(line_num))}} |   ^^^^ [{' | '.join(labels)}]")
            else:
                out.append(f"         {line_num:>5} | {line_text}")

    out.append("")
    out.append("-" * 72)
    out.append(f"END OF EVIDENCE — {relpath}")
    out.append("-" * 72)

    return "\n".join(out)


def _build_binary_evidence(filepath: str, file_findings: list, relpath: str) -> str:
    """Build evidence for binary files (WASM) — annotations only."""
    out = []
    out.append("=" * 72)
    out.append("EVIDENCE FILE (binary)")
    out.append("=" * 72)
    out.append(f"Source:    {relpath}")
    out.append(f"Website:   {file_findings[0].website}")
    out.append(f"Snapshot:  {format_timestamp(file_findings[0].timestamp)}")
    out.append(f"Findings:  {len(file_findings)}")
    out.append(f"Note:      Binary file — showing signature matches, not source code")
    out.append("=" * 72)

    for i, f in enumerate(file_findings, 1):
        info = ATTACK_INFO.get(f.test_name, {})
        out.append(f"")
        out.append(f"  [{f.severity}] Finding {i}: {info.get('name', f.test_name)}")
        if info.get("cwe"):
            out.append(f"  CWE:    {info['cwe']}")
        out.append(f"  Detail: {f.description}")
        if f.line_content:
            out.append(f"  Match:  {f.line_content[:200]}")

    out.append("")
    out.append("-" * 72)
    out.append(f"END OF EVIDENCE — {relpath}")
    out.append("-" * 72)

    return "\n".join(out)


# ── Stats Printer ────────────────────────────────────────────────────────

def print_stats(findings: List[Finding], structure: Dict, progress: Progress):
    """Print comprehensive statistics."""

    if not findings:
        progress.newline("\n  No findings to report.")
        return

    progress.newline(f"\n{'='*70}")
    progress.newline(f"  RESULTS SUMMARY")
    progress.newline(f"{'='*70}")

    # ── Overall severity counts ──
    sev_counts = Counter(f.severity for f in findings)
    total = len(findings)
    progress.newline(f"\n  SEVERITY BREAKDOWN")
    progress.newline(f"  {'─'*40}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        count = sev_counts.get(sev, 0)
        bar = "█" * min(count, 50)
        pct = (count / total * 100) if total else 0
        progress.newline(f"  {sev:<10} {count:>5}  ({pct:5.1f}%)  {bar}")
    progress.newline(f"  {'─'*40}")
    progress.newline(f"  {'TOTAL':<10} {total:>5}")

    # ── Attack type breakdown ──
    progress.newline(f"\n  ATTACKS DETECTED")
    progress.newline(f"  {'─'*66}")
    progress.newline(f"  {'Attack':<40} {'CWE':<12} {'Count':>6} {'Worst':>8}")
    progress.newline(f"  {'─'*40} {'─'*12} {'─'*6} {'─'*8}")

    by_attack = defaultdict(list)
    for f in findings:
        by_attack[f.test_name].append(f)

    for test_name, atk_findings in sorted(
        by_attack.items(),
        key=lambda x: min(SEVERITY_ORDER.get(f.severity, 4) for f in x[1])
    ):
        info = ATTACK_INFO.get(test_name, {})
        name = info.get("name", test_name)[:39]
        cwe = info.get("cwe", "")[:11]
        worst = min(atk_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 4)).severity
        progress.newline(f"  {name:<40} {cwe:<12} {len(atk_findings):>6} {worst:>8}")

    # ── Per-website breakdown ──
    progress.newline(f"\n  PER-WEBSITE BREAKDOWN")
    progress.newline(f"  {'─'*66}")
    progress.newline(
        f"  {'Website':<35} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'Total':>6}"
    )
    progress.newline(f"  {'─'*35} {'─'*5} {'─'*5} {'─'*5} {'─'*6}")

    by_site = defaultdict(list)
    for f in findings:
        by_site[f.website].append(f)

    for website in sorted(by_site.keys()):
        site_findings = by_site[website]
        sc = Counter(f.severity for f in site_findings)
        name = website[:34]
        progress.newline(
            f"  {name:<35} "
            f"{sc.get('CRITICAL',0):>5} "
            f"{sc.get('HIGH',0):>5} "
            f"{sc.get('MEDIUM',0):>5} "
            f"{len(site_findings):>6}"
        )

    # ── Timeline: attacks per timestamp per site ──
    progress.newline(f"\n  TIMELINE — ATTACKS PER SNAPSHOT")
    progress.newline(f"  {'─'*66}")

    for website in sorted(by_site.keys()):
        site_findings = by_site[website]
        by_ts = defaultdict(list)
        for f in site_findings:
            by_ts[f.timestamp].append(f)

        progress.newline(f"\n  {website}")
        for ts in sorted(by_ts.keys()):
            ts_findings = by_ts[ts]
            ts_display = format_timestamp(ts)
            sc = Counter(f.severity for f in ts_findings)
            atk_types = len(set(f.test_name for f in ts_findings))

            crit_high = sc.get("CRITICAL", 0) + sc.get("HIGH", 0)
            if crit_high > 0:
                status = "VULNERABLE"
            elif sc.get("MEDIUM", 0) > 0:
                status = "REVIEW"
            else:
                status = "CLEAN"

            progress.newline(
                f"    {ts_display:<22} "
                f"{status:<12} "
                f"{len(ts_findings):>4} findings, "
                f"{atk_types:>2} attack types  "
                f"(C={sc.get('CRITICAL',0)} H={sc.get('HIGH',0)} M={sc.get('MEDIUM',0)})"
            )

    # ── Most vulnerable files ──
    progress.newline(f"\n  TOP 15 MOST VULNERABLE FILES")
    progress.newline(f"  {'─'*66}")

    file_crit_high = Counter()
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH"):
            file_crit_high[f.relative_path] += 1

    if file_crit_high:
        for fpath, count in file_crit_high.most_common(15):
            progress.newline(f"  {count:>4} CRIT+HIGH  {fpath}")
    else:
        progress.newline(f"  No CRITICAL or HIGH findings.")

    # ── Unique attack types per website ──
    progress.newline(f"\n  ATTACK COVERAGE MAP")
    progress.newline(f"  {'─'*66}")
    progress.newline(f"  Which attacks affect which websites:\n")

    attack_sites = defaultdict(set)
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            attack_sites[f.test_name].add(f.website)

    for test_name in sorted(attack_sites.keys(),
                             key=lambda t: -len(attack_sites[t])):
        info = ATTACK_INFO.get(test_name, {})
        name = info.get("name", test_name)[:35]
        sites = attack_sites[test_name]
        progress.newline(f"  {name:<36} → {len(sites)} sites")
        for s in sorted(sites)[:5]:
            progress.newline(f"    {'':36}   {s}")
        if len(sites) > 5:
            progress.newline(f"    {'':36}   ... and {len(sites)-5} more")

    progress.newline(f"\n{'='*70}")


# ── Report Writer ────────────────────────────────────────────────────────

def write_reports(
    findings: List[Finding],
    structure: Dict,
    report_dir: str,
    progress: Progress,
):
    """Write per-website JSON reports and a master summary."""

    os.makedirs(report_dir, exist_ok=True)

    by_site = defaultdict(list)
    for f in findings:
        by_site[f.website].append(f)

    # ── Per-website reports ──
    for website, site_findings in sorted(by_site.items()):
        safe_name = website.replace("/", "_").replace(":", "_")
        report_path = os.path.join(report_dir, f"{safe_name}.json")

        by_ts = defaultdict(list)
        for f in site_findings:
            by_ts[f.timestamp].append(f)

        snapshots = []
        for ts in sorted(by_ts.keys()):
            ts_findings = by_ts[ts]
            sc = Counter(f.severity for f in ts_findings)
            attacks_found = sorted(set(f.test_name for f in ts_findings))
            snapshots.append({
                "timestamp": ts,
                "timestamp_readable": format_timestamp(ts),
                "total_findings": len(ts_findings),
                "severity_breakdown": dict(sc),
                "attacks_found": attacks_found,
                "findings": [asdict(f) for f in ts_findings],
            })

        sc_total = Counter(f.severity for f in site_findings)
        report = {
            "website": website,
            "total_findings": len(site_findings),
            "severity_breakdown": dict(sc_total),
            "attacks_found": sorted(set(f.test_name for f in site_findings)),
            "snapshots_scanned": len(by_ts),
            "snapshots": snapshots,
        }

        with open(report_path, "w") as fh:
            json.dump(report, fh, indent=2)

    # ── Master summary ──
    master_path = os.path.join(report_dir, "_MASTER_SUMMARY.json")

    site_summaries = []
    for website, site_findings in sorted(by_site.items()):
        sc = Counter(f.severity for f in site_findings)
        crit_high = sc.get("CRITICAL", 0) + sc.get("HIGH", 0)
        site_summaries.append({
            "website": website,
            "status": "VULNERABLE" if crit_high > 0 else "REVIEW" if sc.get("MEDIUM", 0) > 0 else "CLEAN",
            "total_findings": len(site_findings),
            "critical": sc.get("CRITICAL", 0),
            "high": sc.get("HIGH", 0),
            "medium": sc.get("MEDIUM", 0),
            "attacks_found": sorted(set(f.test_name for f in site_findings)),
            "snapshots": len(set(f.timestamp for f in site_findings)),
        })

    site_summaries.sort(key=lambda s: -(s["critical"] * 100 + s["high"] * 10 + s["medium"]))

    master = {
        "scan_timestamp": datetime.now().isoformat(),
        "total_websites": len(structure),
        "websites_with_findings": len(by_site),
        "total_findings": len(findings),
        "severity_breakdown": dict(Counter(f.severity for f in findings)),
        "attack_types_found": sorted(set(f.test_name for f in findings)),
        "websites": site_summaries,
    }

    with open(master_path, "w") as fh:
        json.dump(master, fh, indent=2)

    progress.newline(f"\n  Reports written to: {report_dir}/")
    progress.newline(f"    {len(by_site)} website reports + _MASTER_SUMMARY.json")


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan output_web/{website}/{timestamp}/{files} for security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan_archive.py output_web/
  python scan_archive.py output_web/ --site example.com
  python scan_archive.py output_web/ --severity HIGH --site example.com
  python scan_archive.py output_web/ --evidence-dir ./evidence --report-dir ./reports

Scans: HTML (.html .htm), JS (.js .mjs .jsx .ts .tsx), CSS (.css),
       XML (.xml .xsl .xslt .soap .rss .atom), WASM (.wasm)

Note: Use the id_ flag when downloading from Wayback Machine to get
      original content without wombat.js injection.

Output:
  evidence/           Annotated vulnerable code snippets
  reports/            Per-website JSON reports + master summary
  Terminal            Full stats with progress
        """,
    )

    parser.add_argument("directory",
                        help="Root directory (e.g., output_web/)")
    parser.add_argument("--evidence-dir", default="evidence",
                        help="Where to write evidence files (default: ./evidence)")
    parser.add_argument("--report-dir", default="reports",
                        help="Where to write JSON reports (default: ./reports)")
    parser.add_argument("--severity", "-s",
                        choices=["CRITICAL", "HIGH", "MEDIUM"],
                        help="Minimum severity to include (default: all)")
    parser.add_argument("--site", type=str, default=None,
                        help="Only scan websites matching this substring")
    parser.add_argument("--no-evidence", action="store_true",
                        help="Skip writing evidence files")
    parser.add_argument("--no-reports", action="store_true",
                        help="Skip writing JSON reports")

    args = parser.parse_args()
    progress = Progress()

    # ── Clean up --site input ──
    site_filter = args.site
    if site_filter:
        site_filter = site_filter.strip("/").strip("\\")
        if "/" in site_filter or "\\" in site_filter:
            site_filter = os.path.basename(site_filter)

    # ── Auto-detect: did the user pass a website dir instead of root? ──
    root_dir = args.directory.rstrip("/").rstrip("\\")

    if not site_filter:
        subdirs = []
        try:
            subdirs = [d for d in os.listdir(root_dir)
                       if os.path.isdir(os.path.join(root_dir, d)) and not d.startswith('.')]
        except OSError:
            pass

        looks_like_timestamps = subdirs and all(
            (len(d) >= 8 and d[:8].isdigit()) for d in subdirs[:5]
        )
        if looks_like_timestamps:
            inferred_site = os.path.basename(root_dir)
            root_dir = os.path.dirname(root_dir)
            site_filter = inferred_site
            progress.newline(f"\n  Auto-detected: '{args.directory}' looks like a website directory")
            progress.newline(f"  Using root='{root_dir}/' and --site={site_filter}")

    # ── Discover structure ──
    progress.newline(f"\n  Discovering structure in: {root_dir}/")
    if site_filter:
        progress.newline(f"  Site filter: '{site_filter}'")

    structure = discover_structure(root_dir, site_filter=site_filter)

    if not structure:
        progress.newline(f"\n  ERROR: No scannable files found.")
        all_sites = discover_structure(root_dir, site_filter=None)
        if all_sites:
            progress.newline(f"\n  Available websites in {root_dir}/:")
            for site_name in sorted(all_sites.keys()):
                ts_count = len(all_sites[site_name])
                file_count = sum(len(f) for f in all_sites[site_name].values())
                progress.newline(f"    {site_name:<40} ({ts_count} snapshots, {file_count} files)")
            if site_filter:
                progress.newline(f"\n  Your --site '{site_filter}' didn't match any of these.")
                progress.newline(f"  The filter is a substring match — try a shorter string.")
        else:
            progress.newline(f"  Expected structure: output_web/{{website}}/{{timestamp}}/{{files}}")
            progress.newline(f"  No website directories found in {root_dir}/")
        sys.exit(1)

    total_sites = len(structure)
    total_ts = sum(len(ts) for ts in structure.values())
    total_files = sum(len(f) for s in structure.values() for f in s.values())

    if site_filter:
        matched = ", ".join(sorted(structure.keys()))
        progress.newline(f"  Matched: {matched}")

    progress.newline(f"  Found {total_sites} website(s), {total_ts} snapshots, {total_files} files")
    progress.newline("")

    # ── Scan ──
    scanner = ArchiveScanner()
    findings = scanner.scan_archive(
        structure, root_dir,
        min_severity=args.severity,
        progress=progress,
    )

    # ── Extract evidence ──
    if not args.no_evidence and findings:
        extract_evidence(findings, root_dir, args.evidence_dir, progress)

    # ── Write reports ──
    if not args.no_reports and findings:
        write_reports(findings, structure, args.report_dir, progress)

    # ── Print stats ──
    print_stats(findings, structure, progress)

    # ── Final line ──
    progress.newline(f"\n  DONE in {progress.elapsed()}")
    progress.newline(f"{'='*70}\n")

    crit_high = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
    sys.exit(1 if crit_high > 0 else 0)


if __name__ == "__main__":
    main()
