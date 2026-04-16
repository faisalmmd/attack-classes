"""
Vulnerable JavaScript Library Detector (Retire.js-compatible)

Identifies JavaScript library versions and checks them against a database
of known-vulnerable versions with their CVEs. Works without npm/node —
uses built-in version detection patterns.

If the `retire` CLI is installed (npm install -g retire), the scanner
will use it for comprehensive coverage. Otherwise it falls back to the
built-in database covering the most critical CVEs in the most common
libraries.

Reference: Lauinger et al., "Thou Shalt Not Depend on Me: Analysing
the Use of Outdated JavaScript Libraries on the Web," NDSS 2017.
"""

import re
import os
import json
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class Finding:
    test_name: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    description: str


# ====================================================================== #
# BUILT-IN VULNERABILITY DATABASE
# ====================================================================== #
# Each entry: library name → list of (version_regex, max_vulnerable, cve, severity, description)
#
# version_regex: regex to extract version string from file content
# max_vulnerable: versions up to AND INCLUDING this are vulnerable
# cve: CVE identifier
# severity: CRITICAL / HIGH / MEDIUM
# description: what the vulnerability allows

VULN_DB = {
    "jquery": {
        "extractors": [
            # jQuery version patterns found in minified and unminified files
            r'jquery[./\s]+v?(\d+\.\d+\.\d+)',
            r'jQuery\s+v(\d+\.\d+\.\d+)',
            r'jQuery\s+JavaScript\s+Library\s+v(\d+\.\d+\.\d+)',
            r'jquery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)',
            r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)',
        ],
        "vulnerabilities": [
            ("3.4.99",  "CRITICAL", "CVE-2020-11022", "XSS via HTML passed to jQuery DOM manipulation methods"),
            ("2.2.99",  "CRITICAL", "CVE-2020-11023", "XSS in jQuery.htmlPrefilter regex"),
            ("2.2.99",  "HIGH",     "CVE-2019-11358", "Prototype pollution via jQuery.extend(true, ...)"),
            ("1.11.99", "HIGH",     "CVE-2015-9251",  "XSS via cross-domain AJAX when receiving non-JSON Content-Type"),
            ("1.6.99",  "MEDIUM",   "CVE-2012-6708",  "XSS via selector when input contains #"),
            ("1.4.99",  "MEDIUM",   "CVE-2011-4969",  "XSS via location.hash in jQuery < 1.5"),
        ],
    },
    "angularjs": {
        "extractors": [
            r'angular[./\s]+v?(\d+\.\d+\.\d+)',
            r'AngularJS\s+v(\d+\.\d+\.\d+)',
            r'angular\.version\s*=\s*\{[^}]*full:\s*["\'](\d+\.\d+\.\d+)',
        ],
        "vulnerabilities": [
            ("1.7.99", "CRITICAL", "CVE-2022-25869", "XSS via $sanitize bypass in AngularJS"),
            ("1.5.99", "HIGH",     "CVE-2019-10768", "Prototype pollution in merge function"),
            ("1.5.99", "HIGH",     "CVE-2019-14863", "XSS via SVG animation"),
            ("1.4.99", "HIGH",     "CVE-2018-14042", "Sandbox bypass allowing arbitrary code execution"),
        ],
    },
    "lodash": {
        "extractors": [
            r'lodash[./\s]+v?(\d+\.\d+\.\d+)',
            r'Lodash\s+v(\d+\.\d+\.\d+)',
            r'lodash\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)',
            r'VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\'].*lodash',
        ],
        "vulnerabilities": [
            ("4.17.20", "CRITICAL", "CVE-2021-23337", "Command injection via template function"),
            ("4.17.18", "HIGH",     "CVE-2020-28500", "ReDoS in _.trim, _.trimEnd, _.trimStart"),
            ("4.17.15", "HIGH",     "CVE-2020-8203",  "Prototype pollution via zipObjectDeep"),
            ("4.17.11", "CRITICAL", "CVE-2019-10744", "Prototype pollution via defaultsDeep"),
            ("4.17.4",  "HIGH",     "CVE-2018-16487", "Prototype pollution via merge and mergeWith"),
        ],
    },
    "bootstrap": {
        "extractors": [
            r'bootstrap[./\s]+v?(\d+\.\d+\.\d+)',
            r'Bootstrap\s+v(\d+\.\d+\.\d+)',
            r'Bootstrap\s*\(v(\d+\.\d+\.\d+)\)',
        ],
        "vulnerabilities": [
            ("3.4.0",  "MEDIUM", "CVE-2019-8331",  "XSS via tooltip/popover data-template attribute"),
            ("3.3.99", "MEDIUM", "CVE-2018-14042", "XSS via data-target attribute in collapse plugin"),
            ("3.3.99", "MEDIUM", "CVE-2018-14040", "XSS via data-parent attribute in collapse plugin"),
            ("3.3.99", "MEDIUM", "CVE-2016-10735", "XSS via data-target attribute in scrollspy plugin"),
        ],
    },
    "moment": {
        "extractors": [
            r'moment[./\s]+v?(\d+\.\d+\.\d+)',
            r'momentjs\.com.*?(\d+\.\d+\.\d+)',
            r'moment\.version\s*=\s*["\'](\d+\.\d+\.\d+)',
        ],
        "vulnerabilities": [
            ("2.29.3", "HIGH", "CVE-2022-31129", "ReDoS in string parsing — crafted date string causes backtracking"),
            ("2.19.2", "MEDIUM", "CVE-2017-18214", "ReDoS in moment duration parsing"),
        ],
    },
    "handlebars": {
        "extractors": [
            r'[Hh]andlebars[./\s]+v?(\d+\.\d+\.\d+)',
            r'Handlebars\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)',
        ],
        "vulnerabilities": [
            ("4.7.6",  "CRITICAL", "CVE-2021-23369", "Remote code execution via crafted template"),
            ("4.7.5",  "CRITICAL", "CVE-2021-23383", "Prototype pollution via template compilation"),
            ("4.5.2",  "HIGH",     "CVE-2019-19919", "Prototype pollution via the lookup helper"),
        ],
    },
    "dompurify": {
        "extractors": [
            r'DOMPurify[./\s]+v?(\d+\.\d+\.\d+)',
            r'dompurify.*?(\d+\.\d+\.\d+)',
        ],
        "vulnerabilities": [
            ("2.3.5",  "HIGH", "CVE-2022-25927", "Mutation XSS bypass in DOMPurify"),
            ("2.0.16", "HIGH", "CVE-2020-26870", "Mutation XSS via namespace confusion"),
        ],
    },
    "vue": {
        "extractors": [
            r'Vue\.js\s+v(\d+\.\d+\.\d+)',
            r'vue[./\s]+v?(\d+\.\d+\.\d+)',
        ],
        "vulnerabilities": [
            ("2.6.11", "MEDIUM", "CVE-2020-13956", "XSS via v-html directive (by design, but often misused)"),
        ],
    },
    "react-dom": {
        "extractors": [
            r'react-dom[./\s]+v?(\d+\.\d+\.\d+)',
            r'ReactDOM\s+v(\d+\.\d+\.\d+)',
        ],
        "vulnerabilities": [
            # CVE-2018-6341: XSS via custom HTML attributes when using SSR
            ("16.1.99", "HIGH", "CVE-2018-6341", "XSS via malicious attribute names in server-side rendering"),
        ],
    },
    "underscore": {
        "extractors": [
            r'[Uu]nderscore[./\s]+v?(\d+\.\d+\.\d+)',
            r'Underscore\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)',
        ],
        "vulnerabilities": [
            ("1.13.0", "CRITICAL", "CVE-2021-23358", "Arbitrary code execution via template function"),
            ("1.12.0", "HIGH",     "CVE-2021-23358", "Code injection via _.template"),
        ],
    },
}


# ====================================================================== #
# VERSION COMPARISON
# ====================================================================== #

def parse_version(v: str) -> Tuple[int, ...]:
    """Parse "1.2.3" into (1, 2, 3) for comparison."""
    try:
        return tuple(int(x) for x in v.split("."))
    except (ValueError, AttributeError):
        return (0, 0, 0)


def version_lte(detected: str, max_vuln: str) -> bool:
    """Check if detected version <= max vulnerable version."""
    return parse_version(detected) <= parse_version(max_vuln)


# ====================================================================== #
# SCANNER
# ====================================================================== #

class RetireScanner:
    """
    Scan JavaScript files for known-vulnerable library versions.

    Tries to use the `retire` CLI (npm install -g retire) first.
    Falls back to built-in database if retire is not installed.
    """

    EXTENSIONS = {".js", ".mjs"}

    def __init__(self):
        self._retire_available = None

    def _check_retire_cli(self) -> bool:
        """Check if retire CLI is installed."""
        if self._retire_available is None:
            try:
                result = subprocess.run(
                    ["retire", "--version"],
                    capture_output=True, text=True, timeout=5,
                )
                self._retire_available = result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._retire_available = False
        return self._retire_available

    def scan(self, file_path: str) -> List[Finding]:
        """Scan one JS file for vulnerable library versions."""
        # Try retire CLI first
        if self._check_retire_cli():
            findings = self._scan_with_retire_cli(file_path)
            if findings is not None:  # None means retire failed, fall through
                return findings

        # Fall back to built-in scanner
        return self._scan_builtin(file_path)

    def _scan_with_retire_cli(self, file_path: str) -> Optional[List[Finding]]:
        """Run retire CLI on a single file and parse JSON output."""
        try:
            result = subprocess.run(
                ["retire", "--jspath", file_path, "--outputformat", "json",
                 "--exitwith", "0"],
                capture_output=True, text=True, timeout=30,
            )

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            findings = []

            for entry in data:
                for result_item in entry.get("results", []):
                    component = result_item.get("component", "unknown")
                    version = result_item.get("version", "unknown")

                    for vuln in result_item.get("vulnerabilities", []):
                        severity_map = {
                            "low": None, "medium": "MEDIUM",
                            "high": "HIGH", "critical": "CRITICAL",
                        }
                        sev = severity_map.get(
                            vuln.get("severity", "medium").lower(), "MEDIUM"
                        )
                        if sev is None:
                            continue  # Skip LOW findings

                        identifiers = vuln.get("identifiers", {})
                        cve = identifiers.get("CVE", [""])[0] if "CVE" in identifiers else ""
                        summary = vuln.get("info", [""])[0] if vuln.get("info") else ""

                        findings.append(Finding(
                            "vulnerable_library", sev, file_path, 0,
                            f"{component} {version}",
                            f"{component} {version} — {cve}: {summary}"[:300]
                        ))

            return findings

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            return None  # Fall through to built-in

    def _scan_builtin(self, file_path: str) -> List[Finding]:
        """Scan using built-in version detection patterns."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return []

        # Only read first 200KB for version strings (they're in headers/comments)
        header = content[:200_000]
        findings = []

        for lib_name, lib_info in VULN_DB.items():
            # Try each extractor regex to find version
            detected_version = None
            match_line = 0
            match_text = ""

            for pattern in lib_info["extractors"]:
                match = re.search(pattern, header, re.IGNORECASE)
                if match:
                    detected_version = match.group(1)
                    # Find line number
                    pos = match.start()
                    match_line = header[:pos].count("\n") + 1
                    match_text = match.group(0)[:200]
                    break

            if not detected_version:
                continue

            # Check against vulnerability database
            for max_vuln, severity, cve, description in lib_info["vulnerabilities"]:
                if version_lte(detected_version, max_vuln):
                    findings.append(Finding(
                        "vulnerable_library", severity, file_path, match_line,
                        match_text,
                        f"{lib_name} {detected_version} — {cve}: {description}"
                    ))

        return findings
