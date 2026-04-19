"""
HTML Security Scanner
Tests:
  - HTML Violation Analyzer: unclosed elements, nested forms, misplaced tags, duplicate IDs
  - Inline <script> extraction → delegates to JS scanner
  - Inline <style> extraction → delegates to CSS scanner
  - Missing SRI (Subresource Integrity) on external scripts/stylesheets
  - Clickjacking: missing frame defenses
  - Dangerous base tag
  - Meta refresh redirect
  - Form action hijacking (HTTP action, formaction override)
  - Dangling markup / unclosed attributes
"""

import re
import os
from dataclasses import dataclass
from typing import List
from html.parser import HTMLParser


@dataclass
class Finding:
    test_name: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    description: str


# ── Inline Block Extractor ───────────────────────────────────────────

class InlineExtractor(HTMLParser):
    """Extract inline <script> and <style> blocks with line numbers."""

    def __init__(self):
        super().__init__()
        self._current_tag = None
        self._current_line = 0
        self._current_content = []
        self.scripts = []   # [(line_number, code_string)]
        self.styles = []    # [(line_number, code_string)]

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        attr_dict = dict(attrs)

        if tag_lower == "script" and "src" not in attr_dict:
            # Inline script (no src attribute)
            self._current_tag = "script"
            self._current_line = self.getpos()[0]
            self._current_content = []
        elif tag_lower == "style":
            self._current_tag = "style"
            self._current_line = self.getpos()[0]
            self._current_content = []

    def handle_data(self, data):
        if self._current_tag:
            self._current_content.append(data)

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower == self._current_tag:
            content = "".join(self._current_content).strip()
            if content:
                if self._current_tag == "script":
                    self.scripts.append((self._current_line, content))
                elif self._current_tag == "style":
                    self.styles.append((self._current_line, content))
            self._current_tag = None
            self._current_content = []


# ── HTML Violation Parser ────────────────────────────────────────────

# Void elements that never have closing tags
VOID_ELEMENTS = {
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
    'link', 'meta', 'param', 'source', 'track', 'wbr',
}

# Raw text elements — content is not parsed as HTML
RAW_TEXT_ELEMENTS = {'script', 'style', 'textarea', 'title'}

# Block elements that auto-close <p>
BLOCK_ELEMENTS = {
    'address', 'article', 'aside', 'blockquote', 'details', 'dialog',
    'dd', 'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure',
    'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header',
    'hgroup', 'hr', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section',
    'table', 'ul',
}

class ViolationParser(HTMLParser):
    """
    Parse HTML and detect structural violations:
    - Unclosed elements (tag opened but never closed)
    - Nested forms (<form> inside <form>)
    - Misplaced tags (block elements inside inline elements like <a>, <span>)
    - Duplicate IDs
    - <p> inside <p> (auto-closed but sloppy)
    """

    def __init__(self):
        super().__init__()
        self.violations = []       # [(line, severity, description)]
        self._tag_stack = []       # [(tag_name, line_number)]
        self._form_depth = 0
        self._seen_ids = {}        # {id_value: line_number}
        self._in_inline = []       # Stack of inline parent tags

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        line = self.getpos()[0]
        attr_dict = {k.lower(): v for k, v in attrs if k}

        # ── Check duplicate IDs ──
        elem_id = attr_dict.get('id', '')
        if elem_id:
            if elem_id in self._seen_ids:
                self.violations.append((
                    line, "MEDIUM",
                    f"Duplicate id=\"{elem_id}\" (first seen at line "
                    f"{self._seen_ids[elem_id]}) — can cause DOM clobbering "
                    f"and inconsistent querySelector behavior"
                ))
            else:
                self._seen_ids[elem_id] = line

        # ── Check nested forms ──
        if tag == 'form':
            self._form_depth += 1
            if self._form_depth > 1:
                self.violations.append((
                    line, "HIGH",
                    f"Nested <form> detected (depth {self._form_depth}) — "
                    f"nested forms cause inconsistent browser parsing and "
                    f"have historically enabled XSS filter bypasses"
                ))

        # ── Check block inside inline ──
        inline_parents = {'a', 'span', 'b', 'i', 'em', 'strong', 'small',
                         'abbr', 'cite', 'code', 'label', 'sub', 'sup'}
        if tag in BLOCK_ELEMENTS and self._in_inline:
            parent_tag, parent_line = self._in_inline[-1]
            self.violations.append((
                line, "MEDIUM",
                f"Block element <{tag}> inside inline element <{parent_tag}> "
                f"(opened at line {parent_line}) — causes inconsistent "
                f"browser parsing behavior"
            ))

        if tag in inline_parents:
            self._in_inline.append((tag, line))

        # ── Push to tag stack (skip void elements) ──
        if tag not in VOID_ELEMENTS and tag not in RAW_TEXT_ELEMENTS:
            self._tag_stack.append((tag, line))

    def handle_endtag(self, tag):
        tag = tag.lower()
        line = self.getpos()[0]

        if tag == 'form':
            self._form_depth = max(0, self._form_depth - 1)

        # Pop inline tracking
        inline_parents = {'a', 'span', 'b', 'i', 'em', 'strong', 'small',
                         'abbr', 'cite', 'code', 'label', 'sub', 'sup'}
        if tag in inline_parents and self._in_inline:
            if self._in_inline[-1][0] == tag:
                self._in_inline.pop()

        # ── Check for mismatched closing tag ──
        if tag in VOID_ELEMENTS:
            return  # Void elements don't need closing tags

        # Find the matching open tag in the stack
        found = False
        for i in range(len(self._tag_stack) - 1, -1, -1):
            if self._tag_stack[i][0] == tag:
                # Everything between this and top of stack is unclosed
                unclosed = self._tag_stack[i+1:]
                for utag, uline in unclosed:
                    self.violations.append((
                        uline, "MEDIUM",
                        f"Unclosed <{utag}> (opened at line {uline}, "
                        f"implicitly closed by </{tag}> at line {line}) — "
                        f"inconsistent parsing may enable XSS filter bypass"
                    ))
                self._tag_stack = self._tag_stack[:i]
                found = True
                break



    def get_unclosed_at_end(self):
        """Return tags still open at end of document."""
        # Filter out common auto-closed tags (html, head, body are OK to leave open)
        ignore = {'html', 'head', 'body'}
        return [(tag, line) for tag, line in self._tag_stack
                if tag not in ignore]


class HTMLScanner:
    """Runs HTML-specific security tests + inline script/style delegation."""

    EXTENSIONS = {".html", ".htm"}

    def __init__(self):
        # Lazy imports to avoid circular dependency at module load
        self._js_scanner = None
        self._css_scanner = None

    def _get_js_scanner(self):
        if self._js_scanner is None:
            from .js_scanner import JavaScriptScanner
            self._js_scanner = JavaScriptScanner()
        return self._js_scanner

    def _get_css_scanner(self):
        if self._css_scanner is None:
            from .css_scanner import CSSScanner
            self._css_scanner = CSSScanner()
        return self._css_scanner

    def scan(self, file_path: str) -> List[Finding]:
        """Run all HTML tests on one file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return []

        lines = content.split("\n")
        findings = []

        # HTML-specific tests
        findings.extend(self._test_html_violations(file_path, content))
        findings.extend(self._test_missing_sri(file_path, lines, content))
        findings.extend(self._test_clickjacking(file_path, lines, content))
        findings.extend(self._test_base_tag(file_path, lines))
        findings.extend(self._test_meta_refresh(file_path, lines))
        findings.extend(self._test_form_action(file_path, lines, content))
        findings.extend(self._test_dangling_markup(file_path, lines, content))
        findings.extend(self._test_dom_clobbering(file_path, lines, content))

        # Extract and scan inline <script> blocks
        findings.extend(self._scan_inline_scripts(file_path, content))

        # Extract and scan inline <style> blocks
        findings.extend(self._scan_inline_styles(file_path, content))

        return findings

    # ------------------------------------------------------------------ #
    # TEST: HTML Violation Analyzer
    # ------------------------------------------------------------------ #
    def _test_html_violations(self, fp: str, content: str) -> List[Finding]:
        """
        Parse HTML structure and detect spec violations:
        - Unclosed elements that cause inconsistent parsing
        - Nested forms (historically enable XSS filter bypass)
        - Block elements inside inline elements
        - Duplicate IDs (DOM clobbering vector)
        - Tags still open at end of document

        Reference: Weinberger et al., "A Systematic Analysis of XSS
        Sanitization in Web Application Frameworks," ESORICS 2011.
        """
        findings = []

        try:
            parser = ViolationParser()
            parser.feed(content)
        except Exception as e:
            return []

        # Collect violations from parser
        lines = content.split("\n")
        for line_num, severity, description in parser.violations:
            line_text = ""
            if 0 < line_num <= len(lines):
                line_text = lines[line_num - 1].strip()[:200]
            findings.append(Finding(
                "html_violation", severity, fp, line_num,
                line_text, description
            ))

        # Check for tags still open at end of document
        unclosed = parser.get_unclosed_at_end()
        if len(unclosed) > 3:
            tags = ", ".join(f"<{t}> (line {l})" for t, l in unclosed[:10])
            extra = f" and {len(unclosed)-10} more" if len(unclosed) > 10 else ""
            findings.append(Finding(
                "html_violation", "MEDIUM", fp, 0, "",
                f"Multiple unclosed elements at end of document: {tags}{extra}"
            ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST: Missing SRI (Subresource Integrity)
    # ------------------------------------------------------------------ #
    def _test_missing_sri(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Check external <script src> and <link rel=stylesheet href> tags
        for missing integrity= attribute.

        External resources loaded without SRI can be tampered with if the
        CDN is compromised — the browser has no way to verify the file
        hasn't been modified.
        """
        findings = []

        # External script tags
        script_pattern = re.compile(
            r'<script[^>]+src\s*=\s*[\'"]([^\'"]+)[\'"][^>]*>',
            re.IGNORECASE
        )
        # External stylesheet links
        link_pattern = re.compile(
            r'<link[^>]+href\s*=\s*[\'"]([^\'"]+)[\'"][^>]*>',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check scripts
            for match in script_pattern.finditer(line):
                src = match.group(1)
                full_tag = match.group(0)

                # Only flag external (cross-origin) resources
                if not self._is_external_url(src):
                    continue

                if 'integrity=' not in full_tag.lower():
                    findings.append(Finding(
                        "missing_sri", "MEDIUM", fp, i,
                        line.strip()[:200],
                        f"External script loaded without SRI integrity hash: {src[:100]}"
                    ))

            # Check stylesheets
            for match in link_pattern.finditer(line):
                href = match.group(1)
                full_tag = match.group(0)

                if 'stylesheet' not in full_tag.lower():
                    continue
                if not self._is_external_url(href):
                    continue

                if 'integrity=' not in full_tag.lower():
                    findings.append(Finding(
                        "missing_sri", "MEDIUM", fp, i,
                        line.strip()[:200],
                        f"External stylesheet loaded without SRI integrity hash: {href[:100]}"
                    ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST: Clickjacking Defenses
    # ------------------------------------------------------------------ #
    def _test_clickjacking(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Check for frame-busting defenses. In archived HTML, we can't check
        HTTP headers, so we look for:
        - <meta> tag equivalents of X-Frame-Options
        - JavaScript frame-busting code
        - CSP frame-ancestors in meta tags
        """
        findings = []
        content_lower = content.lower()

        has_frame_options_meta = bool(re.search(
            r'<meta[^>]+http-equiv\s*=\s*[\'"]x-frame-options[\'"]',
            content_lower
        ))

        has_csp_frame_ancestors = bool(re.search(
            r'frame-ancestors', content_lower
        ))

        has_js_framebusting = bool(re.search(
            r'(?:top\s*!==?\s*self|top\s*!==?\s*window|self\s*!==?\s*top|'
            r'window\s*!==?\s*top|top\.location|parent\.location)',
            content
        ))

        # Check for iframes that could be clickjacking vectors
        iframe_pattern = re.compile(
            r'<iframe[^>]+(?:style\s*=\s*[\'"][^"]*(?:opacity\s*:\s*0|'
            r'visibility\s*:\s*hidden|position\s*:\s*(?:absolute|fixed))[^"]*[\'"])',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            for match in iframe_pattern.finditer(line):
                findings.append(Finding(
                    "clickjacking", "HIGH", fp, i,
                    line.strip()[:200],
                    "Hidden/transparent iframe detected — potential clickjacking overlay"
                ))

        # Report missing defenses (only if page has forms or interactive elements)
        has_forms = '<form' in content_lower
        has_buttons = '<button' in content_lower or 'type="submit"' in content_lower
        has_login = any(w in content_lower for w in ['login', 'signin', 'sign-in', 'password'])

        if (has_forms or has_buttons or has_login):
            if not (has_frame_options_meta or has_csp_frame_ancestors or has_js_framebusting):
                findings.append(Finding(
                    "clickjacking", "MEDIUM", fp, 0, "",
                    "Page has forms/login but no frame-busting defense detected "
                    "(no X-Frame-Options meta, no CSP frame-ancestors, no JS frame-busting)"
                ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST: Dangerous <base> Tag
    # ------------------------------------------------------------------ #
    def _test_base_tag(self, fp: str, lines: list) -> List[Finding]:
        """
        A <base href="..."> tag changes the base URL for all relative links
        on the page. If an attacker can inject a base tag pointing to their
        domain, every relative URL (scripts, stylesheets, forms, links)
        resolves to the attacker's server.
        """
        findings = []

        base_pattern = re.compile(
            r'<base[^>]+href\s*=\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            match = base_pattern.search(line)
            if match:
                href = match.group(1)
                if self._is_external_url(href):
                    findings.append(Finding(
                        "base_tag_hijack", "HIGH", fp, i,
                        line.strip()[:200],
                        f"<base> tag points to external domain: {href[:100]} — "
                        f"all relative URLs on this page resolve to this domain"
                    ))


        return findings

    # ------------------------------------------------------------------ #
    # TEST: Meta Refresh Redirect
    # ------------------------------------------------------------------ #
    def _test_meta_refresh(self, fp: str, lines: list) -> List[Finding]:
        """
        <meta http-equiv="refresh" content="0;url=https://evil.com">
        redirects the user after a delay. If the URL is external or
        user-controllable, it's an open redirect.
        """
        findings = []

        meta_pattern = re.compile(
            r'<meta[^>]+http-equiv\s*=\s*[\'"]refresh[\'"][^>]+content\s*=\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            match = meta_pattern.search(line)
            if match:
                content_val = match.group(1)
                url_match = re.search(r'url\s*=\s*(.+)', content_val, re.IGNORECASE)

                if url_match:
                    url = url_match.group(1).strip().strip("'\"")
                    if self._is_external_url(url):
                        findings.append(Finding(
                            "meta_refresh_redirect", "HIGH", fp, i,
                            line.strip()[:200],
                            f"Meta refresh redirects to external URL: {url[:100]}"
                        ))


        return findings

    # ------------------------------------------------------------------ #
    # TEST: Form Action Hijacking
    # ------------------------------------------------------------------ #
    def _test_form_action(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Check for:
        1. Forms with action pointing to HTTP (not HTTPS) — credentials leak in transit
        2. Forms with action pointing to external domain
        3. Buttons/inputs with formaction attribute (can override form action)
        4. Forms with no action (submits to current page — generally OK)
        """
        findings = []

        # Form action
        form_pattern = re.compile(
            r'<form[^>]+action\s*=\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            match = form_pattern.search(line)
            if match:
                action = match.group(1)

                if action.startswith("http://"):
                    findings.append(Finding(
                        "form_action_hijack", "HIGH", fp, i,
                        line.strip()[:200],
                        f"Form submits over plain HTTP (not HTTPS): {action[:100]} — "
                        f"credentials/data leak in transit"
                    ))
                elif self._is_external_url(action):
                    findings.append(Finding(
                        "form_action_hijack", "MEDIUM", fp, i,
                        line.strip()[:200],
                        f"Form submits to external domain: {action[:100]}"
                    ))

        # formaction attribute on buttons/inputs (overrides form action)
        formaction_pattern = re.compile(
            r'<(?:button|input)[^>]+formaction\s*=\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            match = formaction_pattern.search(line)
            if match:
                action = match.group(1)
                findings.append(Finding(
                    "form_action_hijack", "MEDIUM", fp, i,
                    line.strip()[:200],
                    f"formaction attribute can override form destination: {action[:100]}"
                ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST: Dangling Markup / Unclosed Attributes
    # ------------------------------------------------------------------ #
    def _test_dangling_markup(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect patterns that could enable dangling markup injection:
        1. Unclosed attribute quotes after user-controllable contexts
        2. <img src= or <a href= without closing quote
        3. Tags with attribute values that span multiple lines suspiciously

        Dangling markup captures everything after an injection point until
        the browser finds a matching quote, potentially including tokens,
        CSRF values, and other secrets.
        """
        findings = []

        # Pattern: tags with attributes that have unmatched quotes
        # This is heuristic — we look for common injection points
        dangling_patterns = [
            # img/script/link with src/href ending in = without closing quote
            (r'<(?:img|script|link|iframe|embed|object|video|audio|source)\s+[^>]*'
             r'(?:src|href|action|data|poster)\s*=\s*[\'"][^"\'>\s]*$',
             "HIGH",
             "Potentially unclosed attribute — could capture subsequent page content "
             "(dangling markup injection)"),

            # Any tag with an unclosed style attribute (CSS injection)
            (r'<[a-z]+[^>]*style\s*=\s*[\'"][^"\']*$',
             "MEDIUM",
             "Unclosed style attribute — potential CSS injection point"),
        ]

        for i, line in enumerate(lines, 1):
            for pat, sev, desc in dangling_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(Finding(
                        "dangling_markup", sev, fp, i,
                        line.strip()[:200], desc
                    ))

        # Check for javascript: URLs in href/src (XSS vector)
        js_url_pattern = re.compile(
            r'(?:href|src|action)\s*=\s*[\'"]?\s*javascript\s*:',
            re.IGNORECASE
        )
        for i, line in enumerate(lines, 1):
            if js_url_pattern.search(line):
                findings.append(Finding(
                    "dangling_markup", "CRITICAL", fp, i,
                    line.strip()[:200],
                    "javascript: URL in href/src/action — direct XSS vector"
                ))

        # Check for data: URLs in script/iframe src
        data_url_pattern = re.compile(
            r'<(?:script|iframe)[^>]+src\s*=\s*[\'"]?\s*data\s*:',
            re.IGNORECASE
        )
        for i, line in enumerate(lines, 1):
            if data_url_pattern.search(line):
                findings.append(Finding(
                    "dangling_markup", "HIGH", fp, i,
                    line.strip()[:200],
                    "data: URL in script/iframe src — potential XSS via base64 encoded content"
                ))

        return findings

    # ------------------------------------------------------------------ #
    # INLINE <script> → JS Scanner Delegation
    # ------------------------------------------------------------------ #
    def _scan_inline_scripts(self, fp: str, content: str) -> List[Finding]:
        """
        Extract all inline <script> blocks and run the JS scanner on each.
        Findings are annotated with [INLINE] and the correct line number
        offset from the HTML file.
        """
        findings = []

        try:
            extractor = InlineExtractor()
            extractor.feed(content)
        except Exception as e:
            return []

        if not extractor.scripts:
            return findings

        js_scanner = self._get_js_scanner()

        for block_start_line, script_code in extractor.scripts:
            # Skip tiny scripts (tracking pixels, empty blocks)
            if len(script_code.strip()) < 20:
                continue

            # Run JS scanner on the inline code
            script_lines = script_code.split("\n")
            raw_findings = []
            raw_findings.extend(js_scanner._test_prototype_pollution(fp, script_lines))
            raw_findings.extend(js_scanner._test_open_redirect(fp, script_lines))
            raw_findings.extend(js_scanner._test_high_risk_apis(fp, script_lines))
            raw_findings.extend(js_scanner._test_dangerous_sinks(fp, script_lines))
            raw_findings.extend(js_scanner._test_jsonp_callback(fp, script_lines))
            raw_findings.extend(js_scanner._test_redos(fp, script_lines, script_code))
            raw_findings.extend(js_scanner._test_service_worker(fp, script_lines))
            raw_findings.extend(js_scanner._test_cryptominer(fp, script_lines, script_code))
            raw_findings.extend(js_scanner._test_postmessage(fp, script_lines, script_code))
            raw_findings.extend(js_scanner._test_dom_clobbering(fp, script_lines))

            # Adjust line numbers and annotate
            for f in raw_findings:
                adjusted_line = f.line_number + block_start_line - 1 if f.line_number > 0 else 0
                findings.append(Finding(
                    test_name=f.test_name,
                    severity=f.severity,
                    file_path=fp,
                    line_number=adjusted_line,
                    line_content=f.line_content,
                    description=f"[INLINE SCRIPT line {block_start_line}] {f.description}",
                ))

        return findings

    # ------------------------------------------------------------------ #
    # INLINE <style> → CSS Scanner Delegation
    # ------------------------------------------------------------------ #
    def _scan_inline_styles(self, fp: str, content: str) -> List[Finding]:
        """
        Extract all inline <style> blocks and run the CSS scanner on each.
        """
        findings = []

        try:
            extractor = InlineExtractor()
            extractor.feed(content)
        except Exception as e:
            return []

        if not extractor.styles:
            return findings

        css_scanner = self._get_css_scanner()

        for block_start_line, style_code in extractor.styles:
            if len(style_code.strip()) < 20:
                continue

            style_lines = style_code.split("\n")
            raw_findings = []
            raw_findings.extend(css_scanner._test_attribute_selector_exfil(fp, style_lines, style_code))
            raw_findings.extend(css_scanner._test_import_chain(fp, style_lines, style_code))
            raw_findings.extend(css_scanner._test_font_ligature_keylog(fp, style_lines, style_code))

            for f in raw_findings:
                adjusted_line = f.line_number + block_start_line - 1 if f.line_number > 0 else 0
                findings.append(Finding(
                    test_name=f.test_name,
                    severity=f.severity,
                    file_path=fp,
                    line_number=adjusted_line,
                    line_content=f.line_content,
                    description=f"[INLINE STYLE line {block_start_line}] {f.description}",
                ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST: DOM Clobbering (HTML_SINK + CHAIN)
    # Sources:
    #   Liu et al., "The DOMino Effect: Detecting and Exploiting DOM Clobbering
    #   Gadgets via Concolic Execution with Symbolic DOM,"
    #   USENIX Security 2025. (497 exploitable gadgets on Tranco Top 5,000;
    #   19 CVEs; zero-days in Google API client, Webpack, Canvas LMS)
    #
    #   Lekies, Jonker & Johns, "DOM Clobbering Strikes Back,"
    #   USENIX Security 2021.
    #
    #   Khodayari & Pellegrino, "It's (DOM) Clobbering Time: Attack Techniques,
    #   Prevalence, and Defenses," IEEE S&P 2023.
    # ------------------------------------------------------------------ #

    # Sensitive global names whose clobbering has security impact.
    # Browser-defined globals, document collection properties (Liu et al. 2025),
    # and common security-sensitive application globals.
    _DC_SENSITIVE = {
        'name', 'status', 'location', 'origin', 'parent', 'top',
        'self', 'frames', 'opener',
        # Document collection properties (Liu et al. 2025 §2.1)
        'scripts', 'forms', 'images', 'links', 'anchors',
        # Security-sensitive application globals
        'config', 'settings', 'options', 'params', 'userData',
        'auth', 'token', 'csrfToken', 'csrf', 'nonce', 'session',
        'isAdmin', 'admin', 'role', 'permissions', 'security', 'policy',
        'app', 'state', 'env', 'debug', 'trusted', 'safe',
        'isLoggedIn', 'isAuthenticated', 'userRole', 'initialized', 'enabled',
    }

    def _test_dom_clobbering(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect DOM clobbering opportunities in HTML:

        HTML_SINK — Named/ID'd elements whose attribute value matches a
          security-sensitive global. These shadow window.X or document.X,
          supplying DOM nodes where application JS expects a security value.
          Elements: form, input, img, a, object, embed, iframe (Lekies et al.
          2021 Table 1 namespace promotion rules).

        CHAIN — HTML_SINK element name also appears in inline JS accessing that
          same global in the same document. Highest-confidence signal; no
          injection required — the collision already exists in the page.

        Two-level — <form id="x"><input name="y"> pattern enabling property
          forgery as x.y in JS, beyond simple window.X shadowing
          (Lekies et al. 2021 §3).
        """
        findings = []
        seen = set()
        sensitive = self._DC_SENSITIVE

        def add(severity, ln, line_text, desc, pat_id):
            key = (pat_id, ln)
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    "dom_clobbering", severity, fp,
                    ln, line_text.strip()[:200], desc
                ))

        # Build alternation for name regex
        _names_alt = '|'.join(
            re.escape(n) for n in sorted(sensitive, key=len, reverse=True)
        )

        # ── HTML_SINK: clobberable elements with sensitive name/id ──────
        elem_pat = re.compile(
            r'<(form|input|img|a|object|embed|iframe)\b[^>]*?'
            r'(?:name|id)\s*=\s*["\'](' + _names_alt + r')["\']',
            re.IGNORECASE
        )

        clobbered_names = set()
        for m in elem_pat.finditer(content):
            tag = m.group(1).lower()
            name = m.group(2)
            ln = content[:m.start()].count('\n') + 1
            clobbered_names.add(name)
            line_text = lines[ln - 1] if ln <= len(lines) else m.group()

            # <iframe name="scripts"> is Liu et al. 2025 motivating exploit path
            if tag == 'iframe' and name in ('scripts', 'forms', 'links', 'images', 'anchors'):
                severity = "CRITICAL"
                desc = (
                    f'<iframe name="{name}"> shadows document.{name} — attacker can '
                    f'replace the real script/element collection with an injected DOM '
                    f'node, enabling XSS via library gadget chains '
                    f'(Liu et al. USENIX Security 2025 §2.1 motivating example)'
                )
            else:
                severity = "HIGH"
                desc = (
                    f'<{tag} name/id="{name}"> shadows window.{name} or '
                    f'document.{name} — JS code reading this global receives a DOM '
                    f'element instead of the expected security-sensitive value '
                    f'(Lekies et al. USENIX Security 2021, Khodayari & Pellegrino '
                    f'IEEE S&P 2023)'
                )

            add(severity, ln, line_text, desc, f"html_sink_{tag}_{name}")

        # ── CHAIN: HTML_SINK name also accessed in inline script ────────
        if clobbered_names:
            _chain_alt = '|'.join(
                re.escape(n) for n in sorted(clobbered_names, key=len, reverse=True)
            )
            js_access_re = re.compile(
                r'\b(?:window\s*\.\s*|document\s*\.\s*)?(' + _chain_alt + r')\b'
            )
            script_block_re = re.compile(
                r'<script\b[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL
            )
            chain_reported = set()
            for block in script_block_re.finditer(content):
                script_text = block.group(1)
                for jm in js_access_re.finditer(script_text):
                    accessed = jm.group(1)
                    if accessed in clobbered_names and accessed not in chain_reported:
                        chain_reported.add(accessed)
                        ln = content[:block.start()].count('\n') + 1
                        add("CRITICAL", ln,
                            f'CHAIN: <*name/id="{accessed}"> + JS access of {accessed}',
                            f'DOM clobbering chain: named element "{accessed}" already '
                            f'exists in this HTML page and the same name is accessed as '
                            f'a global in inline JS — no injection required, collision '
                            f'already present (Liu et al. USENIX Security 2025)',
                            f"chain_{accessed}")

        # ── Two-level: <form id="x"><input name="y"> ────────────────────
        two_level_re = re.compile(
            r'<form\b[^>]*id\s*=\s*["\'](\w+)["\'][^>]*>.*?'
            r'<input\b[^>]*name\s*=\s*["\'](\w+)["\']',
            re.IGNORECASE | re.DOTALL
        )
        for m in two_level_re.finditer(content):
            form_id = m.group(1)
            input_name = m.group(2)
            ln = content[:m.start()].count('\n') + 1
            line_text = lines[ln - 1] if ln <= len(lines) else m.group()[:200]
            add("HIGH", ln, line_text,
                f'Two-level DOM clobbering: <form id="{form_id}"><input name="{input_name}"> '
                f'— allows property forgery as {form_id}.{input_name} in JS, enabling '
                f'precise clobbering of nested object properties '
                f'(Lekies et al. USENIX Security 2021 §3)',
                f"two_level_{form_id}_{input_name}")

        return findings

    # ------------------------------------------------------------------ #
    # Helper
    # ------------------------------------------------------------------ #
    @staticmethod
    def _is_external_url(url: str) -> bool:
        """Check if a URL is external (different origin)."""
        url = url.strip()
        if url.startswith("//"):
            return True
        if url.startswith("http://") or url.startswith("https://"):
            return True
        return False
