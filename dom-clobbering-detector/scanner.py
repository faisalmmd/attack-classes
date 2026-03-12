"""
Core scanning logic for DOM clobbering vulnerability detection.

Two complementary scans run on each HTML file:

  1. HTML element scan (HTML_SINK) - finds named/id'd elements whose attribute
     value matches a security-sensitive global name from the SENSITIVE_NAMES set.

  2. Inline script scan (JS_RELIANCE) - finds JavaScript patterns that access
     globals in ways that are susceptible to clobbering.

When a named element and a matching global access appear in the same HTML
document, a CHAIN finding is generated. This is the highest-confidence DOM
clobbering signal available without dynamic execution.

Standalone JS files are scanned for JS_RELIANCE patterns only. We cannot
know which HTML document loaded them, so no cross-referencing is possible.

Important: The CHAIN finding represents the element collision case where the
injected HTML element is already present in the same page as the vulnerable
JS code. For the injection scenario (attacker-supplied HTML via stored XSS or
a CMS input field), any page that reads named element properties is a candidate
even if no CHAIN finding fires.
"""

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Set, Tuple

from bs4 import BeautifulSoup

from patterns import (
    COMPILED_JS_PATTERNS, SENSITIVE_NAMES, CLOBBERABLE_ELEMENTS, SEVERITY_ORDER,
)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ClobberingFinding:
    country: str
    domain: str
    year: str
    timestamp: str
    source_file: str
    source_type: str    # 'html_element' | 'inline_script' | 'js_file' | 'chain'

    category: str       # HTML_SINK | JS_RELIANCE | CHAIN | DEFENSIVE
    severity: str
    pattern_id: str
    pattern_label: str

    clobbered_name: str  # the sensitive name in the element or global access
    element_tag: str     # HTML tag name for HTML_SINK findings, else ''
    line_number: int
    context: str
    match_preview: str

    def to_dict(self) -> dict:
        return asdict(self)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_provenance(path: Path) -> Tuple[str, str, str, str]:
    parts = path.parts
    country, domain = 'UNKNOWN', path.parent.name
    for i, part in enumerate(parts):
        if len(part) == 2 and part.isupper():
            country = part
            if i + 1 < len(parts):
                domain = parts[i + 1]
            break
    name = path.stem
    tokens = name.split('_')
    year = tokens[0] if tokens and tokens[0].isdigit() and len(tokens[0]) == 4 else 'UNKNOWN'
    ts_match = re.search(r'(\d{14})', name)
    timestamp = ts_match.group(1) if ts_match else 'UNKNOWN'
    return country, domain, year, timestamp


def _snippet(text: str, match_start: int, window: int = 120) -> str:
    start = max(0, match_start - window // 2)
    end = min(len(text), match_start + window)
    return text[start:end].replace('\n', ' ').replace('\r', '').strip()[:250]


def _char_to_line(text: str, pos: int) -> int:
    return text[:pos].count('\n') + 1


# Names pattern for extracting which sensitive name a JS match references
_SENSITIVE_NAMES_RE = re.compile(
    r'\b(' + '|'.join(re.escape(n) for n in sorted(SENSITIVE_NAMES, key=len, reverse=True)) + r')\b'
)


def _scan_js_text(
    text: str,
    provenance: Tuple,
    source_file: str,
    source_type: str,
) -> List[ClobberingFinding]:
    """Scan a JS code block for clobbering-susceptible global access patterns."""
    country, domain, year, timestamp = provenance
    findings: List[ClobberingFinding] = []
    seen = set()

    newline_positions = [i for i, c in enumerate(text) if c == '\n']

    def char_to_line(pos: int) -> int:
        lo, hi = 0, len(newline_positions)
        while lo < hi:
            mid = (lo + hi) // 2
            if newline_positions[mid] < pos:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1

    for pattern, compiled in COMPILED_JS_PATTERNS:
        for match in compiled.finditer(text):
            lineno = char_to_line(match.start())
            key = (pattern.id, lineno)
            if key in seen:
                continue
            seen.add(key)

            # Extract the sensitive name from the match text if identifiable
            name_match = _SENSITIVE_NAMES_RE.search(match.group())
            clobbered_name = name_match.group(1) if name_match else ''

            findings.append(ClobberingFinding(
                country=country,
                domain=domain,
                year=year,
                timestamp=timestamp,
                source_file=source_file,
                source_type=source_type,
                category=pattern.category,
                severity=pattern.severity,
                pattern_id=pattern.id,
                pattern_label=pattern.label,
                clobbered_name=clobbered_name,
                element_tag='',
                line_number=lineno,
                context=_snippet(text, match.start()),
                match_preview=match.group()[:80].replace('\n', ' '),
            ))

    return findings


# ── Wayback preamble stripping ────────────────────────────────────────────────

_WB_NOISE = re.compile(r'_____WB\$wombat|self\._wb_wombat|__WB_pmw', re.IGNORECASE)


def _strip_wayback_preamble(text: str) -> str:
    lines = text.split('\n')
    in_preamble = True
    clean = []
    for i, line in enumerate(lines):
        if in_preamble and _WB_NOISE.search(line):
            continue
        if in_preamble and i > 25:
            in_preamble = False
        clean.append(line)
    return '\n'.join(clean)


# ── HTML element extraction ───────────────────────────────────────────────────

def _extract_clobberable_elements(soup: BeautifulSoup) -> List[Tuple[str, str, str]]:
    """
    Find HTML elements whose id or name attribute is a sensitive global name.
    Returns list of (tag_name, attribute_name, name_value).

    Covers the namespace promotion rules from Lekies et al. 2021:
      - Any element with id -> accessible as window[id] in all major browsers
      - form, img, a, object, embed, input with name -> accessible as document[name]
        and sometimes window[name]
    """
    results = []
    for tag in soup.find_all(True):
        tag_name = (tag.name or '').lower()

        name_val = (tag.get('name') or '').strip()
        if name_val and name_val in SENSITIVE_NAMES:
            results.append((tag_name, 'name', name_val))

        id_val = (tag.get('id') or '').strip()
        if id_val and id_val in SENSITIVE_NAMES:
            results.append((tag_name, 'id', id_val))

    return results


# ── Public API ────────────────────────────────────────────────────────────────

def scan_js_file(path: Path) -> List[ClobberingFinding]:
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    text = _strip_wayback_preamble(text)
    provenance = _extract_provenance(path)
    return _scan_js_text(text, provenance, path.name, 'js_file')


def scan_html_file(path: Path) -> List[ClobberingFinding]:
    try:
        html = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []

    provenance = _extract_provenance(path)
    country, domain, year, timestamp = provenance
    findings: List[ClobberingFinding] = []

    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return []

    # 1. Find HTML elements that could clobber sensitive globals
    clobberable = _extract_clobberable_elements(soup)
    clobbered_names_in_page: Set[str] = set()

    for tag_name, attr, name_val in clobberable:
        clobbered_names_in_page.add(name_val)

        # Locate the element in the raw HTML for accurate line numbers
        search_dq = f'{attr}="{name_val}"'
        search_sq = f"{attr}='{name_val}'"
        pos = html.find(search_dq)
        if pos == -1:
            pos = html.find(search_sq)
        lineno = _char_to_line(html, pos) if pos != -1 else 0

        context_str = f'<{tag_name} {attr}="{name_val}">'
        findings.append(ClobberingFinding(
            country=country,
            domain=domain,
            year=year,
            timestamp=timestamp,
            source_file=path.name,
            source_type='html_element',
            category='HTML_SINK',
            severity='HIGH',
            pattern_id='named_element_sensitive',
            pattern_label='Named/ID Element with Sensitive Global Name',
            clobbered_name=name_val,
            element_tag=tag_name,
            line_number=lineno,
            context=context_str,
            match_preview=context_str[:80],
        ))

    # 2. Scan inline scripts for JS_RELIANCE and DEFENSIVE patterns
    inline_findings: List[ClobberingFinding] = []
    for idx, tag in enumerate(soup.find_all('script'), start=1):
        if tag.get('src'):
            continue
        content = tag.string or ''
        if not content.strip():
            continue
        if 'archive.org' in content[:200]:
            continue
        label = f'{path.name}::inline_{idx}'
        inline_findings.extend(_scan_js_text(content, provenance, label, 'inline_script'))

    findings.extend(inline_findings)

    # 3. Generate CHAIN findings when a named element and a matching global access
    #    appear in the same HTML document - this is the collision scenario.
    if clobbered_names_in_page and inline_findings:
        js_names_accessed = {
            f.clobbered_name for f in inline_findings
            if f.clobbered_name and f.category == 'JS_RELIANCE'
        }
        chained_names = clobbered_names_in_page & js_names_accessed

        for name in sorted(chained_names):
            html_ex = next((f for f in findings
                            if f.category == 'HTML_SINK' and f.clobbered_name == name), None)
            js_ex = next((f for f in inline_findings
                          if f.clobbered_name == name and f.category == 'JS_RELIANCE'), None)
            if html_ex and js_ex:
                findings.append(ClobberingFinding(
                    country=country,
                    domain=domain,
                    year=year,
                    timestamp=timestamp,
                    source_file=path.name,
                    source_type='chain',
                    category='CHAIN',
                    severity='CRITICAL',
                    pattern_id='html_js_name_chain',
                    pattern_label='DOM Clobbering Chain: Named Element + Global Access',
                    clobbered_name=name,
                    element_tag=html_ex.element_tag,
                    line_number=html_ex.line_number,
                    context=(
                        f'HTML: <{html_ex.element_tag} name/id="{name}"> | '
                        f'JS: {js_ex.match_preview}'
                    ),
                    match_preview=f'chain:{name}',
                ))

    return findings
