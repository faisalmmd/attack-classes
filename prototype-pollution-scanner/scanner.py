"""
Core scanning logic for prototype pollution pattern detection.

Scans standalone JS files and HTML inline scripts. Because JavaScript
can be minified to a single line, both line-by-line and character-window
approaches are used depending on line length.

Important framing: this is static pattern detection, not taint tracking.
A VULNERABLE pattern finding means "this code structure is dangerous if
user-controlled input reaches it." Whether that happens requires manual
review or dynamic testing. The DEFENSIVE pattern findings are equally
important - they show when a codebase is prototype-aware.
"""

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Tuple

from bs4 import BeautifulSoup

from patterns import COMPILED_PATTERNS, SEVERITY_ORDER


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class PollutionFinding:
    country: str
    domain: str
    year: str
    timestamp: str
    source_file: str
    source_type: str    # 'js_file' | 'inline_script'

    pattern_id: str
    pattern_label: str
    category: str       # VULNERABLE | INDICATOR | DEFENSIVE
    severity: str
    line_number: int
    context: str        # snippet around match, truncated
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


def _snippet(text: str, match_start: int, window: int = 100) -> str:
    start = max(0, match_start - window // 2)
    end = min(len(text), match_start + window)
    return text[start:end].replace('\n', ' ').replace('\r', '').strip()[:200]


def _scan_text(
    text: str,
    provenance: Tuple,
    source_file: str,
    source_type: str,
) -> List[PollutionFinding]:
    """
    Scan a string of JS code for all pollution patterns.
    Operates on the full text (not line-by-line) so that DOTALL patterns
    work correctly on minified single-line code.
    """
    country, domain, year, timestamp = provenance
    findings: List[PollutionFinding] = []
    seen = set()

    # Build a line-number index so we can report meaningful line numbers
    # even when the full-text regex scan doesn't track lines itself.
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

    for pattern, compiled in COMPILED_PATTERNS:
        for match in compiled.finditer(text):
            # For high-volume patterns (forin_no_hasown), cap per-file findings
            # to avoid flooding results with every for-in loop in minified libs.
            file_key = (pattern.id, source_file)
            if pattern.id == 'forin_no_hasown':
                existing = sum(1 for f in findings if f.pattern_id == 'forin_no_hasown')
                if existing >= 10:
                    # Record count but stop individual findings
                    break

            lineno = char_to_line(match.start())
            key = (pattern.id, lineno)
            if key in seen:
                continue
            seen.add(key)

            findings.append(PollutionFinding(
                country=country,
                domain=domain,
                year=year,
                timestamp=timestamp,
                source_file=source_file,
                source_type=source_type,
                pattern_id=pattern.id,
                pattern_label=pattern.label,
                category=pattern.category,
                severity=pattern.severity,
                line_number=lineno,
                context=_snippet(text, match.start()),
                match_preview=match.group()[:80].replace('\n', ' '),
            ))

    return findings


# ── Public API ────────────────────────────────────────────────────────────────

# Lines containing Wayback Machine infrastructure - skip these
_WB_NOISE = re.compile(r'_____WB\$wombat|self\._wb_wombat|__WB_pmw', re.IGNORECASE)


def _strip_wayback_preamble(text: str) -> str:
    """Remove the WB wombat wrapper from JS files before scanning."""
    lines = text.split('\n')
    # The preamble ends when we stop seeing wombat-specific lines
    # (typically first 15-20 lines). Find the first non-wombat line
    # after the preamble block.
    in_preamble = True
    clean = []
    for i, line in enumerate(lines):
        if in_preamble and _WB_NOISE.search(line):
            continue
        if in_preamble and i > 25:
            in_preamble = False
        clean.append(line)
    return '\n'.join(clean)


def scan_js_file(path: Path) -> List[PollutionFinding]:
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []

    text = _strip_wayback_preamble(text)
    provenance = _extract_provenance(path)
    return _scan_text(text, provenance, path.name, 'js_file')


def scan_html_file(path: Path) -> List[PollutionFinding]:
    try:
        html = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []

    provenance = _extract_provenance(path)
    findings: List[PollutionFinding] = []

    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return []

    for idx, tag in enumerate(soup.find_all('script'), start=1):
        if tag.get('src'):
            continue
        content = tag.string or ''
        if not content.strip():
            continue
        if 'archive.org' in content[:200]:
            continue
        label = f'{path.name}::inline_{idx}'
        findings.extend(_scan_text(content, provenance, label, 'inline_script'))

    return findings
