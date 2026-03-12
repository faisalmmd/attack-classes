"""
Core scanning logic for JavaScript open redirect detection.

Scans standalone JS files and HTML inline scripts for redirect sinks,
user-controllable URL sources, and source-to-sink chains.

Static framing: a CHAIN finding (source expression visible in the same
statement as a sink) is a high-confidence open redirect. SINK-only findings
need cross-referencing with SOURCE findings from the same file to assess
whether user input actually reaches the redirect. DEFENSIVE findings reduce
the risk score for a domain but do not guarantee safety - the validation
logic must be verified to actually reject non-relative or non-trusted URLs.
"""

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Tuple

from bs4 import BeautifulSoup

from patterns import COMPILED_PATTERNS, SEVERITY_ORDER


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class RedirectFinding:
    country: str
    domain: str
    year: str
    timestamp: str
    source_file: str
    source_type: str    # 'js_file' | 'inline_script'

    pattern_id: str
    pattern_label: str
    category: str       # SINK | SOURCE | CHAIN | DEFENSIVE
    severity: str
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


def _scan_text(
    text: str,
    provenance: Tuple,
    source_file: str,
    source_type: str,
) -> List[RedirectFinding]:
    """
    Full-text scan (not line-by-line) so DOTALL patterns work correctly on
    minified single-line code. Builds a line-number index separately.
    """
    country, domain, year, timestamp = provenance
    findings: List[RedirectFinding] = []
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

    for pattern, compiled in COMPILED_PATTERNS:
        for match in compiled.finditer(text):
            lineno = char_to_line(match.start())
            key = (pattern.id, lineno)
            if key in seen:
                continue
            seen.add(key)

            findings.append(RedirectFinding(
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

_WB_NOISE = re.compile(r'_____WB\$wombat|self\._wb_wombat|__WB_pmw', re.IGNORECASE)


def _strip_wayback_preamble(text: str) -> str:
    """Remove the Wayback Machine wombat wrapper injected at the top of JS files."""
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


def scan_js_file(path: Path) -> List[RedirectFinding]:
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    text = _strip_wayback_preamble(text)
    provenance = _extract_provenance(path)
    return _scan_text(text, provenance, path.name, 'js_file')


def scan_html_file(path: Path) -> List[RedirectFinding]:
    try:
        html = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []

    provenance = _extract_provenance(path)
    findings: List[RedirectFinding] = []

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
