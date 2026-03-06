"""
Core scanning logic for the JS secrets scanner.

Two entry points:
  scan_js_file()    — scan a standalone .js file
  scan_html_file()  — extract inline <script> blocks and scan each one

Both return lists of Finding objects that the main CLI collects for output.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup

from patterns import COMPILED_PATTERNS, is_wayback_noise, redact_match


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    # Provenance
    country: str
    domain: str
    year: str
    timestamp: str
    source_file: str        # basename of the file
    source_type: str        # 'js_file' | 'inline_script'

    # Detection result
    pattern_id: str
    pattern_label: str
    severity: str
    line_number: int

    # Safe representation of the match (never the raw secret)
    context: str            # surrounding ~80 chars with the match redacted
    match_preview: str      # first 6 chars + '[redacted]'
    match_length: int

    def to_dict(self) -> dict:
        return {
            'country': self.country,
            'domain': self.domain,
            'year': self.year,
            'timestamp': self.timestamp,
            'source_file': self.source_file,
            'source_type': self.source_type,
            'pattern_id': self.pattern_id,
            'pattern_label': self.pattern_label,
            'severity': self.severity,
            'line_number': self.line_number,
            'context': self.context,
            'match_preview': self.match_preview,
            'match_length': self.match_length,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_provenance(path: Path) -> Tuple[str, str, str, str]:
    """
    Parse country, domain, year, and timestamp out of the standard path/filename
    conventions used in this dataset.

    snapshot_js_data/{COUNTRY}/{domain}/{year}_{timestamp}_script_N.js
    snapshot_data/{COUNTRY}/{domain}/{year}_index_{domain}_{timestamp}.html
    """
    parts = path.parts
    # Walk back from the file to find country and domain in the directory tree
    country = 'UNKNOWN'
    domain = path.parent.name

    for i, part in enumerate(parts):
        # Heuristic: country codes are 2 uppercase letters sitting above domain
        if len(part) == 2 and part.isupper():
            country = part
            if i + 1 < len(parts):
                domain = parts[i + 1]
            break

    name = path.stem  # filename without extension
    tokens = name.split('_')
    year = tokens[0] if tokens and tokens[0].isdigit() and len(tokens[0]) == 4 else 'UNKNOWN'

    # Timestamp: 14-digit YYYYMMDDHHmmss somewhere in the name
    ts_match = re.search(r'(\d{14})', name)
    timestamp = ts_match.group(1) if ts_match else 'UNKNOWN'

    return country, domain, year, timestamp


def _build_context(line: str, match: re.Match, window: int = 80) -> str:
    """
    Return a snippet of the line around the match, with the matched portion
    replaced by a redaction placeholder. Keeps window chars either side.
    """
    start = max(0, match.start() - window // 2)
    end = min(len(line), match.end() + window // 2)
    before = line[start:match.start()]
    after = line[match.end():end]
    redacted = '[REDACTED:{}]'.format(len(match.group()))
    snippet = before + redacted + after
    return snippet.replace('\n', ' ').replace('\r', '').strip()


def _scan_lines(
    lines: List[str],
    provenance: Tuple[str, str, str, str],
    source_file: str,
    source_type: str,
    skip_wayback: bool = True,
) -> List[Finding]:
    """
    Apply all patterns line by line. Returns a list of Finding objects.
    Deduplicates on (pattern_id, line_number) to avoid flooding from minified
    single-line JS files.
    """
    country, domain, year, timestamp = provenance
    findings: List[Finding] = []
    seen: set = set()

    for lineno, line in enumerate(lines, start=1):
        if skip_wayback and is_wayback_noise(line):
            continue

        for pattern, compiled in COMPILED_PATTERNS:
            for match in compiled.finditer(line):
                key = (pattern.id, lineno)
                if key in seen:
                    continue
                seen.add(key)

                raw_match = match.group()
                findings.append(Finding(
                    country=country,
                    domain=domain,
                    year=year,
                    timestamp=timestamp,
                    source_file=source_file,
                    source_type=source_type,
                    pattern_id=pattern.id,
                    pattern_label=pattern.label,
                    severity=pattern.severity,
                    line_number=lineno,
                    context=_build_context(line, match),
                    match_preview=redact_match(raw_match),
                    match_length=len(raw_match),
                ))

    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def scan_js_file(path: Path) -> List[Finding]:
    """Scan a standalone .js file for secrets."""
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []

    lines = text.splitlines()
    provenance = _extract_provenance(path)
    return _scan_lines(lines, provenance, path.name, 'js_file')


def scan_html_file(path: Path) -> List[Finding]:
    """
    Extract all inline <script> blocks from an HTML file and scan each one.
    Blocks served by archive.org infrastructure (toolbar, wombat, etc.) are
    identified by their src attributes and excluded.
    """
    try:
        html = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []

    provenance = _extract_provenance(path)
    findings: List[Finding] = []

    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return []

    for idx, script_tag in enumerate(soup.find_all('script'), start=1):
        # Skip external scripts (they have a src attribute) — those are handled
        # by the tracker mapper. We only want inline code here.
        if script_tag.get('src'):
            continue

        content = script_tag.string or ''
        if not content.strip():
            continue

        # Skip Wayback Machine injected script blocks
        src_hint = script_tag.get('src', '')
        if 'archive.org' in src_hint or 'archive.org' in content[:200]:
            continue

        lines = content.splitlines()
        block_label = f'{path.name}::inline_script_{idx}'
        block_findings = _scan_lines(
            lines, provenance, block_label, 'inline_script'
        )
        findings.extend(block_findings)

    return findings
