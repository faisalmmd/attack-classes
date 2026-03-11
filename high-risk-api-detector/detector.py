"""
Core detection logic for high-risk browser API usage.

Three scan modes:
  scan_js_file()          - standalone .js files
  scan_html_file()        - inline <script> blocks in HTML
  check_header_policy()   - Permissions-Policy / Feature-Policy header analysis
"""

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup

from apis import COMPILED_API_PATTERNS, HEADER_NAMES, PERMISSIONS_POLICY_FEATURES


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class APIFinding:
    country: str
    domain: str
    year: str
    timestamp: str
    source_file: str
    source_type: str    # 'js_file' | 'inline_script'

    api_id: str
    api_label: str
    category: str
    severity: str
    line_number: int
    context: str        # surrounding line, truncated
    pattern_matched: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HeaderPolicyResult:
    country: str
    domain: str
    year: str
    timestamp: str
    source_file: str

    header_found: bool
    header_name: str        # which header variant was present
    raw_value: str
    features_restricted: List[str]
    features_unrestricted: List[str]   # known sensitive features NOT in the policy
    is_restrictive: bool               # True if policy blocks at least some features

    def to_dict(self) -> dict:
        d = asdict(self)
        d['features_restricted'] = '|'.join(self.features_restricted)
        d['features_unrestricted'] = '|'.join(self.features_unrestricted)
        return d


# ── Shared helpers ────────────────────────────────────────────────────────────

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


def _context_snippet(line: str, max_len: int = 120) -> str:
    return line.strip()[:max_len].replace('\n', ' ').replace('\r', '')


def _scan_text_lines(
    lines: List[str],
    provenance: Tuple,
    source_file: str,
    source_type: str,
) -> List[APIFinding]:
    country, domain, year, timestamp = provenance
    findings: List[APIFinding] = []
    seen = set()

    for lineno, line in enumerate(lines, start=1):
        for cpat in COMPILED_API_PATTERNS:
            for compiled in cpat.compiled:
                m = compiled.search(line)
                if m:
                    key = (cpat.meta.id, lineno)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(APIFinding(
                        country=country,
                        domain=domain,
                        year=year,
                        timestamp=timestamp,
                        source_file=source_file,
                        source_type=source_type,
                        api_id=cpat.meta.id,
                        api_label=cpat.meta.label,
                        category=cpat.meta.category,
                        severity=cpat.meta.severity,
                        line_number=lineno,
                        context=_context_snippet(line),
                        pattern_matched=m.group()[:80],
                    ))
                    break   # one match per API per line is enough

    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def scan_js_file(path: Path) -> List[APIFinding]:
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    provenance = _extract_provenance(path)
    return _scan_text_lines(text.splitlines(), provenance, path.name, 'js_file')


def scan_html_file(path: Path) -> List[APIFinding]:
    try:
        html = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []

    provenance = _extract_provenance(path)
    findings: List[APIFinding] = []

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
        findings.extend(
            _scan_text_lines(content.splitlines(), provenance, label, 'inline_script')
        )

    return findings


def check_header_policy(path: Path, headers: Dict) -> Optional[HeaderPolicyResult]:
    """
    Parse Permissions-Policy or Feature-Policy from a headers dict.
    Returns a HeaderPolicyResult regardless of whether a header was found,
    so we can track absence (no policy) as well as presence and content.
    """
    provenance = _extract_provenance(path)
    country, domain, year, timestamp = provenance

    lowered = {k.lower(): v for k, v in headers.items()}

    raw_value = ''
    header_name = ''
    for h in HEADER_NAMES:
        if h in lowered:
            raw_value = str(lowered[h])
            header_name = h
            break

    header_found = bool(raw_value)
    features_restricted: List[str] = []

    if header_found:
        # Feature-Policy: "geolocation 'none'; camera 'none'"
        # Permissions-Policy: "geolocation=(), camera=()"
        # Extract feature names from both formats
        feat_re = re.compile(
            r'(\b(?:' + '|'.join(re.escape(f) for f in PERMISSIONS_POLICY_FEATURES) + r')\b)',
            re.IGNORECASE,
        )
        for m in feat_re.finditer(raw_value):
            feat = m.group(1).lower()
            if feat not in features_restricted:
                features_restricted.append(feat)

    # Which sensitive features are NOT mentioned in the policy at all?
    sensitive = {'geolocation', 'camera', 'microphone', 'payment',
                 'usb', 'bluetooth', 'clipboard-read', 'display-capture',
                 'serial', 'ambient-light-sensor'}
    features_unrestricted = sorted(sensitive - set(features_restricted))

    return HeaderPolicyResult(
        country=country,
        domain=domain,
        year=year,
        timestamp=timestamp,
        source_file=path.name,
        header_found=header_found,
        header_name=header_name,
        raw_value=raw_value[:300] if raw_value else '',
        features_restricted=features_restricted,
        features_unrestricted=features_unrestricted,
        is_restrictive=len(features_restricted) > 0,
    )
