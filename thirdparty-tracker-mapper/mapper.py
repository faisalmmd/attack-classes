"""
Core HTML parsing and third-party script classification logic.

Handles the Wayback Machine's URL rewriting: when a page is archived without
the id_ flag, all resource URLs are rewritten to web.archive.org/web/{ts}/...
We unwrap these to get the original third-party domain for classification.

Reference methodology:
  Nikiforakis et al., "You Are What You Include" (CCS 2012)
  Lerner et al., "Internet Jones and the Raiders of the Lost Trackers" (USENIX 2016)
  — the Lerner paper literally used the Wayback Machine on a similar longitudinal dataset.
"""

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tracker_lists import (
    TRACKER_DOMAINS,
    CDN_DOMAINS,
    INLINE_TRACKER_PATTERNS,
    WAYBACK_DOMAINS,
)

# Compiled inline patterns once
_COMPILED_INLINE = [(re.compile(p, re.IGNORECASE), name)
                    for p, name in INLINE_TRACKER_PATTERNS]

# Wayback URL unwrapper — extracts original URL from archived form
_WB_URL_RE = re.compile(
    r'https?://web\.archive\.org/web/\d{8,14}[a-z_]*/(.+)',
    re.IGNORECASE,
)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ScriptInclusion:
    country: str
    domain: str
    year: str
    timestamp: str
    source_file: str

    raw_src: str            # src attribute as found in HTML
    resolved_url: str       # after unwrapping Wayback rewriting
    script_domain: str      # hostname of the script URL
    protocol: str           # 'https', 'http', 'protocol_relative', 'relative', 'other'

    is_third_party: bool
    is_cdn: bool
    is_tracker: bool
    tracker_category: Optional[str]     # ANALYTICS, ADVERTISING, SOCIAL, etc.
    tracker_name: Optional[str]

    has_integrity: bool     # SRI integrity attribute present
    crossorigin: Optional[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InlineTracker:
    country: str
    domain: str
    year: str
    timestamp: str
    source_file: str
    tracker_name: str
    pattern: str
    line_number: int

    def to_dict(self) -> dict:
        return asdict(self)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_provenance(path: Path) -> Tuple[str, str, str, str]:
    parts = path.parts
    country = 'UNKNOWN'
    domain = path.parent.name

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


def _page_domain_from_filename(filename: str) -> str:
    """
    Derive the page's own domain from the snapshot filename.
    Filenames follow: {year}_index_{domain_with_underscores}_{timestamp}.html
    Domain underscores are ambiguous with path separators, but the convention
    in this dataset is that the directory name IS the domain with underscores.
    """
    # The parent directory name is the domain (underscores instead of dots)
    # e.g. snapshot_data/AE/chatbot_moccae_gov_ae/
    return ''   # Caller passes the directory name directly


def _unwrap_wayback(url: str) -> str:
    """Strip the web.archive.org/web/{timestamp}/ wrapper if present."""
    m = _WB_URL_RE.match(url)
    if m:
        inner = m.group(1)
        # Ensure it has a scheme
        if inner.startswith('//'):
            inner = 'https:' + inner
        return inner
    return url


def _extract_domain(url: str) -> str:
    """Return the hostname from a URL, or empty string on failure."""
    try:
        return urlparse(url).hostname or ''
    except Exception:
        return ''


def _protocol_of(url: str) -> str:
    if url.startswith('//'):
        return 'protocol_relative'
    if url.startswith('https://'):
        return 'https'
    if url.startswith('http://'):
        return 'http'
    if url.startswith('/') or (url and not url.startswith('http')):
        return 'relative'
    return 'other'


def _classify_domain(script_domain: str, page_domain: str):
    """
    Returns (is_third_party, is_cdn, is_tracker, tracker_category, tracker_name).
    """
    if not script_domain:
        return False, False, False, None, None

    # Wayback infrastructure is neither tracker nor third-party in our study
    for wb_d in WAYBACK_DOMAINS:
        if script_domain == wb_d or script_domain.endswith('.' + wb_d):
            return False, False, False, None, None

    # First-party check: same domain or subdomain of page
    page_root = page_domain.replace('_', '.')
    is_third_party = (
        script_domain != page_root
        and not script_domain.endswith('.' + page_root)
        and not page_root.endswith('.' + script_domain)
    )

    # CDN check
    is_cdn = any(
        script_domain == cdn or script_domain.endswith('.' + cdn)
        for cdn in CDN_DOMAINS
    )

    # Tracker check — longest-suffix match wins
    is_tracker = False
    tracker_category = None
    tracker_name = None
    best_match_len = 0

    for tracker_domain, (category, name) in TRACKER_DOMAINS.items():
        if (script_domain == tracker_domain
                or script_domain.endswith('.' + tracker_domain)):
            if len(tracker_domain) > best_match_len:
                best_match_len = len(tracker_domain)
                is_tracker = True
                tracker_category = category
                tracker_name = name

    return is_third_party, is_cdn, is_tracker, tracker_category, tracker_name


# ── Public API ────────────────────────────────────────────────────────────────

def scan_html_file(path: Path) -> Tuple[List[ScriptInclusion], List[InlineTracker]]:
    """
    Parse an HTML snapshot and return:
      - list of ScriptInclusion for every <script src="..."> tag
      - list of InlineTracker for every inline tracker API call detected
    """
    try:
        html = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return [], []

    provenance = _extract_provenance(path)
    country, domain, year, timestamp = provenance

    # The directory name is the domain (underscores as in the dataset)
    page_domain_raw = path.parent.name  # e.g. 'chatbot_moccae_gov_ae'
    page_domain = page_domain_raw.replace('_', '.')

    inclusions: List[ScriptInclusion] = []
    inline_trackers: List[InlineTracker] = []

    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return [], []

    # ── Script inclusions ────────────────────────────────────────────────────
    for tag in soup.find_all('script'):
        raw_src = tag.get('src', '').strip()
        if not raw_src:
            continue

        # Resolve protocol-relative and unwrap Wayback
        if raw_src.startswith('//'):
            raw_src_resolved = 'https:' + raw_src
        else:
            raw_src_resolved = raw_src

        resolved = _unwrap_wayback(raw_src_resolved)
        script_domain = _extract_domain(resolved)

        (is_third_party, is_cdn, is_tracker,
         tracker_category, tracker_name) = _classify_domain(script_domain, page_domain_raw)

        inclusions.append(ScriptInclusion(
            country=country,
            domain=domain,
            year=year,
            timestamp=timestamp,
            source_file=path.name,
            raw_src=raw_src,
            resolved_url=resolved,
            script_domain=script_domain,
            protocol=_protocol_of(raw_src),
            is_third_party=is_third_party,
            is_cdn=is_cdn,
            is_tracker=is_tracker,
            tracker_category=tracker_category,
            tracker_name=tracker_name,
            has_integrity=bool(tag.get('integrity')),
            crossorigin=tag.get('crossorigin'),
        ))

    # ── Inline tracker calls ─────────────────────────────────────────────────
    for idx, tag in enumerate(soup.find_all('script'), start=1):
        if tag.get('src'):
            continue
        content = tag.string or ''
        if not content.strip():
            continue

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for compiled_pat, tracker_name in _COMPILED_INLINE:
                if compiled_pat.search(line):
                    inline_trackers.append(InlineTracker(
                        country=country,
                        domain=domain,
                        year=year,
                        timestamp=timestamp,
                        source_file=path.name,
                        tracker_name=tracker_name,
                        pattern=compiled_pat.pattern,
                        line_number=lineno,
                    ))
                    break   # one tracker match per line is enough

    return inclusions, inline_trackers
