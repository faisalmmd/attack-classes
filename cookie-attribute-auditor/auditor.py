"""
Core cookie parsing and security attribute analysis.

Handles Set-Cookie headers from both direct and Wayback Machine wrapped
format (x-archive-orig-set-cookie). Each cookie is assessed against the
three primary security attributes that have been the focus of longitudinal
measurement research: HttpOnly, Secure, and SameSite.

Reference:
  Khodayari & Pellegrino, "The State of the SameSite" (S&P 2022)
  Barth, Jackson & Mitchell, "Robust Defenses for CSRF" (CCS 2008)
"""

import re
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


# Cookie names that look like session or auth tokens — these carry higher risk
# when missing security attributes because losing them to XSS or MITM is severe.
SESSION_NAME_PATTERNS = re.compile(
    r'(?i)(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid|cfid|cftoken'
    r'|session|sess|sid|auth|token|jwt|bearer|login|user_id|userid|uid'
    r'|remember_me|rememberme|persistent|identity|credential)',
    re.IGNORECASE,
)


@dataclass
class CookieRecord:
    """Parsed representation of a single Set-Cookie value."""
    name: str
    value_hash: str         # SHA-1 of the raw value — never log the raw value
    value_length: int

    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None   # 'strict', 'lax', 'none', or None
    domain: Optional[str] = None
    path: Optional[str] = None
    max_age: Optional[int] = None
    has_expires: bool = False

    is_session_like: bool = False

    # Risk flags (populated by assess_risk)
    risks: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['risks'] = '|'.join(self.risks) if self.risks else ''
        return d


def _hash_value(raw: str) -> str:
    return hashlib.sha1(raw.encode('utf-8', errors='replace')).hexdigest()[:12]


def parse_set_cookie(header_value: str) -> Optional[CookieRecord]:
    """
    Parse a single Set-Cookie header string into a CookieRecord.

    Returns None if the header is empty or malformed beyond recovery.
    """
    if not header_value or not header_value.strip():
        return None

    parts = [p.strip() for p in header_value.split(';')]
    if not parts or '=' not in parts[0]:
        # Could be a flag-only cookie, but that's unusual. Skip.
        return None

    # First token is always name=value
    name_part = parts[0]
    eq_idx = name_part.index('=')
    name = name_part[:eq_idx].strip()
    raw_value = name_part[eq_idx + 1:].strip()

    record = CookieRecord(
        name=name,
        value_hash=_hash_value(raw_value),
        value_length=len(raw_value),
        is_session_like=bool(SESSION_NAME_PATTERNS.search(name)),
    )

    for attr in parts[1:]:
        al = attr.lower()
        if al == 'httponly':
            record.httponly = True
        elif al == 'secure':
            record.secure = True
        elif al.startswith('samesite='):
            record.samesite = al.split('=', 1)[1].strip()
        elif al.startswith('domain='):
            record.domain = attr.split('=', 1)[1].strip()
        elif al.startswith('path='):
            record.path = attr.split('=', 1)[1].strip()
        elif al.startswith('max-age='):
            try:
                record.max_age = int(al.split('=', 1)[1].strip())
            except ValueError:
                pass
        elif al.startswith('expires='):
            record.has_expires = True

    assess_risk(record)
    return record


def assess_risk(record: CookieRecord) -> None:
    """
    Populate record.risks with short string identifiers for each weakness.
    These map directly to the dimensions tracked in published cookie security studies.
    """
    risks = []

    if not record.secure:
        risks.append('NO_SECURE')

    if not record.httponly:
        if record.is_session_like:
            risks.append('NO_HTTPONLY_SESSION')
        else:
            risks.append('NO_HTTPONLY')

    if record.samesite is None:
        risks.append('NO_SAMESITE')
    elif record.samesite == 'none':
        if not record.secure:
            # SameSite=None without Secure is invalid per RFC 6265bis and
            # browsers reject it, but the server is still misconfigured.
            risks.append('SAMESITE_NONE_WITHOUT_SECURE')
        else:
            # Deliberate cross-site opt-out — noteworthy but not necessarily wrong
            risks.append('SAMESITE_NONE')

    record.risks = risks


def extract_cookies_from_headers(headers: Dict) -> List[Tuple[str, CookieRecord]]:
    """
    Extract and parse all Set-Cookie entries from a headers dict.

    Handles:
      1. 'x-archive-orig-set-cookie' (Wayback Machine wrapped original headers)
      2. 'Set-Cookie' or 'set-cookie' at the top level (direct capture or
         headers where Wayback didn't strip them)

    Returns a list of (source_key, CookieRecord) tuples.
    """
    results: List[Tuple[str, CookieRecord]] = []

    # Normalise keys to lowercase for lookup
    lowered = {k.lower(): (k, v) for k, v in headers.items()}

    # Priority: original headers first
    for lookup_key in ('x-archive-orig-set-cookie', 'set-cookie'):
        if lookup_key in lowered:
            orig_key, value = lowered[lookup_key]
            candidates = value if isinstance(value, list) else [value]
            for raw in candidates:
                rec = parse_set_cookie(str(raw))
                if rec:
                    results.append((lookup_key, rec))
            # Don't double-count if both keys exist and one is the archive wrap
            if results:
                break

    return results


def risk_summary(records: List[CookieRecord]) -> Dict[str, int]:
    """Aggregate risk flag counts across a list of cookie records."""
    counts: Dict[str, int] = {}
    for rec in records:
        for risk in rec.risks:
            counts[risk] = counts.get(risk, 0) + 1
    return counts
