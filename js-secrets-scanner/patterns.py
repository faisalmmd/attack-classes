"""
Regex patterns for secret and API key detection in JavaScript files.

Pattern sources:
  - TruffleHog ruleset (github.com/trufflesecurity/trufflehog)
  - Gitleaks default config (github.com/gitleaks/gitleaks)
  - Intruder Research (2025): "Secrets in your Bundle(.js)"
  - Escape.tech: 189M URL scan findings
  - Whispers (Skyscanner) ruleset

Patterns are ordered roughly by severity and specificity. Format-specific
patterns (e.g., AKIA prefix for AWS) come before generic assignment patterns
to give the most accurate label when both would match.
"""

import re
from dataclasses import dataclass


@dataclass
class Pattern:
    id: str
    label: str
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW
    regex: str
    description: str


PATTERNS = [
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    Pattern(
        id='aws_access_key',
        label='AWS Access Key ID',
        severity='CRITICAL',
        regex=r'AKIA[0-9A-Z]{16}',
        description='AWS access key ID. Exposure can lead to full cloud account compromise.',
    ),
    Pattern(
        id='stripe_live_secret',
        label='Stripe Live Secret Key',
        severity='CRITICAL',
        regex=r'sk_live_[0-9a-zA-Z]{24}',
        description='Stripe live-mode secret key. Directly enables payment fraud and refund abuse.',
    ),
    Pattern(
        id='github_token',
        label='GitHub Personal Access Token',
        severity='CRITICAL',
        regex=r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',
        description='GitHub PAT. Grants repository read/write depending on scope.',
    ),
    Pattern(
        id='private_key_header',
        label='Private Key (PEM Block)',
        severity='CRITICAL',
        regex=r'-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        description='PEM-encoded private key embedded in JavaScript source.',
    ),

    # ── HIGH ──────────────────────────────────────────────────────────────────
    Pattern(
        id='google_api_key',
        label='Google API Key',
        severity='HIGH',
        regex=r'AIza[0-9A-Za-z\-_]{35}',
        description=(
            'Google API key (Maps, YouTube, Firebase, Places, etc). '
            'Extremely common in government portals using embedded maps. '
            'Exposure enables quota theft and unexpected billing charges.'
        ),
    ),
    Pattern(
        id='firebase_config',
        label='Firebase Config Block',
        severity='HIGH',
        regex=r'"apiKey"\s*:\s*"(AIza[0-9A-Za-z\-_]{35})"',
        description=(
            'Firebase configuration object containing an API key. '
            'Often left in client-side JS bundles of government self-service portals.'
        ),
    ),
    Pattern(
        id='sendgrid_key',
        label='SendGrid API Key',
        severity='HIGH',
        regex=r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
        description='SendGrid API key. Enables sending email as the account owner.',
    ),
    Pattern(
        id='mailgun_key',
        label='Mailgun API Key',
        severity='HIGH',
        regex=r'\bkey-[0-9a-zA-Z]{32}\b',
        description='Mailgun API key.',
    ),
    Pattern(
        id='basic_auth_url',
        label='Credentials in URL',
        severity='HIGH',
        regex=r'https?://[A-Za-z0-9._~%!$&()*+,;=:\-]+:[A-Za-z0-9._~%!$&()*+,;=:\-]+@[A-Za-z0-9.\-]+',
        description='Username and password embedded in a URL (HTTP Basic Auth format).',
    ),
    Pattern(
        id='hardcoded_password',
        label='Hardcoded Password',
        severity='HIGH',
        regex=r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
        description='Hardcoded password string in code. 8+ char minimum to reduce noise.',
    ),
    Pattern(
        id='mapbox_token',
        label='Mapbox Access Token',
        severity='HIGH',
        regex=r'pk\.eyJ1[A-Za-z0-9_\-\.]{50,}',
        description='Mapbox public access token. Common in government mapping and GIS portals.',
    ),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    Pattern(
        id='stripe_live_pub',
        label='Stripe Live Publishable Key',
        severity='MEDIUM',
        regex=r'pk_live_[0-9a-zA-Z]{24}',
        description='Stripe live-mode publishable key. Identifies the merchant account.',
    ),
    Pattern(
        id='twilio_sid',
        label='Twilio Account SID',
        severity='MEDIUM',
        regex=r'\bAC[a-fA-F0-9]{32}\b',
        description='Twilio Account SID.',
    ),
    Pattern(
        id='jwt_token',
        label='JSON Web Token',
        severity='MEDIUM',
        regex=r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
        description='JWT hardcoded in source. May be a valid long-lived token or signing secret.',
    ),
    Pattern(
        id='generic_api_key',
        label='Generic API Key Assignment',
        severity='MEDIUM',
        regex=r'(?:api[_\-]?key|apikey|api[_\-]?token|app[_\-]?key|app[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
        description='Generic API key/token assignment with a value ≥20 chars.',
    ),
    Pattern(
        id='generic_secret',
        label='Generic Secret Assignment',
        severity='MEDIUM',
        regex=r'(?:secret[_\-]?key|client[_\-]?secret|consumer[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{16,})["\']',
        description='Generic secret key or OAuth client secret assignment.',
    ),

    # ── LOW ───────────────────────────────────────────────────────────────────
    Pattern(
        id='generic_token',
        label='Generic Token Assignment',
        severity='LOW',
        regex=r'(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token|refresh[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-\.]{20,})["\']',
        description='Generic token assignment. Requires manual context to assess real severity.',
    ),
]

# Pre-compiled for scanning performance
COMPILED_PATTERNS = [(p, re.compile(p.regex, re.IGNORECASE)) for p in PATTERNS]

# Lines starting with these strings are injected by the Wayback Machine
# and should be excluded from secret scanning to avoid false positives.
WAYBACK_NOISE_MARKERS = (
    '_____WB$wombat',
    'self._wb_wombat',
    '__WB_pmw',
    'archive_analytics',
    'web-static.archive.org',
    '__wm.rw',
    'window.WB_wombat_',
)


def is_wayback_noise(line: str) -> bool:
    """Return True if the line is injected Wayback Machine infrastructure code."""
    stripped = line.strip()
    return any(stripped.startswith(marker) or marker in stripped[:120]
               for marker in WAYBACK_NOISE_MARKERS)


def redact_match(match_text: str, max_show: int = 6) -> str:
    """Return a partially redacted version of a matched secret for safe logging."""
    if len(match_text) <= max_show:
        return '*' * len(match_text)
    return match_text[:max_show] + '...[redacted]'
