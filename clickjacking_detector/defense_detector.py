"""
Defense Detector Module for Clickjacking Analysis

Detects clickjacking defense mechanisms including:
- X-Frame-Options HTTP header
- Content-Security-Policy frame-ancestors directive
- Frame-busting JavaScript code
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from bs4 import BeautifulSoup


@dataclass
class DefenseResult:
    """Results of defense mechanism detection."""
    has_xframe_options: bool = False
    xframe_options_value: Optional[str] = None
    has_csp_frame_ancestors: bool = False
    csp_frame_ancestors_value: Optional[str] = None
    has_framebusting_js: bool = False
    framebusting_patterns_found: List[str] = field(default_factory=list)
    framebusting_code_snippets: List[str] = field(default_factory=list)
    defense_score: int = 0  # 0-10, higher is better protected
    defense_level: str = "none"  # none, weak, moderate, strong


# Frame-busting JavaScript patterns
# Based on ASIACCS 2010 paper and common patterns
FRAMEBUSTING_PATTERNS = [
    # Top/self comparison patterns
    (r'if\s*\(\s*top\s*[!=]=\s*self\s*\)', 'top != self check'),
    (r'if\s*\(\s*self\s*[!=]=\s*top\s*\)', 'self != top check'),
    (r'if\s*\(\s*top\s*!==\s*self\s*\)', 'top !== self strict check'),
    (r'if\s*\(\s*window\.top\s*[!=]=\s*window\.self\s*\)', 'window.top != window.self check'),
    (r'if\s*\(\s*window\.top\s*!==\s*window\.self\s*\)', 'window.top !== window.self strict check'),
    (r'if\s*\(\s*top\s*!=\s*window\s*\)', 'top != window check'),
    (r'if\s*\(\s*parent\s*[!=]=\s*self\s*\)', 'parent != self check'),
    (r'if\s*\(\s*parent\s*&&\s*parent\s*[!=]=\s*window\s*\)', 'parent != window check'),

    # Top.location redirect patterns
    (r'top\.location\s*=', 'top.location assignment'),
    (r'top\.location\.href\s*=', 'top.location.href assignment'),
    (r'top\.location\.replace\s*\(', 'top.location.replace()'),
    (r'parent\.location\s*=', 'parent.location assignment'),
    (r'window\.top\.location\s*=', 'window.top.location assignment'),

    # Frame counting patterns
    (r'parent\.frames\.length\s*>', 'parent.frames.length check'),
    (r'top\.frames\.length\s*[>!=]', 'top.frames.length check'),
    (r'window\.frames\.length\s*>', 'window.frames.length check'),

    # Document.domain check
    (r'if\s*\(\s*document\.domain\s*[!=]', 'document.domain check'),

    # Ancestor check patterns
    (r'window\.frameElement', 'window.frameElement check'),
    (r'if\s*\(\s*frameElement\s*\)', 'frameElement existence check'),

    # Break out of frame patterns
    (r'top\.location\.hostname\s*[!=]=\s*location\.hostname', 'hostname comparison'),
    (r'top\.location\.host\s*[!=]=\s*location\.host', 'host comparison'),

    # Visibility/display manipulation
    (r'document\.body\.style\.display\s*=\s*[\'"]none[\'"]', 'body display none'),
    (r'document\.body\.innerHTML\s*=\s*[\'"][\'"]', 'body innerHTML clear'),

    # Modern sandbox detection
    (r'window\.sandbox', 'sandbox detection'),

    # Event-based frame detection
    (r'onload\s*=.*top\.location', 'onload frame check'),
    (r'onbeforeunload.*top', 'onbeforeunload frame check'),
]

# More aggressive/obfuscated patterns
ADVANCED_FRAMEBUSTING_PATTERNS = [
    # Obfuscated patterns
    (r'\[[\'"](t|T)(o|O)(p|P)[\'"]\]', 'obfuscated top reference'),
    (r'window\[[\'"]top[\'"]\]', 'window["top"] access'),
    (r'eval\s*\([^)]*top[^)]*\)', 'eval with top reference'),

    # Try-catch frame busting
    (r'try\s*\{[^}]*top[^}]*\}\s*catch', 'try-catch frame buster'),

    # SetInterval/setTimeout based
    (r'setInterval\s*\([^)]*top[^)]*\)', 'setInterval frame check'),
    (r'setTimeout\s*\([^)]*top[^)]*\)', 'setTimeout frame check'),
]


def check_xframe_header(headers: Dict[str, str]) -> Tuple[bool, Optional[str], str]:
    """
    Check for X-Frame-Options HTTP header.

    Args:
        headers: Dictionary of HTTP headers (case-insensitive keys)

    Returns:
        Tuple of (has_header, value, effectiveness)
        effectiveness: 'strong', 'moderate', 'weak', 'none'
    """
    # Normalize header keys to lowercase
    headers_lower = {k.lower(): v for k, v in headers.items()}

    xfo_value = headers_lower.get('x-frame-options')

    if not xfo_value:
        return False, None, 'none'

    xfo_value = xfo_value.strip().upper()

    # Evaluate effectiveness
    if xfo_value == 'DENY':
        return True, xfo_value, 'strong'
    elif xfo_value == 'SAMEORIGIN':
        return True, xfo_value, 'strong'
    elif xfo_value.startswith('ALLOW-FROM'):
        # ALLOW-FROM is deprecated and not supported in all browsers
        return True, xfo_value, 'moderate'
    else:
        # Invalid or unknown value
        return True, xfo_value, 'weak'


def check_csp_frame_ancestors(headers: Dict[str, str]) -> Tuple[bool, Optional[str], str]:
    """
    Check for Content-Security-Policy frame-ancestors directive.

    Args:
        headers: Dictionary of HTTP headers

    Returns:
        Tuple of (has_directive, value, effectiveness)
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    csp_value = headers_lower.get('content-security-policy')

    if not csp_value:
        return False, None, 'none'

    # Look for frame-ancestors directive
    match = re.search(r'frame-ancestors\s+([^;]+)', csp_value, re.IGNORECASE)

    if not match:
        return False, None, 'none'

    ancestors_value = match.group(1).strip()

    # Evaluate effectiveness
    if "'none'" in ancestors_value.lower():
        return True, ancestors_value, 'strong'
    elif "'self'" in ancestors_value.lower():
        return True, ancestors_value, 'strong'
    elif '*' in ancestors_value:
        return True, ancestors_value, 'weak'
    else:
        # Specific domains listed
        return True, ancestors_value, 'moderate'


def check_meta_csp(html_content: str) -> Tuple[bool, Optional[str], str]:
    """
    Check for Content-Security-Policy in meta tags.

    Args:
        html_content: Raw HTML string

    Returns:
        Tuple of (has_directive, value, effectiveness)
    """
    soup = BeautifulSoup(html_content, 'lxml')

    for meta in soup.find_all('meta'):
        http_equiv = meta.get('http-equiv', '').lower()
        if http_equiv == 'content-security-policy':
            content = meta.get('content', '')
            match = re.search(r'frame-ancestors\s+([^;]+)', content, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if "'none'" in value.lower():
                    return True, value, 'strong'
                elif "'self'" in value.lower():
                    return True, value, 'strong'
                elif '*' in value:
                    return True, value, 'weak'
                else:
                    return True, value, 'moderate'

    return False, None, 'none'


def detect_framebusting_js(html_content: str,
                           include_advanced: bool = True) -> Tuple[bool, List[str], List[str]]:
    """
    Detect frame-busting JavaScript patterns in HTML content.

    Args:
        html_content: Raw HTML string
        include_advanced: Whether to include advanced/obfuscated patterns

    Returns:
        Tuple of (has_framebusting, patterns_found, code_snippets)
    """
    soup = BeautifulSoup(html_content, 'lxml')
    patterns_found = []
    code_snippets = []

    # Collect all JavaScript content
    js_contents = []

    # From <script> tags
    for script in soup.find_all('script'):
        # Skip external scripts (we can't analyze them)
        if script.get('src'):
            continue
        js_text = script.get_text()
        if js_text:
            js_contents.append(('script', js_text))

    # From event handlers
    event_attrs = ['onclick', 'onload', 'onbeforeunload', 'onunload', 'onerror']
    for attr in event_attrs:
        for tag in soup.find_all(attrs={attr: True}):
            js_contents.append((f'{attr} handler', tag.get(attr)))

    # Check body onload
    body = soup.find('body')
    if body and body.get('onload'):
        js_contents.append(('body onload', body.get('onload')))

    # Combine patterns to check
    all_patterns = list(FRAMEBUSTING_PATTERNS)
    if include_advanced:
        all_patterns.extend(ADVANCED_FRAMEBUSTING_PATTERNS)

    # Search for patterns
    for source, js_text in js_contents:
        for pattern, description in all_patterns:
            matches = re.finditer(pattern, js_text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if description not in patterns_found:
                    patterns_found.append(description)

                # Extract code snippet around the match
                start = max(0, match.start() - 50)
                end = min(len(js_text), match.end() + 50)
                snippet = js_text[start:end].strip()
                snippet = re.sub(r'\s+', ' ', snippet)  # Normalize whitespace

                if len(snippet) > 200:
                    snippet = snippet[:200] + '...'

                snippet_info = f"[{source}] {snippet}"
                if snippet_info not in code_snippets:
                    code_snippets.append(snippet_info)

    return bool(patterns_found), patterns_found, code_snippets


def evaluate_framebusting_effectiveness(patterns_found: List[str],
                                        html_content: str) -> str:
    """
    Evaluate how effective the frame-busting code is likely to be.

    Args:
        patterns_found: List of detected pattern descriptions
        html_content: Raw HTML for additional analysis

    Returns:
        Effectiveness level: 'strong', 'moderate', 'weak', 'none'
    """
    if not patterns_found:
        return 'none'

    score = 0

    # Strong indicators
    strong_patterns = [
        'top.location assignment',
        'top.location.replace()',
        'window.top.location assignment',
        'body display none',
        'body innerHTML clear',
    ]

    # Check patterns
    for pattern in patterns_found:
        if any(strong in pattern for strong in strong_patterns):
            score += 3
        elif 'check' in pattern.lower():
            score += 1
        else:
            score += 2

    # Check for common bypasses that weaken effectiveness
    soup = BeautifulSoup(html_content, 'lxml')

    # Check if frame-busting is in a conditional that might not execute
    for script in soup.find_all('script'):
        js_text = script.get_text()
        # Look for try-catch that might swallow errors
        if re.search(r'try\s*\{[^}]*top[^}]*\}\s*catch\s*\([^)]*\)\s*\{\s*\}', js_text):
            score -= 2

    # Evaluate final score
    if score >= 5:
        return 'strong'
    elif score >= 3:
        return 'moderate'
    elif score >= 1:
        return 'weak'
    else:
        return 'none'


def analyze_defenses(headers: Dict[str, str], html_content: str) -> DefenseResult:
    """
    Complete defense analysis combining all detection methods.

    Args:
        headers: HTTP headers dictionary
        html_content: Raw HTML content

    Returns:
        DefenseResult with all findings
    """
    result = DefenseResult()

    # Check X-Frame-Options
    has_xfo, xfo_value, xfo_effectiveness = check_xframe_header(headers)
    result.has_xframe_options = has_xfo
    result.xframe_options_value = xfo_value

    # Check CSP frame-ancestors
    has_csp, csp_value, csp_effectiveness = check_csp_frame_ancestors(headers)

    # Also check meta tag CSP
    has_meta_csp, meta_csp_value, meta_csp_effectiveness = check_meta_csp(html_content)

    if has_csp or has_meta_csp:
        result.has_csp_frame_ancestors = True
        result.csp_frame_ancestors_value = csp_value or meta_csp_value

    # Check frame-busting JavaScript
    has_fb, patterns, snippets = detect_framebusting_js(html_content)
    result.has_framebusting_js = has_fb
    result.framebusting_patterns_found = patterns
    result.framebusting_code_snippets = snippets

    fb_effectiveness = evaluate_framebusting_effectiveness(patterns, html_content)

    # Calculate overall defense score (0-10)
    score = 0

    # HTTP header defenses (most reliable)
    if xfo_effectiveness == 'strong':
        score += 4
    elif xfo_effectiveness == 'moderate':
        score += 3
    elif xfo_effectiveness == 'weak':
        score += 1

    if csp_effectiveness == 'strong' or meta_csp_effectiveness == 'strong':
        score += 4
    elif csp_effectiveness == 'moderate' or meta_csp_effectiveness == 'moderate':
        score += 3
    elif csp_effectiveness == 'weak' or meta_csp_effectiveness == 'weak':
        score += 1

    # JavaScript defenses (can be bypassed)
    if fb_effectiveness == 'strong':
        score += 2
    elif fb_effectiveness == 'moderate':
        score += 1
    elif fb_effectiveness == 'weak':
        score += 0.5

    result.defense_score = min(10, int(score))

    # Determine defense level
    if score >= 7:
        result.defense_level = 'strong'
    elif score >= 4:
        result.defense_level = 'moderate'
    elif score >= 1:
        result.defense_level = 'weak'
    else:
        result.defense_level = 'none'

    return result


def get_defense_summary(result: DefenseResult) -> Dict[str, Any]:
    """
    Get a summary dictionary of defense findings.

    Args:
        result: DefenseResult object

    Returns:
        Summary dictionary
    """
    return {
        'has_defenses': result.defense_level != 'none',
        'defense_level': result.defense_level,
        'defense_score': result.defense_score,
        'mechanisms': {
            'x_frame_options': {
                'present': result.has_xframe_options,
                'value': result.xframe_options_value
            },
            'csp_frame_ancestors': {
                'present': result.has_csp_frame_ancestors,
                'value': result.csp_frame_ancestors_value
            },
            'framebusting_js': {
                'present': result.has_framebusting_js,
                'patterns_count': len(result.framebusting_patterns_found),
                'patterns': result.framebusting_patterns_found
            }
        }
    }


# Historical analysis helpers for archived content
def get_defense_by_era(year: int) -> Dict[str, Any]:
    """
    Get expected defense mechanisms by era.
    Useful for contextualizing findings in historical archived content.

    Args:
        year: Year of the archived content

    Returns:
        Dictionary with era-appropriate defense expectations
    """
    if year < 2008:
        return {
            'expected_defenses': ['framebusting_js'],
            'notes': 'X-Frame-Options not yet standardized (2008). Frame-busting JS was primary defense.',
            'xfo_expected': False,
            'csp_expected': False
        }
    elif year < 2012:
        return {
            'expected_defenses': ['framebusting_js', 'x_frame_options'],
            'notes': 'X-Frame-Options available but adoption still growing. CSP not yet widespread.',
            'xfo_expected': True,
            'csp_expected': False
        }
    elif year < 2016:
        return {
            'expected_defenses': ['x_frame_options', 'framebusting_js'],
            'notes': 'X-Frame-Options well established. CSP frame-ancestors emerging.',
            'xfo_expected': True,
            'csp_expected': False
        }
    else:
        return {
            'expected_defenses': ['x_frame_options', 'csp_frame_ancestors'],
            'notes': 'Both X-Frame-Options and CSP frame-ancestors expected. JS fallback optional.',
            'xfo_expected': True,
            'csp_expected': True
        }
