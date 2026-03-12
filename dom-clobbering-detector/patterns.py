"""
Pattern definitions for DOM clobbering vulnerability detection.

Based on:
  Lekies, Jonker & Johns, "DOM Clobbering Strikes Back" (USENIX Security 2021)
  -- systematic study of DOM clobbering gadgets in real-world libraries;
  found exploitable chains in Chromium, DOMPurify, Gmail, and others. The
  paper establishes the named-element-to-global-variable naming collision as
  the root cause, and catalogues which HTML element/attribute combinations
  promote to window and document namespaces in each major browser.

  Sogeti / MISC Research Lab, "DOM-Based XSS: An Empirical Study"
  -- earlier characterization of browser namespace promotion behaviour that
  underpins all modern DOM clobbering research.

  Khodayari & Pellegrino, "It's (DOM) Clobbering Time: Attack Techniques,
  Prevalence, and Defenses" (IEEE S&P 2023) -- first large-scale measurement
  study of DOM clobbering in the wild; scanned 5,000 sites and found clobbering
  gadgets in 9.8% of pages, including patterns that bypass CSP nonce checks.

The attack exploits a browser feature where named HTML elements
(form, input, img, a, object, embed) are accessible as properties on window
and document. If a page contains <form name="config"> and JavaScript code
checks `if (window.config.debug)`, an attacker who can inject that element
can make `window.config` return an HTMLFormElement. Security checks that
depend on application-defined globals can be bypassed because DOM elements
are truthy, so `if (window.isAdmin)` passes even when the real isAdmin
flag is false - the element is just there.

The two-level variant (Lekies et al. 2021) uses <form id="x"><input name="y">
to make x.y return a DOM element, enabling more precise property forgery.

Pattern categories:
  HTML_SINK    - HTML element whose name/id could clobber a JS global
  JS_RELIANCE  - JS code accessing globals in ways susceptible to clobbering
  CHAIN        - named element and matching global access in the same HTML page
  DEFENSIVE    - explicit DOM API use (getElementById, querySelector) that
                 avoids relying on namespace promotion
"""

import re
from dataclasses import dataclass
from typing import Set


@dataclass
class ClobberPattern:
    id: str
    label: str
    category: str   # JS_RELIANCE | DEFENSIVE (HTML_SINK generated dynamically)
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    regex: str
    description: str
    false_positive_note: str = ''


# Names that, if claimed by an HTML element, could affect security behavior.
# Sourced from Lekies et al. 2021 known gadget targets plus common app patterns
# observed in government portal codebases (CMS-generated globals, auth state).
SENSITIVE_NAMES: Set[str] = {
    # Browser-defined globals that named elements can shadow
    'name', 'status', 'location', 'origin', 'parent', 'top',
    'self', 'frames', 'opener', 'closed',

    # Security-sensitive application globals
    'config', 'settings', 'options', 'params', 'data', 'userData',
    'auth', 'token', 'csrfToken', 'csrf', 'nonce', 'session',
    'isAdmin', 'admin', 'role', 'permissions', 'security', 'policy',
    'init', 'app', 'state', 'env', 'debug', 'trusted', 'safe',

    # Common boolean flags checked without explicit initialization
    'loaded', 'initialized', 'ready', 'enabled', 'allowed',
    'isLoggedIn', 'isAuthenticated', 'userRole',
}

# HTML elements whose name or id attributes create window/document properties.
# Based on browser namespace promotion rules documented in Lekies et al. 2021.
CLOBBERABLE_ELEMENTS = {'form', 'input', 'img', 'a', 'object', 'embed', 'iframe'}


JS_PATTERNS = [

    # ── High-confidence JS reliance patterns ──────────────────────────────────

    ClobberPattern(
        id='window_bracket_access',
        label='Dynamic window Property Access window[x]',
        category='JS_RELIANCE',
        severity='HIGH',
        regex=r'\bwindow\s*\[\s*\w+\s*\]',
        description=(
            'Computed property access on window using a variable key. If the '
            'variable name is predictable or externally influenced, an attacker '
            'who can inject HTML can clobber the target property. Even with a '
            'fixed variable, this pattern indicates the codebase relies on the '
            'global namespace in a way that named elements can interfere with.'
        ),
    ),

    ClobberPattern(
        id='security_global_check',
        label='Security-Relevant Global Variable in Conditional',
        category='JS_RELIANCE',
        severity='HIGH',
        regex=(
            r'if\s*\(\s*(?:typeof\s+)?(?:window\s*\.\s*)?'
            r'(?:isAdmin|isLoggedIn|isAuthenticated|admin|role|permissions|auth|token|csrf|nonce)\s*'
            r'[)=!&|]'
        ),
        description=(
            'An if-check on a security-relevant global without a prior var/let/const '
            'declaration in the same scope. If an attacker can inject an HTML element '
            'with a matching name or id attribute, this check evaluates the DOM element '
            'rather than the intended application state variable. DOM elements are '
            'truthy, so `if (window.isAdmin)` would always pass regardless of the '
            'actual authorization state.'
        ),
    ),

    ClobberPattern(
        id='window_config_access',
        label='window.config / window.settings Direct Access',
        category='JS_RELIANCE',
        severity='MEDIUM',
        regex=r'\bwindow\s*\.\s*(?:config|settings|options|globals|env|state|app)\b',
        description=(
            'Accessing a configuration or state object as a window property. A '
            '<form name="config"> element makes window.config an HTMLFormElement. '
            'Any property access on it returns undefined rather than throwing an '
            'error, silently breaking security-relevant configuration lookups like '
            'window.config.csrfToken or window.config.apiEndpoint.'
        ),
    ),

    ClobberPattern(
        id='document_named_access',
        label='document.X Named Property Access',
        category='JS_RELIANCE',
        severity='MEDIUM',
        regex=r'\bdocument\s*\.\s*(?:config|settings|data|auth|user|options|params|state|app)\b',
        description=(
            'Accessing document.X where X is a name likely shared with a named '
            'form or anchor element. Named form elements and anchors with a name '
            'attribute are accessible directly as document.elementName in browsers. '
            'If attacker-controlled HTML can introduce such an element, document.X '
            'returns the DOM node instead of the expected application value.'
        ),
    ),

    ClobberPattern(
        id='undeclared_security_variable',
        label='Security Variable Used Without Visible Declaration',
        category='JS_RELIANCE',
        severity='LOW',
        regex=(
            r'(?<![.\w\'"])(?:isAdmin|isLoggedIn|isAuthenticated|userRole|csrfToken)\s*'
            r'(?:[=!]=|&&|\|\||\?|;)'
        ),
        description=(
            'A security-relevant variable referenced in a conditional or assignment '
            'without a visible var/let/const declaration in the same code block. '
            'If this variable is not initialized before the check runs, and an HTML '
            'element with a matching id or name exists on the page, the browser may '
            'supply the DOM element as the value. DOM elements are truthy by default, '
            'so authorization checks that expected a false boolean value will pass.'
        ),
        false_positive_note='High false positive rate for code where declaration is in a separate file.',
    ),

    ClobberPattern(
        id='nonce_from_meta',
        label='CSP Nonce Read from Meta/Global (Clobberable Path)',
        category='JS_RELIANCE',
        severity='HIGH',
        regex=r'(?:window\s*\.\s*|document\s*\.\s*)?(?:cspNonce|nonce|__nonce__)\b',
        description=(
            'Accessing a CSP nonce value through a global variable or named property. '
            'Khodayari & Pellegrino S&P 2023 demonstrated that DOM clobbering can '
            'forge the nonce value read by dynamically-loaded scripts, bypassing CSP '
            'protections even when the header is correctly configured. If the nonce is '
            'set via a named element rather than a proper script attribute, it is '
            'clobberable.'
        ),
    ),

    # ── Defensive patterns ────────────────────────────────────────────────────

    ClobberPattern(
        id='defense_getelementbyid',
        label='getElementById Usage (Explicit DOM Access)',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'\bdocument\s*\.\s*getElementById\s*\(',
        description=(
            'Using getElementById to fetch elements by id - the correct approach '
            'that avoids relying on global namespace promotion. Code that consistently '
            'uses getElementById rather than window.id or document.id is not '
            'susceptible to DOM clobbering on the element access side. Note that '
            'the retrieved element could still clobber if passed to insecure '
            'innerHTML operations.'
        ),
    ),

    ClobberPattern(
        id='defense_queryselector',
        label='querySelector / querySelectorAll Usage',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'\bdocument\s*\.\s*querySelector(?:All)?\s*\(',
        description=(
            'Using querySelector/querySelectorAll for DOM access. Like getElementById, '
            'this explicitly fetches elements without relying on name-to-global '
            'namespace promotion, making the code resilient to DOM clobbering on '
            'the element retrieval side.'
        ),
    ),

    ClobberPattern(
        id='defense_object_create_null',
        label='Object.create(null) - Prototype-Safe Dictionary',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'Object\s*\.\s*create\s*\(\s*null\s*\)',
        description=(
            'Creating an object with no prototype chain. Objects created this way '
            'cannot be polluted via DOM clobbering of Object.prototype. When used '
            'for configuration storage, these objects are immune to named element '
            'interference.'
        ),
    ),
]

COMPILED_JS_PATTERNS = [(p, re.compile(p.regex, re.DOTALL)) for p in JS_PATTERNS]

SEVERITY_ORDER = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
