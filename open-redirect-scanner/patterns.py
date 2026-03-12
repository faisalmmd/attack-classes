"""
Pattern definitions for JavaScript-based open redirect detection.

Based on:
  Lekies, Stock & Johns, "25 Million Flows Later: Large-scale Detection of
  DOM-based XSS" (CCS 2013) -- establishes the taint source/sink vocabulary
  for DOM-based vulnerabilities; open redirect shares the same source set
  (location.search, location.hash, document.referrer, document.URL) with
  only the sink class differing (navigation vs. script execution).

  OWASP Unvalidated Redirects and Forwards Cheat Sheet -- practical sink
  enumeration used as ground truth for pattern selection.

  Pellegrino, Johns, Koch & Backes, "Deemon: Detecting CSRF with Dynamic
  Analysis and Property Graphs" (CCS 2017) -- covers client-side navigation
  manipulation as part of cross-origin attack surface analysis, including
  how attacker-controlled URL parameters reach window.location assignments.

Open redirect happens when an application reads a URL from attacker-controlled
input (URL query string, fragment, or referrer) and navigates the user to it
without validating that the destination is a trusted domain. In a government
context the consequence is phishing amplification: a link that begins with a
trusted .gov domain silently sends users to an attacker page. The victim sees
a legitimate URL in the status bar before clicking.

Static framing: a CHAIN finding (source expression visible in the same
statement as a sink) is a high-confidence open redirect. A SINK-only finding
needs cross-referencing with SOURCE findings from the same domain to estimate
whether user input reaches it. DEFENSIVE findings lower the overall risk score
but must be inspected - an allowlist check is only meaningful if it rejects
absolute URLs before the sink executes.

Pattern categories:
  SINK      - a redirect operation (flag all, evaluate surrounding context)
  SOURCE    - a user-controllable URL input read (flag when near a SINK)
  CHAIN     - source expression directly visible in the same sink statement
  DEFENSIVE - validation pattern that limits where a redirect can land
"""

import re
from dataclasses import dataclass


@dataclass
class RedirectPattern:
    id: str
    label: str
    category: str   # SINK | SOURCE | CHAIN | DEFENSIVE
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    regex: str
    description: str
    false_positive_note: str = ''


PATTERNS = [

    # ── Redirect sinks ────────────────────────────────────────────────────────

    RedirectPattern(
        id='location_href_assign',
        label='location.href Assignment',
        category='SINK',
        severity='HIGH',
        regex=r'(?:window\s*\.\s*)?location\s*\.\s*href\s*=\s*(?!=)',
        description=(
            'Assigning a value to location.href triggers a navigation. If the '
            'assigned value comes from any user-controlled source - URL parameter, '
            'fragment, referrer, or postMessage data - this is an open redirect. '
            'Even when the value is constructed server-side and reflected into the '
            'page as a JS variable, a missing domain validation step allows an '
            'attacker to substitute a malicious URL as the parameter value.'
        ),
        false_positive_note=(
            'Very common in navigation menus and login flows. Risk is elevated '
            'only when a SOURCE pattern appears in the same file or function body.'
        ),
    ),

    RedirectPattern(
        id='location_assign_call',
        label='location.assign() Call',
        category='SINK',
        severity='HIGH',
        regex=r'(?:window\s*\.\s*)?location\s*\.\s*assign\s*\(',
        description=(
            'location.assign() navigates to a new page and adds it to the browser '
            'history. Functionally identical to setting location.href for open '
            'redirect purposes. The history entry it creates can be exploited with '
            'the back button to chain attacks.'
        ),
        false_positive_note='Same false positive profile as location.href.',
    ),

    RedirectPattern(
        id='location_replace_call',
        label='location.replace() Call',
        category='SINK',
        severity='HIGH',
        regex=r'(?:window\s*\.\s*)?location\s*\.\s*replace\s*\(',
        description=(
            'location.replace() redirects without adding a history entry, making '
            'it impossible for the victim to navigate back. Frequently used in '
            'login and logout flows. When the destination URL is derived from user '
            'input, it is equally exploitable as location.href and slightly harder '
            'to detect because the absence of a history entry removes a visible '
            'forensic trail.'
        ),
    ),

    RedirectPattern(
        id='location_direct_assign',
        label='window.location Direct Assignment',
        category='SINK',
        severity='HIGH',
        regex=r'\bwindow\s*\.\s*location\s*=\s*(?!=)',
        description=(
            'Direct assignment to window.location rather than window.location.href. '
            'Less common but equally effective as a redirect trigger. Appears in '
            'older codebases and occasionally in code that avoids the .href property '
            'to confuse keyword-based filters.'
        ),
    ),

    RedirectPattern(
        id='open_external_window',
        label='window.open() with Variable URL',
        category='SINK',
        severity='MEDIUM',
        regex=r'\bwindow\s*\.\s*open\s*\(\s*(?!["\'][^"\']*["\'])',
        description=(
            'window.open() called with a non-literal URL argument. When the target '
            'URL is read from user input, this opens an attacker-controlled page in '
            'a new tab. The opened window also receives a reference to the opener '
            'via window.opener, enabling reverse tabnapping: the new page can set '
            'opener.location to replace the original trusted page.'
        ),
        false_positive_note='Very common for legitimate popups. Only flag when argument is clearly a variable.',
    ),

    # ── User-controllable URL sources ─────────────────────────────────────────

    RedirectPattern(
        id='location_search_read',
        label='location.search Read (Query String)',
        category='SOURCE',
        severity='MEDIUM',
        regex=r'(?:window\s*\.\s*)?location\s*\.\s*search\b',
        description=(
            'Reading the query string from the current URL. This is the most '
            'exploited source for open redirect: the attacker crafts a link with '
            '?redirect=https://evil.com and sends it to the target. Government '
            'portal login pages frequently read a "redirect", "next", or '
            '"returnUrl" parameter to send the user to the originally requested '
            'page after authentication - exactly the pattern attackers rely on.'
        ),
    ),

    RedirectPattern(
        id='location_hash_read',
        label='location.hash Read (URL Fragment)',
        category='SOURCE',
        severity='MEDIUM',
        regex=r'(?:window\s*\.\s*)?location\s*\.\s*hash\b',
        description=(
            'Reading the URL fragment (#...). Fragments are not sent to the server '
            'and are fully attacker-controllable on the client side. Single-page '
            'applications from the 2010-2015 era used hash-based routing, and many '
            'implemented fragment-based redirects without validating that the '
            'target remained on the same origin.'
        ),
    ),

    RedirectPattern(
        id='document_url_read',
        label='document.URL / document.documentURI Read',
        category='SOURCE',
        severity='MEDIUM',
        regex=r'\bdocument\s*\.\s*(?:URL|documentURI)\b',
        description=(
            'Reading the full current URL string. Attackers control the query '
            'string and fragment portions. If the code extracts a redirect target '
            'by parsing this string (e.g., a regex match on the full URL), it is '
            'vulnerable to the same attack as reading location.search directly.'
        ),
    ),

    RedirectPattern(
        id='document_referrer_read',
        label='document.referrer Read',
        category='SOURCE',
        severity='LOW',
        regex=r'\bdocument\s*\.\s*referrer\b',
        description=(
            'Reading the HTTP Referer header from JavaScript. Less directly '
            'exploitable than query parameters because the attacker must control '
            'the page the user arrives from. Still used in some redirect-back '
            'flows and worth flagging as a lower-confidence source.'
        ),
    ),

    RedirectPattern(
        id='url_search_params',
        label='URLSearchParams Instantiation',
        category='SOURCE',
        severity='MEDIUM',
        regex=r'\bnew\s+URLSearchParams\s*\(',
        description=(
            'Modern query string parsing via the URLSearchParams API, introduced '
            'in 2016. This is how contemporary SPAs extract redirect targets from '
            'URL parameters. Presence in the same file as a SINK pattern is a '
            'reliable signal that user-controlled URL data is being processed in '
            'the same code path.'
        ),
    ),

    RedirectPattern(
        id='get_param_helper',
        label='Custom getParam / getUrlParam Helper Call',
        category='SOURCE',
        severity='MEDIUM',
        regex=r'\b(?:getParam(?:eter)?|getQuery(?:Param)?|getUrlParam|urlParam|getSearch(?:Param)?)\s*\(',
        description=(
            'A custom query parameter extraction function - the standard pattern '
            'in government portal codebases from 2008-2018 before URLSearchParams '
            'was widely available. These helpers typically split location.search '
            'on & and = and return the raw (attacker-controlled) value directly.'
        ),
    ),

    # ── High-confidence source-to-sink chains ─────────────────────────────────

    RedirectPattern(
        id='search_hash_direct_to_location',
        label='URL Param/Hash Directly into location (Chain)',
        category='CHAIN',
        severity='CRITICAL',
        regex=(
            r'(?:window\s*\.\s*)?location(?:\s*\.\s*(?:href|assign|replace))?\s*[=(]\s*'
            r'[^;)]{0,300}location\s*\.\s*(?:search|hash)'
        ),
        description=(
            'A redirect sink with location.search or location.hash appearing in '
            'the same statement - the URL parameter or fragment is fed directly '
            'to the redirect without any intervening transformation. This is a '
            'near-certain open redirect unless there is a relative-path check '
            'immediately wrapping the assignment.'
        ),
    ),

    RedirectPattern(
        id='referrer_direct_to_location',
        label='document.referrer Directly into location (Chain)',
        category='CHAIN',
        severity='HIGH',
        regex=(
            r'(?:window\s*\.\s*)?location(?:\s*\.\s*(?:href|assign|replace))?\s*[=(]\s*'
            r'[^;)]{0,200}document\s*\.\s*referrer'
        ),
        description=(
            'document.referrer fed directly into a redirect sink in the same '
            'expression. Commonly seen in return-to-previous-page flows. An attacker '
            'who controls the referring page - or can trick a user into arriving '
            'from one - can redirect to an arbitrary URL.'
        ),
    ),

    # ── Defensive patterns ─────────────────────────────────────────────────────

    RedirectPattern(
        id='relative_url_check',
        label='Relative URL startsWith Check (Defense)',
        category='DEFENSIVE',
        severity='INFO',
        regex=(
            r'(?:url|redirect|href|target|next|returnUrl|returnTo)\s*[\w.]*'
            r'\s*\.\s*startsWith\s*\(\s*["\']\/["\']'
        ),
        description=(
            'Checking that a redirect target starts with "/" before navigating, '
            'which rejects absolute URLs (http://evil.com) and keeps the redirect '
            'on the same origin. This is the most common defense pattern in '
            'government portal login flows.'
        ),
    ),

    RedirectPattern(
        id='url_origin_check',
        label='URL Constructor with .origin / .hostname Check (Defense)',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'new\s+URL\s*\([^)]+\)\s*\.\s*(?:origin|hostname|host)\b',
        description=(
            'Parsing the redirect target with the URL constructor and checking its '
            'origin or hostname against an allowed list. The correct modern approach '
            'to redirect validation. Presence near a SINK finding is a strong '
            'defense signal, but the validation must actually reject non-matching '
            'values - inspect the conditional logic.'
        ),
    ),

    RedirectPattern(
        id='trusted_domain_allowlist',
        label='Trusted Domain Allowlist Variable (Defense)',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'\b(?:allowedDomains?|trustedDomains?|whitelist|allowedUrls?|ALLOWED_HOSTS?)\s*[=\[.]',
        description=(
            'An explicit list of allowed redirect destinations. When validated '
            'correctly this is a robust defense. Presence in the codebase suggests '
            'the developer considered redirect safety - review the validation logic '
            'to confirm it is actually enforced before the sink executes.'
        ),
    ),

]

COMPILED_PATTERNS = [(p, re.compile(p.regex, re.DOTALL)) for p in PATTERNS]

SEVERITY_ORDER = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
CATEGORY_ORDER = {'SINK': 0, 'SOURCE': 1, 'CHAIN': 2, 'DEFENSIVE': 3}
