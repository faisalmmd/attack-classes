"""
Pattern definitions for prototype pollution vulnerability detection.

Based on:
  Kang, Li & Cao, "Probe the Proto: Measuring Client-Side Prototype Pollution
  Vulnerabilities of One Million Real-world Websites" (NDSS 2022)

  Shcherbakov & Balliu, "Silent Spring: Prototype Pollution Leads to Remote
  Code Execution in Node.js" (USENIX Security 2023)

The attack works by merging a user-controlled object into an application
object without sanitizing property keys. If the user sends:
  ?__proto__[isAdmin]=true
and the application does:
  merge(config, queryParams)
then Object.prototype.isAdmin becomes true for all objects.

Kang et al. found 2,738 vulnerable sites in the Alexa top 1M, including 10
in the top 1,000. Of those: 48 gadget chains led to XSS, 736 to cookie
manipulation. Static analysis can't prove exploitability without taint
tracking, but it can reliably flag the code structures that make a codebase
vulnerable when user input reaches them.

Pattern categories:
  VULNERABLE  - code pattern that is dangerous if user-controlled input reaches it
  INDICATOR   - not inherently exploitable but warrants manual review
  DEFENSIVE   - hardening pattern; absence is sometimes as interesting as presence
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class PollutionPattern:
    id: str
    label: str
    category: str       # VULNERABLE, INDICATOR, DEFENSIVE
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW, INFO
    regex: str
    description: str
    false_positive_note: str = ''


PATTERNS = [
    # ── Direct prototype access ───────────────────────────────────────────────

    PollutionPattern(
        id='proto_string_key',
        label='__proto__ String Key',
        category='INDICATOR',
        severity='HIGH',
        regex=r'["\']__proto__["\']',
        description=(
            'Explicit string reference to "__proto__". In production code this '
            'almost always means the developer is aware of the property - either '
            'attempting to access it directly or (hopefully) validating against it. '
            'Either way it needs a look.'
        ),
        false_positive_note='Often appears in validation/sanitization code checking for this exact string.',
    ),

    PollutionPattern(
        id='constructor_prototype',
        label='constructor.prototype Access',
        category='INDICATOR',
        severity='HIGH',
        regex=r'\.constructor\s*\.\s*prototype\b',
        description=(
            'Access to .constructor.prototype - the second common prototype pollution '
            'pathway besides __proto__. An attacker can send ?constructor[prototype][x]=y '
            'and reach Object.prototype through this chain if the merge code follows it.'
        ),
        false_positive_note='Can appear in legitimate type-checking code.',
    ),

    PollutionPattern(
        id='object_prototype_set',
        label='Object.prototype Direct Assignment',
        category='VULNERABLE',
        severity='CRITICAL',
        regex=r'Object\s*\.\s*prototype\s*\[',
        description=(
            'Direct computed property assignment on Object.prototype. If the key '
            'comes from any external source, this IS prototype pollution. Even if '
            'the key is a literal, adding enumerable properties to Object.prototype '
            'affects all objects in the page.'
        ),
        false_positive_note='Rare in legitimate code; usually only appears in polyfills.',
    ),

    # ── Unsafe merge patterns ─────────────────────────────────────────────────

    PollutionPattern(
        id='forin_bracket_assign',
        label='Unsafe for-in with Bracket Assignment',
        category='VULNERABLE',
        severity='HIGH',
        regex=r'for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+\w+\s*\)[^;{]{0,120}\[\s*\w+\s*\]\s*=',
        description=(
            'A for-in loop where the key is used as a bracket-notation property '
            'assignment in the same statement. This is the canonical unsafe merge '
            'pattern. Without a hasOwnProperty() guard or key blocklist, iterating '
            'over a user-controlled object will write __proto__ and constructor '
            'to the target, polluting the prototype chain.'
        ),
        false_positive_note=(
            'High volume in minified code. Many instances are internal utility merges '
            'that never receive user input. Triage by looking at the call site, not '
            'just the function body.'
        ),
    ),

    PollutionPattern(
        id='forin_no_hasown',
        label='for-in Loop (hasOwnProperty not detected nearby)',
        category='INDICATOR',
        severity='MEDIUM',
        regex=r'for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+\w+\s*\)',
        description=(
            'Any for-in loop. Flagged separately from the bracket-assign pattern to '
            'capture cases where the assignment is on the next line. A for-in without '
            'hasOwnProperty() guard is a prerequisite for prototype pollution in '
            'recursive merge functions.'
        ),
        false_positive_note='High volume; most are benign. Use as a density signal rather than a per-finding alarm.',
    ),

    # ── Library-specific vulnerable calls ────────────────────────────────────

    PollutionPattern(
        id='jquery_extend_deep',
        label='jQuery.extend (deep merge)',
        category='VULNERABLE',
        severity='HIGH',
        regex=r'\$\s*\.extend\s*\(\s*true\s*,',
        description=(
            'jQuery.extend with deep=true was vulnerable to prototype pollution in '
            'all versions before 3.4.0 (CVE-2019-11358). When any user-controlled '
            'object reaches this call, an attacker can set arbitrary properties on '
            'Object.prototype. Cross-reference with the RetireJS output to see '
            'whether the jQuery version on this site is actually affected.'
        ),
        false_positive_note='Only a real vulnerability if a patched jQuery version is not present.',
    ),

    PollutionPattern(
        id='lodash_deep_merge',
        label='Lodash merge / defaultsDeep',
        category='VULNERABLE',
        severity='HIGH',
        regex=r'(?:_|lodash)\s*\.\s*(?:merge|defaultsDeep)\s*\(',
        description=(
            'Lodash merge() and defaultsDeep() were vulnerable to prototype pollution '
            'before version 4.17.11 (CVE-2018-3721, CVE-2019-10744). These are very '
            'common utility calls in older government portal codebases. Cross-reference '
            'the timestamp with the RetireJS output to confirm whether the lodash '
            'version present is actually patched.'
        ),
        false_positive_note='Safe in lodash >= 4.17.11. Use RetireJS output to confirm version.',
    ),

    PollutionPattern(
        id='object_assign_call',
        label='Object.assign Call',
        category='INDICATOR',
        severity='LOW',
        regex=r'Object\s*\.\s*assign\s*\(\s*\w',
        description=(
            'Object.assign() itself is not vulnerable to prototype pollution - it '
            'uses [[OwnProperty]] iteration, not for-in. However, it is commonly '
            'used in merge utility functions that ALSO have a recursive branch, and '
            'those recursive branches often use for-in. Flagging as a density '
            'indicator to map where merging is happening.'
        ),
        false_positive_note='Object.assign is safe by itself. Context is everything here.',
    ),

    PollutionPattern(
        id='json_parse_spread',
        label='JSON.parse Result Used in Property Spread/Assign',
        category='VULNERABLE',
        severity='HIGH',
        regex=r'JSON\s*\.\s*parse\s*\([^)]+\)[^;]{0,80}(?:Object\.assign|for\s*\(|merge\s*\()',
        description=(
            'JSON.parse output used directly as the source in an assign or merge '
            'operation. If the JSON string comes from user input (URL parameter, '
            'request body, localStorage), this is a complete prototype pollution '
            'attack chain. The hardest variant to spot in static analysis.'
        ),
        false_positive_note='Severity depends entirely on where the JSON string originates.',
    ),

    # ── Defensive patterns (positive signals) ─────────────────────────────────

    PollutionPattern(
        id='defense_freeze_proto',
        label='Object.freeze(Object.prototype) - Hardening',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'Object\s*\.\s*freeze\s*\(\s*Object\s*\.\s*prototype\s*\)',
        description=(
            'Explicitly freezing Object.prototype prevents any script from adding '
            'enumerable properties to it. This is the strongest available defense '
            'against prototype pollution. Presence is a positive signal that the '
            'developer was aware of the threat.'
        ),
    ),

    PollutionPattern(
        id='defense_null_proto',
        label='Object.create(null) - Null Prototype Dictionary',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'Object\s*\.\s*create\s*\(\s*null\s*\)',
        description=(
            'Creates an object with no prototype chain. Using null-prototype objects '
            'as dictionaries means they cannot be polluted via __proto__ inheritance. '
            'Presence suggests prototype-aware code.'
        ),
    ),

    PollutionPattern(
        id='defense_hasown_call',
        label='hasOwnProperty Guard in Loop',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'hasOwnProperty\s*\.\s*call\s*\(',
        description=(
            'Calling hasOwnProperty.call() before acting on a property - the '
            'canonical guard against for-in prototype chain traversal. Presence '
            'near for-in loops indicates the developer accounted for this risk.'
        ),
    ),

    PollutionPattern(
        id='defense_key_blocklist',
        label='Key Blocklist Check (__proto__ / constructor)',
        category='DEFENSIVE',
        severity='INFO',
        regex=r'["\']__proto__["\']\s*\|\|.*["\']constructor["\']|["\']constructor["\']\s*\|\|.*["\']__proto__["\']',
        description=(
            'Explicit key validation checking for __proto__ and constructor before '
            'property assignment - a direct defense against prototype pollution inputs.'
        ),
    ),
]

COMPILED_PATTERNS = [(p, re.compile(p.regex, re.DOTALL)) for p in PATTERNS]

# Severity ordering for filtering
SEVERITY_ORDER = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
