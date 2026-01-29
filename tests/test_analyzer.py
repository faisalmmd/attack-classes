#!/usr/bin/env python3
"""
Unit tests for the Clickjacking Detection Tool.

Run with: python -m pytest tests/test_analyzer.py -v
Or simply: python tests/test_analyzer.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from pathlib import Path

from frame_detector import (
    extract_frames,
    parse_inline_style,
    is_transparent,
    is_cross_domain,
    analyze_frames,
    get_suspicious_frames
)
from overlap_checker import (
    extract_clickable_elements,
    check_overlap,
    find_overlapping_elements
)
from defense_detector import (
    check_xframe_header,
    check_csp_frame_ancestors,
    detect_framebusting_js,
    analyze_defenses
)
from analyzer import ClickjackingAnalyzer, VulnerabilityReport


class TestFrameDetector(unittest.TestCase):
    """Tests for frame_detector module."""

    def test_extract_frames_basic(self):
        """Test basic iframe extraction."""
        html = '''
        <html>
        <body>
            <iframe src="https://example.com/embed"></iframe>
            <iframe src="/local/page" id="local-frame"></iframe>
        </body>
        </html>
        '''
        frames = extract_frames(html)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0].src, "https://example.com/embed")
        self.assertEqual(frames[1].id, "local-frame")

    def test_extract_frames_with_style(self):
        """Test iframe extraction with inline styles."""
        html = '''
        <html>
        <body>
            <iframe src="https://evil.com" style="opacity: 0; position: absolute;"></iframe>
        </body>
        </html>
        '''
        frames = extract_frames(html)
        self.assertEqual(len(frames), 1)
        self.assertIn('opacity', frames[0].css_properties)

    def test_parse_inline_style(self):
        """Test CSS style parsing."""
        style = "opacity: 0.5; position: absolute; z-index: 9999;"
        props = parse_inline_style(style)
        self.assertEqual(props.get('opacity'), '0.5')
        self.assertEqual(props.get('position'), 'absolute')
        self.assertEqual(props.get('z-index'), '9999')

    def test_is_transparent(self):
        """Test transparency detection."""
        # Transparent
        self.assertTrue(is_transparent({'opacity': 0}))
        self.assertTrue(is_transparent({'opacity': 0.05}))
        self.assertTrue(is_transparent({'visibility': 'hidden'}))
        self.assertTrue(is_transparent({'display': 'none'}))

        # Not transparent
        self.assertFalse(is_transparent({'opacity': 1.0}))
        self.assertFalse(is_transparent({'opacity': 0.5}))
        self.assertFalse(is_transparent({}))

    def test_is_cross_domain(self):
        """Test cross-domain detection."""
        page_url = "https://www.government.gov/page"

        # Cross-domain
        self.assertTrue(is_cross_domain("https://evil.com/steal", page_url))
        self.assertTrue(is_cross_domain("https://attacker.net/frame", page_url))
        self.assertTrue(is_cross_domain("//other-domain.com/page", page_url))

        # Same domain
        self.assertFalse(is_cross_domain("/local/page", page_url))
        self.assertFalse(is_cross_domain("page.html", page_url))
        self.assertFalse(is_cross_domain(None, page_url))
        self.assertFalse(is_cross_domain("javascript:void(0)", page_url))

    def test_analyze_frames_suspicious(self):
        """Test detection of suspicious frames."""
        html = '''
        <html>
        <body>
            <iframe src="https://malicious.com/attack" style="opacity: 0;"></iframe>
            <iframe src="/local/embed" style="opacity: 1;"></iframe>
        </body>
        </html>
        '''
        frames = analyze_frames(html, "https://legitimate.gov")
        suspicious = get_suspicious_frames(frames)

        self.assertEqual(len(frames), 2)
        self.assertEqual(len(suspicious), 1)
        self.assertTrue(suspicious[0].is_transparent)
        self.assertTrue(suspicious[0].is_cross_domain)


class TestOverlapChecker(unittest.TestCase):
    """Tests for overlap_checker module."""

    def test_extract_clickable_elements(self):
        """Test clickable element extraction."""
        html = '''
        <html>
        <body>
            <a href="/link">Click me</a>
            <button>Submit</button>
            <input type="submit" value="Send">
            <input type="text" name="query">
        </body>
        </html>
        '''
        clickables = extract_clickable_elements(html)

        # Should find link, button, and submit input (not text input)
        types = [c.element_type for c in clickables]
        self.assertIn('link', types)
        self.assertIn('button', types)
        self.assertIn('input', types)
        self.assertEqual(len(clickables), 3)

    def test_check_overlap_yes(self):
        """Test overlap detection - overlapping boxes."""
        box1 = (0, 0, 100, 100)  # Frame
        box2 = (50, 50, 100, 100)  # Button

        overlaps, overlap_box, pct = check_overlap(box1, box2)
        self.assertTrue(overlaps)
        self.assertIsNotNone(overlap_box)
        self.assertGreater(pct, 0)

    def test_check_overlap_no(self):
        """Test overlap detection - non-overlapping boxes."""
        box1 = (0, 0, 100, 100)
        box2 = (200, 200, 50, 50)

        overlaps, overlap_box, pct = check_overlap(box1, box2)
        self.assertFalse(overlaps)
        self.assertIsNone(overlap_box)
        self.assertEqual(pct, 0)


class TestDefenseDetector(unittest.TestCase):
    """Tests for defense_detector module."""

    def test_xframe_options_deny(self):
        """Test X-Frame-Options DENY detection."""
        headers = {'X-Frame-Options': 'DENY'}
        has_xfo, value, effectiveness = check_xframe_header(headers)

        self.assertTrue(has_xfo)
        self.assertEqual(value, 'DENY')
        self.assertEqual(effectiveness, 'strong')

    def test_xframe_options_sameorigin(self):
        """Test X-Frame-Options SAMEORIGIN detection."""
        headers = {'x-frame-options': 'sameorigin'}  # lowercase
        has_xfo, value, effectiveness = check_xframe_header(headers)

        self.assertTrue(has_xfo)
        self.assertEqual(value, 'SAMEORIGIN')
        self.assertEqual(effectiveness, 'strong')

    def test_no_xframe_options(self):
        """Test missing X-Frame-Options."""
        headers = {'Content-Type': 'text/html'}
        has_xfo, value, effectiveness = check_xframe_header(headers)

        self.assertFalse(has_xfo)
        self.assertIsNone(value)
        self.assertEqual(effectiveness, 'none')

    def test_csp_frame_ancestors(self):
        """Test CSP frame-ancestors detection."""
        headers = {
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'"
        }
        has_csp, value, effectiveness = check_csp_frame_ancestors(headers)

        self.assertTrue(has_csp)
        self.assertEqual(effectiveness, 'strong')

    def test_framebusting_js_detection(self):
        """Test frame-busting JavaScript detection."""
        html = '''
        <html>
        <head>
            <script>
                if (top !== self) {
                    top.location.replace(self.location.href);
                }
            </script>
        </head>
        <body></body>
        </html>
        '''
        has_fb, patterns, snippets = detect_framebusting_js(html)

        self.assertTrue(has_fb)
        self.assertGreater(len(patterns), 0)

    def test_no_framebusting(self):
        """Test page without frame-busting."""
        html = '''
        <html>
        <head>
            <script>
                console.log("Hello world");
            </script>
        </head>
        <body></body>
        </html>
        '''
        has_fb, patterns, snippets = detect_framebusting_js(html)

        self.assertFalse(has_fb)
        self.assertEqual(len(patterns), 0)


class TestAnalyzer(unittest.TestCase):
    """Tests for main analyzer module."""

    def setUp(self):
        self.analyzer = ClickjackingAnalyzer()

    def test_analyze_benign_page(self):
        """Test analysis of benign page."""
        html = '''
        <html>
        <body>
            <h1>Welcome</h1>
            <a href="/about">About</a>
            <iframe src="/local/embed" style="width: 100%; height: 400px;"></iframe>
        </body>
        </html>
        '''
        headers = {'X-Frame-Options': 'SAMEORIGIN'}
        metadata = {'url': 'https://gov.example.com'}

        report = self.analyzer.analyze_page(html, headers, metadata)

        self.assertFalse(report.vulnerable)
        self.assertEqual(report.risk_level, 'none')
        self.assertTrue(report.has_xframe_options)

    def test_analyze_vulnerable_page(self):
        """Test analysis of vulnerable page."""
        html = '''
        <html>
        <body>
            <button id="login" style="position: absolute; top: 100px; left: 100px; width: 100px; height: 40px;">
                Login
            </button>
            <iframe
                src="https://malicious.com/steal"
                style="position: absolute; top: 95px; left: 95px; width: 110px; height: 50px; opacity: 0; z-index: 9999;">
            </iframe>
        </body>
        </html>
        '''
        headers = {}  # No defenses
        metadata = {'url': 'https://gov.example.com'}

        report = self.analyzer.analyze_page(html, headers, metadata)

        self.assertTrue(report.vulnerable)
        self.assertIn(report.risk_level, ['medium', 'high', 'critical'])
        self.assertGreater(report.suspicious_frames, 0)
        self.assertFalse(report.has_xframe_options)

    def test_vulnerability_score_calculation(self):
        """Test vulnerability score calculation."""
        # Page with transparent cross-domain iframe + no defenses
        html = '''
        <html>
        <body>
            <iframe src="https://evil.com" style="opacity: 0;"></iframe>
        </body>
        </html>
        '''
        report = self.analyzer.analyze_page(html, {}, {'url': 'https://gov.example.com'})

        # Should have score >= 3 (suspicious frame + no defenses)
        self.assertGreaterEqual(report.vulnerability_score, 3)

    def test_report_to_csv_row(self):
        """Test report CSV export."""
        html = '<html><body><p>Test</p></body></html>'
        report = self.analyzer.analyze_page(html, {}, {'url': 'https://test.com'})

        csv_row = report.to_csv_row()

        self.assertIn('url', csv_row)
        self.assertIn('vulnerable', csv_row)
        self.assertIn('risk_level', csv_row)
        self.assertIsInstance(csv_row['vulnerable'], bool)


class TestWithRealFiles(unittest.TestCase):
    """Tests using the test HTML files."""

    @classmethod
    def setUpClass(cls):
        cls.test_dir = Path(__file__).parent / 'test_pages'
        cls.analyzer = ClickjackingAnalyzer()

    def _read_test_file(self, name):
        path = self.test_dir / name
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        return None

    def _read_headers_file(self, name):
        path = self.test_dir / name
        if path.exists():
            headers = {}
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
            return headers
        return {}

    def test_benign_page(self):
        """Test benign.html - should not be vulnerable."""
        html = self._read_test_file('benign.html')
        if html is None:
            self.skipTest("Test file not found")

        report = self.analyzer.analyze_page(html, {}, {'url': 'https://gov.example.com'})

        self.assertFalse(report.vulnerable)
        self.assertEqual(report.suspicious_frames, 0)

    def test_transparent_iframe(self):
        """Test transparent_iframe.html - should be vulnerable."""
        html = self._read_test_file('transparent_iframe.html')
        if html is None:
            self.skipTest("Test file not found")

        report = self.analyzer.analyze_page(html, {}, {'url': 'https://gov.example.com'})

        self.assertTrue(report.vulnerable)
        self.assertGreater(report.suspicious_frames, 0)
        self.assertGreater(report.transparent_frames, 0)
        self.assertGreater(report.cross_domain_frames, 0)

    def test_with_defenses(self):
        """Test with_defenses.html - should have defenses detected."""
        html = self._read_test_file('with_defenses.html')
        headers = self._read_headers_file('with_defenses.headers')
        if html is None:
            self.skipTest("Test file not found")

        report = self.analyzer.analyze_page(html, headers, {'url': 'https://gov.example.com'})

        self.assertTrue(report.has_xframe_options)
        self.assertTrue(report.has_csp_frame_ancestors)
        self.assertTrue(report.has_framebusting_js)
        self.assertEqual(report.defense_level, 'strong')

    def test_overlapping(self):
        """Test overlapping.html - should detect overlaps."""
        html = self._read_test_file('overlapping.html')
        if html is None:
            self.skipTest("Test file not found")

        report = self.analyzer.analyze_page(html, {}, {'url': 'https://gov.example.com'})

        self.assertTrue(report.vulnerable)
        self.assertGreater(report.suspicious_frames, 0)
        # Should find high-value targets (login, payment buttons)
        self.assertGreater(report.total_clickables, 0)


def run_tests():
    """Run all tests."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestFrameDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestOverlapChecker))
    suite.addTests(loader.loadTestsFromTestCase(TestDefenseDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestWithRealFiles))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
