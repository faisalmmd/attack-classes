"""
Clickjacking Detection Tool

A Python tool for detecting clickjacking vulnerabilities in archived HTML files
using static analysis based on ASIACCS 2010 paper methodology.

Components:
    - frame_detector: Extract and analyze iframe/frame elements
    - overlap_checker: Detect overlapping clickable elements
    - defense_detector: Identify defense mechanisms (X-Frame-Options, CSP, JS)
    - analyzer: Main orchestration class
    - main: CLI interface

Usage:
    from clickjacking_detector import ClickjackingAnalyzer

    analyzer = ClickjackingAnalyzer()
    report = analyzer.analyze_page(html_content, headers, metadata)
"""

from analyzer import ClickjackingAnalyzer, BatchAnalyzer, VulnerabilityReport
from frame_detector import (
    analyze_frames,
    extract_frames,
    get_suspicious_frames,
    FrameElement
)
from overlap_checker import (
    extract_clickable_elements,
    find_overlapping_elements,
    ClickableElement
)
from defense_detector import (
    analyze_defenses,
    check_xframe_header,
    detect_framebusting_js,
    DefenseResult
)

__version__ = "1.0.0"
__author__ = "Clickjacking Research Team"

__all__ = [
    'ClickjackingAnalyzer',
    'BatchAnalyzer',
    'VulnerabilityReport',
    'analyze_frames',
    'extract_frames',
    'get_suspicious_frames',
    'FrameElement',
    'extract_clickable_elements',
    'find_overlapping_elements',
    'ClickableElement',
    'analyze_defenses',
    'check_xframe_header',
    'detect_framebusting_js',
    'DefenseResult',
]
