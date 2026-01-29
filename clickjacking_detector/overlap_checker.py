"""
Overlap Checker Module for Clickjacking Analysis

Extracts clickable elements from HTML and checks for potential
overlapping elements that could indicate clickjacking attempts.
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Tag
import cssutils
import logging

from frame_detector import (
    FrameElement,
    parse_inline_style,
    _parse_dimension,
    extract_stylesheet_rules,
    StyleRule
)

# Suppress cssutils warnings
cssutils.log.setLevel(logging.CRITICAL)


@dataclass
class ClickableElement:
    """Represents a clickable element in the page."""
    tag_name: str
    element_type: str  # 'link', 'button', 'input', 'embed', 'area', 'other'
    id: Optional[str] = None
    name: Optional[str] = None
    href: Optional[str] = None
    text_content: Optional[str] = None
    css_properties: Dict[str, Any] = field(default_factory=dict)
    bounding_box: Optional[Tuple[float, float, float, float]] = None  # x, y, width, height
    raw_element: Optional[str] = None


@dataclass
class OverlapResult:
    """Represents an overlap between a frame and a clickable element."""
    frame: FrameElement
    clickable: ClickableElement
    overlap_area: float  # Percentage of clickable element covered
    overlap_box: Optional[Tuple[float, float, float, float]] = None


# Elements that are inherently clickable
CLICKABLE_TAGS = {
    'a': 'link',
    'button': 'button',
    'input': 'input',
    'embed': 'embed',
    'object': 'embed',
    'area': 'area',
    'select': 'input',
    'textarea': 'input',
    'label': 'other',  # Can trigger associated input
}

# Input types that are clickable
CLICKABLE_INPUT_TYPES = {
    'submit', 'button', 'reset', 'checkbox', 'radio',
    'file', 'image', 'color', 'range'
}


def extract_clickable_elements(html_content: str) -> List[ClickableElement]:
    """
    Extract all clickable elements from HTML content.

    Args:
        html_content: Raw HTML string

    Returns:
        List of ClickableElement objects
    """
    soup = BeautifulSoup(html_content, 'lxml')
    clickables = []

    # Extract from known clickable tags
    for tag_name, element_type in CLICKABLE_TAGS.items():
        for tag in soup.find_all(tag_name):
            # Skip non-clickable input types
            if tag_name == 'input':
                input_type = (tag.get('type') or 'text').lower()
                if input_type not in CLICKABLE_INPUT_TYPES:
                    continue

            clickable = _create_clickable(tag, element_type)
            if clickable:
                clickables.append(clickable)

    # Find elements with onclick handlers
    for tag in soup.find_all(attrs={'onclick': True}):
        if tag.name not in CLICKABLE_TAGS:
            clickable = _create_clickable(tag, 'other')
            if clickable:
                clickables.append(clickable)

    # Find elements with cursor: pointer style (often clickable)
    for tag in soup.find_all(style=re.compile(r'cursor\s*:\s*pointer', re.I)):
        if tag.name not in CLICKABLE_TAGS and not tag.get('onclick'):
            clickable = _create_clickable(tag, 'other')
            if clickable:
                clickables.append(clickable)

    # Find elements with role="button" or role="link"
    for tag in soup.find_all(attrs={'role': re.compile(r'^(button|link)$', re.I)}):
        if tag.name not in CLICKABLE_TAGS:
            clickable = _create_clickable(tag, 'other')
            if clickable:
                clickables.append(clickable)

    return clickables


def _create_clickable(tag: Tag, element_type: str) -> Optional[ClickableElement]:
    """Create a ClickableElement from a BeautifulSoup tag."""
    # Get text content (truncated)
    text = tag.get_text(strip=True)[:100] if tag.get_text(strip=True) else None

    # Parse inline style
    style = tag.get('style')
    css_props = parse_inline_style(style) if style else {}

    # Calculate bounding box from attributes and CSS
    bbox = _calculate_element_bbox(tag, css_props)

    return ClickableElement(
        tag_name=tag.name,
        element_type=element_type,
        id=tag.get('id'),
        name=tag.get('name'),
        href=tag.get('href') if tag.name == 'a' else None,
        text_content=text,
        css_properties=css_props,
        bounding_box=bbox,
        raw_element=str(tag)[:300]
    )


def _calculate_element_bbox(tag: Tag, css_props: Dict[str, Any]) -> Optional[Tuple[float, float, float, float]]:
    """
    Estimate bounding box for a clickable element.
    This is an approximation since we can't render the page.
    """
    width = None
    height = None
    x = 0
    y = 0

    # Try CSS properties first
    if 'width' in css_props:
        width = _parse_dimension(css_props['width'])
    if 'height' in css_props:
        height = _parse_dimension(css_props['height'])
    if 'left' in css_props:
        x = _parse_dimension(css_props['left']) or 0
    if 'top' in css_props:
        y = _parse_dimension(css_props['top']) or 0

    # Try HTML attributes
    if width is None:
        attr_width = tag.get('width')
        if attr_width:
            width = _parse_dimension(attr_width)

    if height is None:
        attr_height = tag.get('height')
        if attr_height:
            height = _parse_dimension(attr_height)

    # Default dimensions based on element type
    if width is None:
        if tag.name in ('button', 'input'):
            width = 100  # Default button width
        elif tag.name == 'a':
            # Estimate based on text length
            text = tag.get_text(strip=True)
            width = len(text) * 8 if text else 50  # Rough character width

    if height is None:
        if tag.name in ('button', 'input', 'a'):
            height = 30  # Default clickable height

    if width is not None and height is not None:
        return (x, y, width, height)

    return None


def check_overlap(box1: Tuple[float, float, float, float],
                  box2: Tuple[float, float, float, float]) -> Tuple[bool, Optional[Tuple[float, float, float, float]], float]:
    """
    Check if two bounding boxes overlap.

    Args:
        box1: First bounding box (x, y, width, height)
        box2: Second bounding box (x, y, width, height)

    Returns:
        Tuple of (overlaps: bool, overlap_box: tuple or None, overlap_percentage: float)
    """
    x1, y1, w1, h1 = box1
    x2, y2, w2, h2 = box2

    # Calculate edges
    left1, right1 = x1, x1 + w1
    top1, bottom1 = y1, y1 + h1
    left2, right2 = x2, x2 + w2
    top2, bottom2 = y2, y2 + h2

    # Check for no overlap
    if left1 >= right2 or right1 <= left2:
        return False, None, 0.0
    if top1 >= bottom2 or bottom1 <= top2:
        return False, None, 0.0

    # Calculate overlap rectangle
    overlap_left = max(left1, left2)
    overlap_right = min(right1, right2)
    overlap_top = max(top1, top2)
    overlap_bottom = min(bottom1, bottom2)

    overlap_width = overlap_right - overlap_left
    overlap_height = overlap_bottom - overlap_top

    if overlap_width <= 0 or overlap_height <= 0:
        return False, None, 0.0

    overlap_box = (overlap_left, overlap_top, overlap_width, overlap_height)
    overlap_area = overlap_width * overlap_height

    # Calculate percentage of box2 that is covered
    box2_area = w2 * h2
    if box2_area > 0:
        overlap_percentage = (overlap_area / box2_area) * 100
    else:
        overlap_percentage = 0.0

    return True, overlap_box, overlap_percentage


def find_overlapping_elements(frames: List[FrameElement],
                              clickables: List[ClickableElement],
                              min_overlap_percent: float = 10.0) -> List[OverlapResult]:
    """
    Find all overlapping pairs between frames and clickable elements.

    Args:
        frames: List of FrameElement objects (typically suspicious frames)
        clickables: List of ClickableElement objects
        min_overlap_percent: Minimum overlap percentage to report

    Returns:
        List of OverlapResult objects
    """
    overlaps = []

    for frame in frames:
        if frame.bounding_box is None:
            continue

        for clickable in clickables:
            if clickable.bounding_box is None:
                continue

            has_overlap, overlap_box, overlap_pct = check_overlap(
                frame.bounding_box,
                clickable.bounding_box
            )

            if has_overlap and overlap_pct >= min_overlap_percent:
                overlaps.append(OverlapResult(
                    frame=frame,
                    clickable=clickable,
                    overlap_area=overlap_pct,
                    overlap_box=overlap_box
                ))

    return overlaps


def analyze_potential_hijacking(html_content: str,
                                suspicious_frames: List[FrameElement]) -> Dict[str, Any]:
    """
    Analyze potential clickjacking by finding clickable elements
    that could be hijacked by suspicious frames.

    Args:
        html_content: Raw HTML content
        suspicious_frames: List of suspicious (transparent, cross-domain) frames

    Returns:
        Analysis results dictionary
    """
    clickables = extract_clickable_elements(html_content)
    overlaps = find_overlapping_elements(suspicious_frames, clickables)

    # Categorize clickables by type
    clickable_by_type = {}
    for c in clickables:
        clickable_by_type.setdefault(c.element_type, []).append(c)

    # Find high-value targets (forms, login buttons, payment links)
    high_value_targets = []
    high_value_patterns = [
        r'login', r'sign.?in', r'submit', r'pay', r'checkout',
        r'confirm', r'delete', r'remove', r'approve', r'authorize',
        r'password', r'transfer', r'send'
    ]

    for clickable in clickables:
        # Check text content
        text = (clickable.text_content or '').lower()
        # Check href
        href = (clickable.href or '').lower()
        # Check id/name
        elem_id = (clickable.id or '').lower()
        elem_name = (clickable.name or '').lower()

        for pattern in high_value_patterns:
            if (re.search(pattern, text) or re.search(pattern, href) or
                    re.search(pattern, elem_id) or re.search(pattern, elem_name)):
                high_value_targets.append(clickable)
                break

    # Find overlaps with high-value targets
    high_value_overlaps = find_overlapping_elements(
        suspicious_frames,
        high_value_targets,
        min_overlap_percent=5.0  # Lower threshold for high-value targets
    )

    return {
        'total_clickables': len(clickables),
        'clickables_by_type': {k: len(v) for k, v in clickable_by_type.items()},
        'total_overlaps': len(overlaps),
        'overlaps': overlaps,
        'high_value_targets': len(high_value_targets),
        'high_value_overlaps': len(high_value_overlaps),
        'high_value_overlap_details': high_value_overlaps,
        'clickables': clickables
    }


def get_z_index_analysis(frames: List[FrameElement],
                         clickables: List[ClickableElement]) -> Dict[str, Any]:
    """
    Analyze z-index values to determine stacking order.
    Higher z-index elements appear on top.

    Args:
        frames: List of frame elements
        clickables: List of clickable elements

    Returns:
        Z-index analysis results
    """
    frame_zindexes = []
    clickable_zindexes = []

    for frame in frames:
        z = frame.css_properties.get('z-index')
        if z is not None:
            frame_zindexes.append((frame, z))

    for clickable in clickables:
        z = clickable.css_properties.get('z-index')
        if z is not None:
            try:
                clickable_zindexes.append((clickable, int(z)))
            except (ValueError, TypeError):
                pass

    # Find frames that appear above clickables
    frames_on_top = []
    if frame_zindexes and clickable_zindexes:
        max_clickable_z = max(z for _, z in clickable_zindexes)
        frames_on_top = [(f, z) for f, z in frame_zindexes
                         if isinstance(z, int) and z > max_clickable_z]

    return {
        'frames_with_zindex': len(frame_zindexes),
        'clickables_with_zindex': len(clickable_zindexes),
        'frames_on_top_count': len(frames_on_top),
        'frames_on_top': frames_on_top,
        'max_frame_zindex': max((z for _, z in frame_zindexes if isinstance(z, int)), default=None),
        'max_clickable_zindex': max((z for _, z in clickable_zindexes), default=None)
    }


# Convenience function
def quick_overlap_analysis(html_content: str,
                           suspicious_frames: List[FrameElement]) -> Dict[str, Any]:
    """
    Quick overlap analysis for suspicious frames.

    Args:
        html_content: Raw HTML content
        suspicious_frames: List of suspicious frames from frame_detector

    Returns:
        Summary of overlap analysis
    """
    result = analyze_potential_hijacking(html_content, suspicious_frames)

    return {
        'has_overlaps': result['total_overlaps'] > 0,
        'overlap_count': result['total_overlaps'],
        'high_value_at_risk': result['high_value_overlaps'] > 0,
        'high_value_overlap_count': result['high_value_overlaps'],
        'details': result
    }
