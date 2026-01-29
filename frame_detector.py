"""
Frame Detector Module for Clickjacking Analysis

Detects and analyzes iframe/frame elements in HTML content,
extracting CSS properties to identify potentially malicious
transparent or hidden frames.
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Tag
import tldextract
import cssutils
import logging

# Suppress cssutils warnings
cssutils.log.setLevel(logging.CRITICAL)


@dataclass
class FrameElement:
    """Represents an iframe or frame element with its properties."""
    tag_name: str  # 'iframe' or 'frame'
    src: Optional[str] = None
    name: Optional[str] = None
    id: Optional[str] = None
    classes: List[str] = field(default_factory=list)  # CSS classes
    css_properties: Dict[str, Any] = field(default_factory=dict)
    inline_style: Optional[str] = None
    bounding_box: Optional[Tuple[float, float, float, float]] = None  # x, y, width, height
    is_transparent: bool = False
    is_cross_domain: bool = False
    raw_element: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class StyleRule:
    """Represents a CSS style rule."""
    selector: str
    properties: Dict[str, str]


def extract_frames(html_content: str) -> List[FrameElement]:
    """
    Extract all iframe and frame elements from HTML content.

    Args:
        html_content: Raw HTML string

    Returns:
        List of FrameElement objects with basic attributes
    """
    soup = BeautifulSoup(html_content, 'lxml')
    frames = []

    # Find all iframe and frame elements
    for tag in soup.find_all(['iframe', 'frame']):
        # Extract class attribute (can be string or list)
        class_attr = tag.get('class', [])
        if isinstance(class_attr, str):
            classes = class_attr.split()
        else:
            classes = class_attr if class_attr else []

        frame = FrameElement(
            tag_name=tag.name,
            src=tag.get('src'),
            name=tag.get('name'),
            id=tag.get('id'),
            classes=classes,
            inline_style=tag.get('style'),
            raw_element=str(tag)[:500]  # Truncate for storage
        )

        # Extract inline CSS properties
        if frame.inline_style:
            frame.css_properties = parse_inline_style(frame.inline_style)

        # Extract dimension attributes (legacy HTML attributes)
        width = tag.get('width')
        height = tag.get('height')
        if width or height:
            frame.css_properties['attr_width'] = width
            frame.css_properties['attr_height'] = height

        # Check for frameborder attribute (often set to 0 for hidden frames)
        frameborder = tag.get('frameborder')
        if frameborder:
            frame.css_properties['frameborder'] = frameborder

        # Check for scrolling attribute
        scrolling = tag.get('scrolling')
        if scrolling:
            frame.css_properties['scrolling'] = scrolling

        frames.append(frame)

    return frames


def parse_inline_style(style_string: str) -> Dict[str, str]:
    """
    Parse inline CSS style string into a dictionary.

    Args:
        style_string: CSS style attribute value

    Returns:
        Dictionary of property: value pairs
    """
    properties = {}

    if not style_string:
        return properties

    # Clean up the style string
    style_string = style_string.strip()

    # Parse using cssutils for robust handling
    try:
        style = cssutils.parseStyle(style_string)
        for prop in style:
            properties[prop.name] = prop.value
    except Exception:
        # Fallback to regex parsing if cssutils fails
        pattern = r'([a-zA-Z-]+)\s*:\s*([^;]+)'
        matches = re.findall(pattern, style_string)
        for name, value in matches:
            properties[name.strip().lower()] = value.strip()

    return properties


def extract_stylesheet_rules(html_content: str) -> List[StyleRule]:
    """
    Extract CSS rules from <style> tags and inline stylesheets.

    Args:
        html_content: Raw HTML string

    Returns:
        List of StyleRule objects
    """
    soup = BeautifulSoup(html_content, 'lxml')
    rules = []

    for style_tag in soup.find_all('style'):
        css_text = style_tag.get_text()
        try:
            sheet = cssutils.parseString(css_text)
            for rule in sheet:
                if hasattr(rule, 'selectorText') and hasattr(rule, 'style'):
                    props = {}
                    for prop in rule.style:
                        props[prop.name] = prop.value
                    rules.append(StyleRule(
                        selector=rule.selectorText,
                        properties=props
                    ))
        except Exception:
            # Skip unparseable stylesheets
            continue

    return rules


def get_css_properties(frame: FrameElement, stylesheet_rules: List[StyleRule] = None) -> Dict[str, Any]:
    """
    Get computed CSS properties for a frame element.
    Combines inline styles with stylesheet rules.

    Args:
        frame: FrameElement to analyze
        stylesheet_rules: Optional list of stylesheet rules to apply

    Returns:
        Dictionary of CSS properties with parsed values
    """
    properties = dict(frame.css_properties)

    # Apply stylesheet rules if provided
    if stylesheet_rules:
        for rule in stylesheet_rules:
            # Check if selector matches this frame
            if _selector_matches(rule.selector, frame):
                # Stylesheet rules have lower specificity than inline
                for prop, value in rule.properties.items():
                    if prop not in properties:
                        properties[prop] = value

    # Normalize and parse specific properties
    normalized = {}

    # Opacity
    if 'opacity' in properties:
        normalized['opacity'] = _parse_opacity(properties['opacity'])
    elif 'filter' in properties:
        # Check for IE alpha filter
        alpha = _parse_alpha_filter(properties['filter'])
        if alpha is not None:
            normalized['opacity'] = alpha

    # Z-index
    if 'z-index' in properties:
        normalized['z-index'] = _parse_zindex(properties['z-index'])

    # Position
    normalized['position'] = properties.get('position', 'static')

    # Dimensions
    for dim in ['width', 'height', 'top', 'left', 'right', 'bottom']:
        if dim in properties:
            normalized[dim] = properties[dim]

    # Visibility
    normalized['visibility'] = properties.get('visibility', 'visible')
    normalized['display'] = properties.get('display', 'inline')

    # Pointer events (modern technique to make frames click-through)
    if 'pointer-events' in properties:
        normalized['pointer-events'] = properties['pointer-events']

    return normalized


def _selector_matches(selector: str, frame: FrameElement) -> bool:
    """
    Check if a CSS selector matches a frame element.
    Simplified matching for common selector patterns.
    """
    selector = selector.strip().lower()

    # Tag selector
    if selector == frame.tag_name:
        return True

    # ID selector
    if selector.startswith('#') and frame.id:
        if selector[1:] == frame.id.lower():
            return True

    # Class selector
    if selector.startswith('.') and frame.classes:
        class_name = selector[1:]
        # Handle compound selectors like .class1.class2
        if '.' in class_name:
            required_classes = class_name.split('.')
            frame_classes_lower = [c.lower() for c in frame.classes]
            if all(rc in frame_classes_lower for rc in required_classes if rc):
                return True
        else:
            if class_name in [c.lower() for c in frame.classes]:
                return True

    # Tag + class selector (e.g., iframe.hidden)
    if '.' in selector and not selector.startswith('.'):
        parts = selector.split('.', 1)
        tag_part = parts[0]
        class_part = parts[1] if len(parts) > 1 else ''
        if tag_part == frame.tag_name and class_part in [c.lower() for c in frame.classes]:
            return True

    # Name attribute selector
    if f'[name="{frame.name}"]' in selector.lower() if frame.name else False:
        return True

    return False


def _parse_opacity(value: str) -> float:
    """Parse opacity value to float."""
    try:
        value = value.strip().lower()
        # Handle percentage
        if value.endswith('%'):
            return float(value[:-1]) / 100.0
        return float(value)
    except (ValueError, AttributeError):
        return 1.0  # Default to fully visible


def _parse_alpha_filter(filter_value: str) -> Optional[float]:
    """
    Parse IE alpha filter to extract opacity value.
    Example: filter: alpha(opacity=0)
    """
    if not filter_value:
        return None

    match = re.search(r'alpha\s*\(\s*opacity\s*=\s*(\d+(?:\.\d+)?)\s*\)',
                      filter_value, re.IGNORECASE)
    if match:
        return float(match.group(1)) / 100.0

    return None


def _parse_zindex(value: str) -> Optional[int]:
    """Parse z-index value to integer."""
    try:
        value = value.strip().lower()
        if value == 'auto':
            return None
        return int(value)
    except (ValueError, AttributeError):
        return None


def is_transparent(css_props: Dict[str, Any], threshold: float = 0.1) -> bool:
    """
    Determine if a frame is effectively transparent/invisible.

    Args:
        css_props: Dictionary of CSS properties
        threshold: Opacity threshold below which element is considered transparent

    Returns:
        True if the frame is transparent/hidden
    """
    # Check opacity
    opacity = css_props.get('opacity')
    if opacity is not None and opacity < threshold:
        return True

    # Check visibility
    if css_props.get('visibility') == 'hidden':
        return True

    # Check display
    if css_props.get('display') == 'none':
        return True

    # Check for zero dimensions
    width = css_props.get('width', '')
    height = css_props.get('height', '')
    if width == '0' or width == '0px' or height == '0' or height == '0px':
        return True

    # Check for negative positioning (off-screen)
    for prop in ['left', 'top']:
        value = css_props.get(prop, '')
        if isinstance(value, str) and value.startswith('-') and 'px' in value:
            try:
                num = int(re.search(r'-(\d+)', value).group(1))
                if num > 1000:  # Significantly off-screen
                    return True
            except (AttributeError, ValueError):
                pass

    return False


def is_cross_domain(frame_src: Optional[str], page_url: str) -> bool:
    """
    Determine if a frame source is from a different domain than the page.

    Args:
        frame_src: The src attribute of the frame
        page_url: The URL of the page containing the frame

    Returns:
        True if the frame is cross-domain
    """
    if not frame_src:
        return False

    # Handle data: and javascript: URLs
    if frame_src.startswith(('data:', 'javascript:', 'about:')):
        return False

    # Handle relative URLs
    if not frame_src.startswith(('http://', 'https://', '//')):
        return False  # Relative URL = same domain

    # Handle protocol-relative URLs
    if frame_src.startswith('//'):
        frame_src = 'https:' + frame_src

    try:
        # Extract registered domains for comparison
        page_extract = tldextract.extract(page_url)
        frame_extract = tldextract.extract(frame_src)

        page_domain = f"{page_extract.domain}.{page_extract.suffix}".lower()
        frame_domain = f"{frame_extract.domain}.{frame_extract.suffix}".lower()

        return page_domain != frame_domain
    except Exception:
        # If parsing fails, be conservative
        return True


def calculate_bounding_box(element: Tag, css_props: Dict[str, Any] = None) -> Optional[Tuple[float, float, float, float]]:
    """
    Calculate the bounding box of an element based on CSS properties and attributes.
    Note: This is an approximation since we can't render the page.

    Args:
        element: BeautifulSoup Tag element
        css_props: Dictionary of CSS properties

    Returns:
        Tuple of (x, y, width, height) or None if cannot be determined
    """
    css_props = css_props or {}

    # Try to extract dimensions from various sources
    width = None
    height = None
    x = 0
    y = 0

    # Check CSS properties
    if 'width' in css_props:
        width = _parse_dimension(css_props['width'])
    if 'height' in css_props:
        height = _parse_dimension(css_props['height'])
    if 'left' in css_props:
        x = _parse_dimension(css_props['left']) or 0
    if 'top' in css_props:
        y = _parse_dimension(css_props['top']) or 0

    # Check HTML attributes as fallback
    if width is None and hasattr(element, 'get'):
        attr_width = element.get('width')
        if attr_width:
            width = _parse_dimension(attr_width)

    if height is None and hasattr(element, 'get'):
        attr_height = element.get('height')
        if attr_height:
            height = _parse_dimension(attr_height)

    # If we have dimensions, return bounding box
    if width is not None and height is not None:
        return (x, y, width, height)

    return None


def _parse_dimension(value: str) -> Optional[float]:
    """Parse a CSS dimension value to pixels (approximate)."""
    if value is None:
        return None

    value = str(value).strip().lower()

    # Handle percentage (approximate as 100% = 1000px for analysis)
    if value.endswith('%'):
        try:
            return float(value[:-1]) * 10  # Rough approximation
        except ValueError:
            return None

    # Handle pixel values
    if value.endswith('px'):
        try:
            return float(value[:-2])
        except ValueError:
            return None

    # Handle em/rem (approximate as 16px per em)
    if value.endswith('em') or value.endswith('rem'):
        try:
            return float(value[:-2 if value.endswith('em') else -3]) * 16
        except ValueError:
            return None

    # Handle plain numbers
    try:
        return float(value)
    except ValueError:
        return None


def analyze_frames(html_content: str, page_url: str) -> List[FrameElement]:
    """
    Complete frame analysis: extract frames and analyze their properties.

    Args:
        html_content: Raw HTML content
        page_url: URL of the page being analyzed

    Returns:
        List of FrameElement objects with full analysis
    """
    # Extract stylesheet rules
    stylesheet_rules = extract_stylesheet_rules(html_content)

    # Extract frames
    frames = extract_frames(html_content)

    # Analyze each frame
    soup = BeautifulSoup(html_content, 'lxml')

    for frame in frames:
        # Get computed CSS properties
        css_props = get_css_properties(frame, stylesheet_rules)
        frame.css_properties = css_props

        # Check transparency
        frame.is_transparent = is_transparent(css_props)

        # Check cross-domain
        frame.is_cross_domain = is_cross_domain(frame.src, page_url)

        # Calculate bounding box
        # Find the actual element again to get attributes
        if frame.id:
            elem = soup.find(id=frame.id)
        elif frame.name:
            elem = soup.find(attrs={'name': frame.name})
        else:
            elem = None

        if elem:
            frame.bounding_box = calculate_bounding_box(elem, css_props)

    return frames


def get_suspicious_frames(frames: List[FrameElement]) -> List[FrameElement]:
    """
    Filter frames to return only those that are suspicious.
    A frame is suspicious if it's transparent AND cross-domain.

    Args:
        frames: List of analyzed FrameElement objects

    Returns:
        List of suspicious frames
    """
    return [f for f in frames if f.is_transparent and f.is_cross_domain]


# Convenience function for quick analysis
def quick_analyze(html_content: str, page_url: str = "http://example.com") -> Dict[str, Any]:
    """
    Quick analysis returning a summary dictionary.

    Args:
        html_content: Raw HTML content
        page_url: URL of the page

    Returns:
        Summary dictionary with frame analysis results
    """
    frames = analyze_frames(html_content, page_url)
    suspicious = get_suspicious_frames(frames)

    return {
        'total_frames': len(frames),
        'transparent_frames': len([f for f in frames if f.is_transparent]),
        'cross_domain_frames': len([f for f in frames if f.is_cross_domain]),
        'suspicious_frames': len(suspicious),
        'frames': frames,
        'suspicious': suspicious
    }
