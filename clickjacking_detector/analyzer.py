"""
Clickjacking Analyzer Module

Main orchestration class that combines frame detection, overlap checking,
and defense detection to produce comprehensive vulnerability reports.
"""

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

from frame_detector import (
    analyze_frames,
    get_suspicious_frames,
    FrameElement
)
from overlap_checker import (
    extract_clickable_elements,
    find_overlapping_elements,
    analyze_potential_hijacking,
    get_z_index_analysis
)
from defense_detector import (
    analyze_defenses,
    get_defense_summary,
    get_defense_by_era,
    DefenseResult
)


class RiskLevel(Enum):
    """Risk level classification."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VulnerabilityReport:
    """Complete vulnerability analysis report."""
    # Metadata
    url: str
    timestamp: Optional[str] = None
    capture_date: Optional[str] = None
    analysis_date: str = field(default_factory=lambda: datetime.now().isoformat())

    # Frame analysis
    total_frames: int = 0
    transparent_frames: int = 0
    cross_domain_frames: int = 0
    suspicious_frames: int = 0

    # Overlap analysis
    total_clickables: int = 0
    overlapping_elements: int = 0
    high_value_targets_at_risk: int = 0

    # Defense analysis
    has_xframe_options: bool = False
    xframe_options_value: Optional[str] = None
    has_csp_frame_ancestors: bool = False
    has_framebusting_js: bool = False
    framebusting_patterns: List[str] = field(default_factory=list)
    defense_score: int = 0
    defense_level: str = "none"

    # Risk assessment
    vulnerability_score: int = 0
    risk_level: str = "none"
    vulnerable: bool = False

    # Detailed findings
    details: Dict[str, Any] = field(default_factory=dict)
    frame_details: List[Dict] = field(default_factory=list)
    overlap_details: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    def to_csv_row(self) -> Dict[str, Any]:
        """Get a flat dictionary suitable for CSV output."""
        return {
            'url': self.url,
            'timestamp': self.timestamp,
            'capture_date': self.capture_date,
            'analysis_date': self.analysis_date,
            'vulnerable': self.vulnerable,
            'risk_level': self.risk_level,
            'vulnerability_score': self.vulnerability_score,
            'total_frames': self.total_frames,
            'transparent_frames': self.transparent_frames,
            'cross_domain_frames': self.cross_domain_frames,
            'suspicious_frames': self.suspicious_frames,
            'overlapping_elements': self.overlapping_elements,
            'high_value_targets_at_risk': self.high_value_targets_at_risk,
            'has_xframe_options': self.has_xframe_options,
            'xframe_options_value': self.xframe_options_value,
            'has_csp_frame_ancestors': self.has_csp_frame_ancestors,
            'has_framebusting_js': self.has_framebusting_js,
            'framebusting_patterns_count': len(self.framebusting_patterns),
            'defense_score': self.defense_score,
            'defense_level': self.defense_level,
            'details': json.dumps(self.details) if self.details else ''
        }


class ClickjackingAnalyzer:
    """
    Main analyzer class for clickjacking vulnerability detection.

    Usage:
        analyzer = ClickjackingAnalyzer()
        report = analyzer.analyze_page(html_content, headers, metadata)
    """

    # Scoring weights
    SCORE_TRANSPARENT_CROSS_DOMAIN = 3
    SCORE_OVERLAPPING_ELEMENTS = 2
    SCORE_HIGH_VALUE_TARGET = 2
    SCORE_NO_DEFENSES = 1
    SCORE_WEAK_DEFENSES = 0.5

    # Risk level thresholds
    RISK_HIGH_THRESHOLD = 4
    RISK_MEDIUM_THRESHOLD = 2
    RISK_LOW_THRESHOLD = 1

    def __init__(self, strict_mode: bool = False):
        """
        Initialize analyzer.

        Args:
            strict_mode: If True, use stricter detection criteria
        """
        self.strict_mode = strict_mode

    def analyze_page(self,
                     html_content: str,
                     headers: Optional[Dict[str, str]] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> VulnerabilityReport:
        """
        Analyze a page for clickjacking vulnerabilities.

        Args:
            html_content: Raw HTML content of the page
            headers: HTTP headers dictionary (optional)
            metadata: Page metadata including url, timestamp, etc.

        Returns:
            VulnerabilityReport with complete analysis
        """
        headers = headers or {}
        metadata = metadata or {}

        # Extract metadata
        url = metadata.get('url', 'unknown')
        timestamp = metadata.get('timestamp')
        capture_date = metadata.get('capture_date')

        # Initialize report
        report = VulnerabilityReport(
            url=url,
            timestamp=timestamp,
            capture_date=capture_date
        )

        # 1. Analyze frames
        frames = analyze_frames(html_content, url)
        suspicious = get_suspicious_frames(frames)

        report.total_frames = len(frames)
        report.transparent_frames = len([f for f in frames if f.is_transparent])
        report.cross_domain_frames = len([f for f in frames if f.is_cross_domain])
        report.suspicious_frames = len(suspicious)

        # Store frame details
        report.frame_details = [
            {
                'src': f.src,
                'is_transparent': f.is_transparent,
                'is_cross_domain': f.is_cross_domain,
                'css_properties': f.css_properties
            }
            for f in frames
        ]

        # 2. Analyze overlaps (if suspicious frames exist)
        if suspicious:
            overlap_analysis = analyze_potential_hijacking(html_content, suspicious)
            report.total_clickables = overlap_analysis['total_clickables']
            report.overlapping_elements = overlap_analysis['total_overlaps']
            report.high_value_targets_at_risk = overlap_analysis['high_value_overlaps']

            # Store overlap details
            for overlap in overlap_analysis.get('overlaps', []):
                report.overlap_details.append({
                    'frame_src': overlap.frame.src,
                    'clickable_type': overlap.clickable.element_type,
                    'clickable_text': overlap.clickable.text_content,
                    'overlap_percentage': overlap.overlap_area
                })
        else:
            # Still count clickables for reporting
            clickables = extract_clickable_elements(html_content)
            report.total_clickables = len(clickables)

        # 3. Analyze defenses
        defense_result = analyze_defenses(headers, html_content)
        report.has_xframe_options = defense_result.has_xframe_options
        report.xframe_options_value = defense_result.xframe_options_value
        report.has_csp_frame_ancestors = defense_result.has_csp_frame_ancestors
        report.has_framebusting_js = defense_result.has_framebusting_js
        report.framebusting_patterns = defense_result.framebusting_patterns_found
        report.defense_score = defense_result.defense_score
        report.defense_level = defense_result.defense_level

        # 4. Calculate vulnerability score and risk level
        report.vulnerability_score = self.calculate_vulnerability_score(
            report, defense_result
        )
        report.risk_level = self.calculate_risk_level(report.vulnerability_score)
        report.vulnerable = report.risk_level in ('medium', 'high', 'critical')

        # 5. Add contextual details
        report.details = self._build_details(report, defense_result, metadata)

        return report

    def calculate_vulnerability_score(self,
                                      report: VulnerabilityReport,
                                      defense_result: DefenseResult) -> int:
        """
        Calculate vulnerability score based on findings.

        Score interpretation:
        - 0: No vulnerability indicators
        - 1-2: Low risk
        - 3-4: Medium risk
        - 5+: High risk

        Args:
            report: Partially filled vulnerability report
            defense_result: Defense analysis result

        Returns:
            Integer vulnerability score
        """
        score = 0

        # Suspicious frames (transparent + cross-domain)
        score += report.suspicious_frames * self.SCORE_TRANSPARENT_CROSS_DOMAIN

        # Overlapping elements
        score += min(report.overlapping_elements, 3) * self.SCORE_OVERLAPPING_ELEMENTS

        # High-value targets at risk
        score += min(report.high_value_targets_at_risk, 2) * self.SCORE_HIGH_VALUE_TARGET

        # Defense penalties (lack of defenses increases risk)
        if defense_result.defense_level == 'none':
            score += self.SCORE_NO_DEFENSES
        elif defense_result.defense_level == 'weak':
            score += self.SCORE_WEAK_DEFENSES

        # Defense bonuses (reduce score if defenses present)
        if defense_result.defense_level == 'strong':
            score = max(0, score - 2)
        elif defense_result.defense_level == 'moderate':
            score = max(0, score - 1)

        return int(score)

    def calculate_risk_level(self, score: int) -> str:
        """
        Convert vulnerability score to risk level.

        Args:
            score: Vulnerability score

        Returns:
            Risk level string
        """
        if score >= 6:
            return RiskLevel.CRITICAL.value
        elif score >= self.RISK_HIGH_THRESHOLD:
            return RiskLevel.HIGH.value
        elif score >= self.RISK_MEDIUM_THRESHOLD:
            return RiskLevel.MEDIUM.value
        elif score >= self.RISK_LOW_THRESHOLD:
            return RiskLevel.LOW.value
        else:
            return RiskLevel.NONE.value

    def _build_details(self,
                       report: VulnerabilityReport,
                       defense_result: DefenseResult,
                       metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Build detailed findings dictionary."""
        details = {
            'findings': [],
            'recommendations': [],
            'era_context': None
        }

        # Add findings
        if report.suspicious_frames > 0:
            details['findings'].append(
                f"Found {report.suspicious_frames} suspicious frame(s) "
                "(transparent and cross-domain)"
            )

        if report.overlapping_elements > 0:
            details['findings'].append(
                f"Found {report.overlapping_elements} potential click hijacking "
                "overlap(s) between frames and clickable elements"
            )

        if report.high_value_targets_at_risk > 0:
            details['findings'].append(
                f"Found {report.high_value_targets_at_risk} high-value targets "
                "(login, payment, etc.) potentially at risk"
            )

        if not report.has_xframe_options and not report.has_csp_frame_ancestors:
            details['findings'].append(
                "No HTTP header-based clickjacking defenses detected"
            )

        if report.has_framebusting_js:
            details['findings'].append(
                f"Frame-busting JavaScript detected with "
                f"{len(report.framebusting_patterns)} pattern(s)"
            )

        # Add recommendations
        if not report.has_xframe_options:
            details['recommendations'].append(
                "Add X-Frame-Options header with DENY or SAMEORIGIN value"
            )

        if not report.has_csp_frame_ancestors:
            details['recommendations'].append(
                "Add Content-Security-Policy with frame-ancestors directive"
            )

        if report.has_framebusting_js and not report.has_xframe_options:
            details['recommendations'].append(
                "Frame-busting JS alone is insufficient; add HTTP header defenses"
            )

        # Add historical context if we have a date
        if metadata.get('capture_date') or metadata.get('timestamp'):
            date_str = metadata.get('capture_date') or metadata.get('timestamp')
            try:
                # Try to extract year
                year = int(date_str[:4]) if date_str else None
                if year and 2000 <= year <= 2030:
                    details['era_context'] = get_defense_by_era(year)
            except (ValueError, TypeError):
                pass

        return details


class BatchAnalyzer:
    """
    Batch analysis of multiple pages for temporal studies.
    """

    def __init__(self, analyzer: Optional[ClickjackingAnalyzer] = None):
        """
        Initialize batch analyzer.

        Args:
            analyzer: ClickjackingAnalyzer instance (creates default if not provided)
        """
        self.analyzer = analyzer or ClickjackingAnalyzer()
        self.results: List[VulnerabilityReport] = []

    def analyze_batch(self,
                      pages: List[Dict[str, Any]]) -> List[VulnerabilityReport]:
        """
        Analyze multiple pages.

        Args:
            pages: List of dicts with keys: html_content, headers, metadata

        Returns:
            List of VulnerabilityReport objects
        """
        self.results = []

        for page in pages:
            try:
                report = self.analyzer.analyze_page(
                    html_content=page.get('html_content', ''),
                    headers=page.get('headers', {}),
                    metadata=page.get('metadata', {})
                )
                self.results.append(report)
            except Exception as e:
                # Create error report
                error_report = VulnerabilityReport(
                    url=page.get('metadata', {}).get('url', 'unknown'),
                    details={'error': str(e)}
                )
                self.results.append(error_report)

        return self.results

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics across all analyzed pages."""
        if not self.results:
            return {'total_pages': 0}

        vulnerable_count = sum(1 for r in self.results if r.vulnerable)
        risk_counts = {}
        for r in self.results:
            risk_counts[r.risk_level] = risk_counts.get(r.risk_level, 0) + 1

        defense_counts = {
            'xframe_options': sum(1 for r in self.results if r.has_xframe_options),
            'csp_frame_ancestors': sum(1 for r in self.results if r.has_csp_frame_ancestors),
            'framebusting_js': sum(1 for r in self.results if r.has_framebusting_js),
            'no_defenses': sum(1 for r in self.results if r.defense_level == 'none')
        }

        return {
            'total_pages': len(self.results),
            'vulnerable_pages': vulnerable_count,
            'vulnerability_rate': vulnerable_count / len(self.results) * 100,
            'risk_distribution': risk_counts,
            'defense_adoption': defense_counts,
            'avg_vulnerability_score': sum(r.vulnerability_score for r in self.results) / len(self.results),
            'pages_with_frames': sum(1 for r in self.results if r.total_frames > 0),
            'pages_with_suspicious_frames': sum(1 for r in self.results if r.suspicious_frames > 0)
        }

    def get_temporal_analysis(self) -> Dict[str, Any]:
        """
        Get temporal analysis grouped by year/period.
        Useful for longitudinal studies.
        """
        by_year = {}

        for report in self.results:
            # Extract year from capture_date or timestamp
            year = None
            date_str = report.capture_date or report.timestamp
            if date_str:
                try:
                    year = int(date_str[:4])
                except (ValueError, TypeError):
                    pass

            if year:
                if year not in by_year:
                    by_year[year] = []
                by_year[year].append(report)

        # Calculate statistics per year
        temporal_stats = {}
        for year, reports in sorted(by_year.items()):
            vulnerable = sum(1 for r in reports if r.vulnerable)
            with_defenses = sum(1 for r in reports if r.defense_level != 'none')

            temporal_stats[year] = {
                'total': len(reports),
                'vulnerable': vulnerable,
                'vulnerability_rate': vulnerable / len(reports) * 100 if reports else 0,
                'with_defenses': with_defenses,
                'defense_rate': with_defenses / len(reports) * 100 if reports else 0,
                'avg_score': sum(r.vulnerability_score for r in reports) / len(reports) if reports else 0
            }

        return temporal_stats
