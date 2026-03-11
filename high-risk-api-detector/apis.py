"""
Browser API pattern definitions for security and privacy risk detection.

Based on the cost-benefit analysis framework from:
  Snyder, Taylor & Kanich, "Most Websites Don't Need to Vibrate:
  A Cost-Benefit Approach to Improving Browser Security" (CCS 2017)

The paper evaluated 74 Web API standards, scoring each on CVE count,
implementation surface area, and actual usage benefit. APIs with high
risk scores and low utility are grouped here by category.

We also check HTTP headers (Permissions-Policy / Feature-Policy) separately,
since those reflect what the server is explicitly allowing or denying.
"""

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class APIPattern:
    id: str
    label: str
    category: str       # PRIVACY, SECURITY, FINGERPRINTING, SENSOR
    severity: str       # HIGH, MEDIUM, LOW
    patterns: List[str]
    description: str
    note: str = ''      # when it might be legitimate


# Compiled once at module load
@dataclass
class CompiledAPIPattern:
    meta: APIPattern
    compiled: List[re.Pattern]


API_PATTERNS = [
    # ── PRIVACY: location and identity leaks ──────────────────────────────────
    APIPattern(
        id='geolocation',
        label='Geolocation API',
        category='PRIVACY',
        severity='HIGH',
        patterns=[
            r'navigator\.geolocation\.getCurrentPosition\s*\(',
            r'navigator\.geolocation\.watchPosition\s*\(',
            r'navigator\.geolocation\.clearWatch\s*\(',
        ],
        description=(
            'Requests the user\'s physical location. Government service portals '
            'accessing citizen location data without clear need raises both privacy '
            'and consent concerns.'
        ),
        note='May be legitimate in emergency services, permit applications, or mapping portals.',
    ),

    # ── PRIVACY: real IP disclosure via WebRTC ─────────────────────────────────
    APIPattern(
        id='webrtc',
        label='WebRTC PeerConnection',
        category='PRIVACY',
        severity='HIGH',
        patterns=[
            r'new\s+RTCPeerConnection\s*\(',
            r'new\s+webkitRTCPeerConnection\s*\(',
            r'new\s+mozRTCPeerConnection\s*\(',
            r'RTCPeerConnection\s*\(',
        ],
        description=(
            'WebRTC peer connections trigger local network IP discovery, bypassing '
            'proxies and VPNs. A government site has almost no legitimate reason to '
            'initiate peer connections. Finding this is high priority for review.'
        ),
        note='Extremely rare legitimate use in government context.',
    ),

    # ── SECURITY: camera and microphone access ────────────────────────────────
    APIPattern(
        id='get_user_media',
        label='Camera / Microphone Access (getUserMedia)',
        category='SECURITY',
        severity='HIGH',
        patterns=[
            r'navigator\.mediaDevices\.getUserMedia\s*\(',
            r'navigator\.getUserMedia\s*\(',
            r'navigator\.webkitGetUserMedia\s*\(',
            r'navigator\.mozGetUserMedia\s*\(',
        ],
        description=(
            'Requests access to the device camera and/or microphone. This is '
            'occasionally used in KYC (Know Your Customer) flows on e-government '
            'portals for identity verification, but its presence is always worth '
            'auditing - particularly in older snapshots where user consent UX was weaker.'
        ),
        note='Legitimate in identity verification, video consultation portals.',
    ),

    # ── SECURITY: screen capture ──────────────────────────────────────────────
    APIPattern(
        id='screen_capture',
        label='Screen Capture API',
        category='SECURITY',
        severity='HIGH',
        patterns=[
            r'navigator\.mediaDevices\.getDisplayMedia\s*\(',
        ],
        description=(
            'Requests permission to capture the user\'s screen or a specific '
            'application window. No standard government portal use case requires this.'
        ),
        note='No typical legitimate use in government services.',
    ),

    # ── FINGERPRINTING: battery status ────────────────────────────────────────
    APIPattern(
        id='battery_status',
        label='Battery Status API',
        category='FINGERPRINTING',
        severity='MEDIUM',
        patterns=[
            r'navigator\.getBattery\s*\(',
            r'navigator\.battery\b',
            r'navigator\.mozBattery\b',
        ],
        description=(
            'The Battery Status API exposes device charge level and charging state, '
            'which can be used as a fingerprinting vector. It was removed from '
            'Firefox and Chrome after privacy research exposed the risk. Presence '
            'in older snapshots is historically interesting.'
        ),
        note='No legitimate use in government services. Now deprecated in most browsers.',
    ),

    # ── FINGERPRINTING/NUISANCE: vibration ───────────────────────────────────
    APIPattern(
        id='vibration',
        label='Vibration API',
        category='FINGERPRINTING',
        severity='MEDIUM',
        patterns=[
            r'navigator\.vibrate\s*\(',
        ],
        description=(
            'Namesake of the Snyder et al. paper. The Vibration API has essentially '
            'no legitimate use in government web portals and has been proposed as a '
            'fingerprinting vector. Its presence on a government site is anomalous.'
        ),
        note='No legitimate use in government services.',
    ),

    # ── SECURITY: push notifications ─────────────────────────────────────────
    APIPattern(
        id='notifications',
        label='Push Notifications',
        category='SECURITY',
        severity='MEDIUM',
        patterns=[
            r'Notification\.requestPermission\s*\(',
            r'Notification\.permission\b',
            r'self\.registration\.showNotification\s*\(',
            r'ServiceWorkerRegistration.*showNotification',
        ],
        description=(
            'The Notifications API requests permission to send push notifications. '
            'While some government portals use this legitimately for status updates, '
            'it is also a common vector in browser-based phishing and notification spam. '
            'Worth auditing whether the permission request is clearly explained to the user.'
        ),
        note='Legitimate in appointment systems, document status trackers.',
    ),

    # ── SECURITY: clipboard read ──────────────────────────────────────────────
    APIPattern(
        id='clipboard_read',
        label='Clipboard Read Access',
        category='SECURITY',
        severity='MEDIUM',
        patterns=[
            r'navigator\.clipboard\.readText\s*\(',
            r'navigator\.clipboard\.read\s*\(',
            r'document\.execCommand\s*\(\s*["\']paste["\']',
        ],
        description=(
            'Reading from the clipboard without a clear user action can silently '
            'capture passwords, IDs, or other sensitive data the user has copied. '
            'Clipboard write is low risk; clipboard read is the concern.'
        ),
        note='Legitimate in form auto-fill helpers if triggered explicitly.',
    ),

    # ── SENSOR: device motion and orientation ─────────────────────────────────
    APIPattern(
        id='device_sensors',
        label='Device Motion / Orientation Sensors',
        category='FINGERPRINTING',
        severity='LOW',
        patterns=[
            r'DeviceMotionEvent\b',
            r'DeviceOrientationEvent\b',
            r'window\.ondevicemotion\b',
            r'window\.ondeviceorientation\b',
        ],
        description=(
            'Motion and orientation sensor data can be used as a covert fingerprinting '
            'channel. Presence on a government site is unusual.'
        ),
        note='Occasionally used in accessibility features.',
    ),

    # ── SECURITY: Web Bluetooth ───────────────────────────────────────────────
    APIPattern(
        id='web_bluetooth',
        label='Web Bluetooth',
        category='SECURITY',
        severity='HIGH',
        patterns=[
            r'navigator\.bluetooth\.requestDevice\s*\(',
            r'navigator\.bluetooth\b',
        ],
        description=(
            'Web Bluetooth grants browser access to nearby Bluetooth devices. '
            'Completely out of place on a government web portal.'
        ),
        note='No legitimate use in government services.',
    ),

    # ── SECURITY: Payment Request API ────────────────────────────────────────
    APIPattern(
        id='payment_request',
        label='Payment Request API',
        category='SECURITY',
        severity='MEDIUM',
        patterns=[
            r'new\s+PaymentRequest\s*\(',
        ],
        description=(
            'The Payment Request API hooks into browser-stored payment methods. '
            'Government e-payment portals might use this legitimately, but its '
            'presence is worth verifying against the site\'s stated purpose.'
        ),
        note='Legitimate in government fee payment portals.',
    ),

    # ── SECURITY: SharedWorker (side-channel risk) ────────────────────────────
    APIPattern(
        id='shared_worker',
        label='SharedWorker',
        category='SECURITY',
        severity='LOW',
        patterns=[
            r'new\s+SharedWorker\s*\(',
        ],
        description=(
            'SharedWorkers persist across tabs and can be used as a communication '
            'channel or as a timing side-channel attack surface. Low frequency in '
            'government sites but worth noting.'
        ),
        note='Occasionally used in multi-tab session management.',
    ),
]

# Pre-compile all patterns
COMPILED_API_PATTERNS = [
    CompiledAPIPattern(
        meta=p,
        compiled=[re.compile(pat, re.IGNORECASE) for pat in p.patterns]
    )
    for p in API_PATTERNS
]

# ── Permissions-Policy / Feature-Policy header analysis ───────────────────────

# These map to the API IDs above where there's a direct correspondence
PERMISSIONS_POLICY_FEATURES = {
    'geolocation',
    'camera',
    'microphone',
    'display-capture',
    'notifications',
    'clipboard-read',
    'clipboard-write',
    'payment',
    'gyroscope',
    'accelerometer',
    'magnetometer',
    'vibrate',
    'battery',
    'bluetooth',
    'usb',
    'serial',
    'ambient-light-sensor',
    'autoplay',
    'fullscreen',
    'picture-in-picture',
    'web-share',
    'xr-spatial-tracking',
}

HEADER_NAMES = (
    # x-archive-orig-* first - these are the original site's headers,
    # not the Wayback Machine's own injected headers.
    # The archive injects `Permissions-Policy: interest-cohort=()` on every
    # response as their own FLoC opt-out - that is NOT the site's policy.
    'x-archive-orig-permissions-policy',
    'x-archive-orig-feature-policy',
    # Fall back to direct keys only as a secondary check
    'feature-policy',
)
