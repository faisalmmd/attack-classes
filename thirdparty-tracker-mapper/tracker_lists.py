"""
Domain lists and inline pattern databases for third-party script classification.

Tracker domain lists are derived from:
  - EasyPrivacy (easylist.github.io)
  - Disconnect Me Tracker Protection (github.com/disconnectme/disconnect-tracking-protection)
  - uBlock Origin filter lists
  - Manual curation from Lerner et al. (USENIX Security 2016) findings
    which specifically studied Wayback Machine snapshots from 1996-2016

CDN domains are trusted hosting providers that are NOT analytics/ad trackers
but whose presence still matters for SRI and supply chain analysis.
"""

# ── Tracker domains ───────────────────────────────────────────────────────────
# Format: domain_suffix -> (category, canonical_name)
# Use suffix matching — 'google-analytics.com' matches 'www.google-analytics.com'

TRACKER_DOMAINS = {
    # Google Analytics / Tag Manager
    'google-analytics.com':         ('ANALYTICS', 'Google Analytics'),
    'googletagmanager.com':          ('ANALYTICS', 'Google Tag Manager'),
    'googletagservices.com':         ('ANALYTICS', 'Google Tag Services'),
    'ssl.google-analytics.com':      ('ANALYTICS', 'Google Analytics (SSL)'),

    # Google Advertising
    'doubleclick.net':               ('ADVERTISING', 'Google DoubleClick'),
    'googlesyndication.com':         ('ADVERTISING', 'Google AdSense'),
    'googleadservices.com':          ('ADVERTISING', 'Google Ad Services'),
    'google.com/ads':                ('ADVERTISING', 'Google Ads'),
    'pagead2.googlesyndication.com': ('ADVERTISING', 'Google AdSense Pagead'),

    # Google Other
    'apis.google.com':               ('SOCIAL', 'Google APIs (social/signin)'),
    'accounts.google.com':           ('SOCIAL', 'Google Sign-In'),

    # Facebook / Meta
    'connect.facebook.net':          ('SOCIAL', 'Facebook Connect'),
    'static.xx.fbcdn.net':           ('SOCIAL', 'Facebook CDN'),
    'graph.facebook.com':            ('SOCIAL', 'Facebook Graph API'),

    # Twitter / X
    'platform.twitter.com':          ('SOCIAL', 'Twitter Platform'),
    'static.ads-twitter.com':        ('ADVERTISING', 'Twitter Ads'),
    'syndication.twitter.com':       ('SOCIAL', 'Twitter Syndication'),

    # Adobe / Omniture
    'omtrdc.net':                    ('ANALYTICS', 'Adobe Analytics (Omniture)'),
    '2o7.net':                       ('ANALYTICS', 'Adobe Analytics (2o7)'),
    'demdex.net':                    ('ANALYTICS', 'Adobe Audience Manager'),
    'adobedtm.com':                  ('ANALYTICS', 'Adobe Dynamic Tag Mgmt'),
    'sc.omtrdc.net':                 ('ANALYTICS', 'Adobe Analytics SC'),

    # Scorecard Research / ComScore
    'scorecardresearch.com':         ('ANALYTICS', 'ComScore/Scorecard Research'),
    'beacon.scorecardresearch.com':  ('ANALYTICS', 'ComScore Beacon'),

    # Quantcast
    'quantserve.com':                ('ANALYTICS', 'Quantcast'),

    # Nielsen
    'mxptint.net':                   ('ANALYTICS', 'Nielsen NetRatings'),
    'imrworldwide.com':              ('ANALYTICS', 'Nielsen IAG'),

    # Hotjar
    'static.hotjar.com':             ('ANALYTICS', 'Hotjar'),

    # Intercom
    'widget.intercom.io':            ('SUPPORT', 'Intercom Widget'),
    'js.intercomcdn.com':            ('SUPPORT', 'Intercom CDN'),

    # Optimizely
    'cdn.optimizely.com':            ('ANALYTICS', 'Optimizely'),

    # Mixpanel
    'cdn.mxpnl.com':                 ('ANALYTICS', 'Mixpanel'),

    # Heap
    'cdn.heapanalytics.com':         ('ANALYTICS', 'Heap Analytics'),

    # Segment
    'cdn.segment.com':               ('ANALYTICS', 'Segment'),

    # New Relic
    'js-agent.newrelic.com':         ('ANALYTICS', 'New Relic Agent'),

    # Cloudflare Analytics (beacon, not CDN)
    'static.cloudflareinsights.com': ('ANALYTICS', 'Cloudflare Web Analytics'),

    # Yandex Metrica
    'mc.yandex.ru':                  ('ANALYTICS', 'Yandex Metrica'),
    'mc.yandex.com':                 ('ANALYTICS', 'Yandex Metrica'),

    # LinkedIn
    'snap.licdn.com':                ('ADVERTISING', 'LinkedIn Insight'),
    'platform.linkedin.com':         ('SOCIAL', 'LinkedIn Platform'),

    # Pinterest
    's.pinimg.com':                  ('SOCIAL', 'Pinterest'),

    # Bing / Microsoft Ads
    'bat.bing.com':                  ('ADVERTISING', 'Microsoft Clarity / Bing Ads'),
    'clarity.ms':                    ('ANALYTICS', 'Microsoft Clarity'),

    # Amazon
    'c.amazon-adsystem.com':         ('ADVERTISING', 'Amazon Ads'),

    # LiveRamp / IdentityLink
    'idsync.rlcdn.com':              ('ADVERTISING', 'LiveRamp/RealPage'),

    # Criteo
    'static.criteo.net':             ('ADVERTISING', 'Criteo'),

    # AddThis (Oracle)
    's7.addthis.com':                ('SOCIAL', 'AddThis (Oracle)'),
    'addthis.com':                   ('SOCIAL', 'AddThis (Oracle)'),

    # ShareThis
    'w.sharethis.com':               ('SOCIAL', 'ShareThis'),

    # Disqus
    'disqus.com':                    ('SOCIAL', 'Disqus'),

    # Recaptcha (often loaded, worth noting)
    'www.google.com/recaptcha':      ('SECURITY', 'Google reCAPTCHA'),
    'recaptcha.net':                 ('SECURITY', 'Google reCAPTCHA (recaptcha.net)'),
}

# ── CDN domains (trusted hosting, NOT analytics trackers) ─────────────────────
CDN_DOMAINS = {
    'cdnjs.cloudflare.com',
    'ajax.googleapis.com',
    'ajax.aspnetcdn.com',
    'ajax.microsoft.com',
    'code.jquery.com',
    'cdn.jsdelivr.net',
    'unpkg.com',
    'cdn.rawgit.com',
    'rawgit.com',
    'stackpath.bootstrapcdn.com',
    'maxcdn.bootstrapcdn.com',
    'netdna.bootstrapcdn.com',
    'use.fontawesome.com',
    'kit.fontawesome.com',
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'cdn.cloudflare.com',
    'static.cloudflare.com',
    'cdnjs.com',
    'yastatic.net',             # Yandex CDN (common in Eastern European gov sites)
    'cdnssb.yandex.net',
}

# ── Inline tracker call patterns ──────────────────────────────────────────────
# These are JavaScript API calls that indicate the tracker is loaded and active,
# even when the include itself might be missed (e.g., loaded via document.write).
INLINE_TRACKER_PATTERNS = [
    # Google Analytics (legacy ga.js)
    (r'_gaq\s*\.push\s*\(', 'Google Analytics (ga.js)'),
    # Google Analytics (analytics.js)
    (r"\bga\s*\(\s*['\"]create['\"]", 'Google Analytics (analytics.js)'),
    # Google Tag Manager / gtag.js
    (r'\bgtag\s*\(', 'Google Tag Manager / gtag.js'),
    (r'dataLayer\s*\.push\s*\(', 'Google Tag Manager (dataLayer)'),
    # Facebook Pixel
    (r"\bfbq\s*\(\s*['\"]init['\"]", 'Facebook Pixel'),
    (r'\bfbevents\.js\b', 'Facebook Pixel (fbevents)'),
    # Twitter Pixel
    (r"\btwq\s*\(\s*['\"]init['\"]", 'Twitter Pixel'),
    # LinkedIn Insight
    (r'_linkedin_data_partner_id', 'LinkedIn Insight Tag'),
    # Adobe Analytics
    (r's\.t\s*\(\s*\)', 'Adobe Analytics (s.t call)'),
    (r"_satellite\s*\.track\s*\(", 'Adobe Launch/DTM'),
    # Hotjar
    (r'\(function\s*\(\s*h\s*,\s*o\s*,\s*t\s*,\s*j\s*,\s*a\s*,\s*r\b', 'Hotjar Init'),
    # Intercom
    (r'\bIntercomSettings\b', 'Intercom'),
    # Mixpanel
    (r'\bmixpanel\.init\s*\(', 'Mixpanel'),
    # Heap
    (r'\bheap\.load\s*\(', 'Heap Analytics'),
    # Yandex Metrica
    (r'\bym\s*\(\s*\d+\s*,', 'Yandex Metrica'),
    (r'new\s+Ya\.Metrika\s*\(', 'Yandex Metrica'),
]

# ── Wayback Machine injected domains (exclude from analysis) ──────────────────
WAYBACK_DOMAINS = {
    'web.archive.org',
    'archive.org',
    'web-static.archive.org',
    'donate.archive.org',
}
