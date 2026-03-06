# Third-Party Tracker Mapper

Maps every external JavaScript inclusion in archived HTML snapshots and classifies each one - analytics tracker, advertising network, social widget, CDN, or unknown third-party. Also detects inline tracker API calls (Google Analytics initialization, Facebook Pixel, etc.) in `<script>` blocks.

## Why this exists

The foundational paper here is Nikiforakis et al., *"You Are What You Include: Large-Scale Evaluation of Remote JavaScript Inclusions"* (CCS 2012). It found that **88.45%** of the Alexa top 10,000 sites include at least one remote JS file, and mapped the trust chains that emerge - if you include a script from a CDN, and an attacker can register an expired domain that CDN depends on, you have an indirect code injection path. That paper established the threat model.

But the more directly relevant predecessor is Lerner et al., *"Internet Jones and the Raiders of the Lost Trackers: An Archaeological Study of Web Tracking from 1996 to 2016"* (USENIX Security 2016). **That paper also used the Wayback Machine on a longitudinal dataset**, which is almost exactly the setup here. They found that in the early 2000s only ~5% of sites contacted 5 or more third parties; by 2016, ~40% did. They traced the rise and fall of individual trackers - when Google Analytics replaced Urchin, when DoubleClick was absorbed into Google, when early behavioral trackers disappeared.

This tool does the same thing for government websites across 16 countries from 2003 to 2024. Government sites are a particularly interesting population because they have no legitimate advertising business model - any advertising tracker present is either a misconfiguration, an embedded widget from an external vendor, or a deliberate data-collection arrangement that the public doesn't know about.

## What it scans

HTML snapshots in `snapshot_data/{COUNTRY}/{domain}/*_index_*.html`.

For each page it extracts:
1. Every `<script src="...">` tag and resolves the URL (unwrapping Wayback's `web.archive.org/web/{timestamp}/...` rewriting)
2. Every inline `<script>` block, scanned for tracker initialization calls

## Classification scheme

| Class | Meaning |
|-------|---------|
| First-party | Same domain or subdomain as the page |
| CDN | Known trusted hosting CDN (jsDelivr, cdnjs, unpkg, Google Fonts CDN, etc.) |
| ANALYTICS | Analytics/measurement: Google Analytics, GTM, Adobe Analytics, Yandex Metrica, Hotjar, etc. |
| ADVERTISING | Ad networks: DoubleClick, AdSense, LinkedIn Insight, Criteo, etc. |
| SOCIAL | Social widgets: Facebook Connect, Twitter Platform, AddThis, ShareThis |
| SECURITY | Security-related services: Google reCAPTCHA |
| SUPPORT | Chat/support widgets: Intercom |
| Unknown 3rd party | Third-party but not in any known list |

Wayback Machine infrastructure domains are excluded from all classification - those are `archive.org`, `web-static.archive.org`, etc.

## Inline tracker detection

In addition to `<script src>` inclusions, the tool scans inline `<script>` content for API calls that indicate an active tracker, even when the inclusion itself may not be visible in the HTML (e.g., loaded dynamically). Detected patterns include:

- `_gaq.push(` - Google Analytics (legacy ga.js)
- `ga('create',` - Google Analytics (analytics.js)
- `gtag(` - Google Tag Manager / gtag.js
- `dataLayer.push(` - GTM data layer
- `fbq('init',` - Facebook Pixel
- `twq('init',` - Twitter Pixel
- `_linkedin_data_partner_id` - LinkedIn Insight Tag
- `ym(...)` / `new Ya.Metrika(` - Yandex Metrica
- And several others (see `tracker_lists.py`)

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Map one country
python main.py --country AE

# Map all countries
python main.py --all

# Only output tracker rows (filter out CDN and first-party)
python main.py --all --trackers-only

# Custom output path
python main.py --all --output /path/to/results
```

## Output

Each run creates a timestamped directory under `results/` with:

| File | Contents |
|------|----------|
| `script_inclusions.csv` | One row per `<script src>` tag: resolved URL, domain, classification, SRI presence |
| `inline_trackers.csv` | Inline API calls: tracker name, line number, source file |
| `tracker_prevalence.csv` | Longitudinal count table: year × tracker × occurrences × unique domains |
| `thirdparty_summary.csv` | Per year/country: % of pages with trackers, total inclusions |
| `thirdparty_overview.json` | Run metadata and top-level counts |

### `tracker_prevalence.csv` columns

```
year, tracker_name, category, occurrences, unique_domains, unique_countries
```

This is the primary table for longitudinal analysis - sort by `year` and you can see which trackers appeared when, and which disappeared (or were replaced).

### `script_inclusions.csv` selected columns

```
country, domain, year, timestamp, script_domain, protocol,
is_third_party, is_cdn, is_tracker, tracker_category, tracker_name,
has_integrity, crossorigin
```

The `has_integrity` column cross-references directly with the SRI scanner: a third-party tracker inclusion without an `integrity` attribute is an unverified remote code execution point.

## Research notes

The HTTP → HTTPS transition is visible in the `protocol` column. Scripts loaded over plain `http://` on an HTTPS page are mixed content - browsers began blocking this around 2015-2016. Tracking when government sites had active mixed-content script loads gives a concrete measure of how long they remained vulnerable after HTTPS was otherwise deployed.

The `tracker_prevalence.csv` output is designed to support a figure showing tracker adoption curves over time per country - something the Lerner et al. paper did for the broader web but has not been done specifically for government websites.
