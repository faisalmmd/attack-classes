# High-Risk Browser API Detector

Scans archived JavaScript files and HTML inline scripts for browser APIs that carry elevated privacy or security risk. Also checks HTTP response headers for `Permissions-Policy` and `Feature-Policy` to see whether the server is actually restricting any of them.

## Background

Snyder, Taylor & Kanich's "Most Websites Don't Need to Vibrate: A Cost-Benefit Approach to Improving Browser Security" (CCS 2017) is where the framework comes from. They went through 74 Web API standards and scored each one on two axes - how much CVE surface area and attack risk it carries, and how many sites actually need it to function. The conclusion was that blocking just 15 of those 74 APIs would eliminate 52% of CVE-related browser code without breaking 94.7% of websites. The paper literally named itself after the Vibration API because it was the clearest example: high risk, zero legitimate use cases on the vast majority of sites.

Government web portals are an even more extreme version of that argument. A citizen-facing service portal has no business accessing your camera, broadcasting your real IP via WebRTC, or checking your battery level. When those APIs show up in archived government site code, the question isn't just "is this a vulnerability" - it's "why is this here, and what was it doing with that data."

The Permissions-Policy header (previously Feature-Policy) is the server-side mechanism for explicitly restricting which APIs the page is allowed to use. We track its adoption alongside the API usage findings. In our AE pilot, `Permissions-Policy` appeared on only a handful of sites - meaning most government sites that were using sensitive APIs had no server-side policy restricting them either.

## What it scans

| Source | Path |
|--------|------|
| Standalone JS files | `snapshot_js_data/{COUNTRY}/{domain}/*.js` |
| Inline `<script>` blocks | `snapshot_data/{COUNTRY}/{domain}/*_index_*.html` |
| HTTP response headers | `snapshot_data/{COUNTRY}/{domain}/*_headers_*.json` |

## Detected APIs

| API | Category | Severity | Government site concern |
|-----|----------|----------|------------------------|
| Geolocation | PRIVACY | HIGH | Location data collection without clear consent |
| WebRTC PeerConnection | PRIVACY | HIGH | Real IP disclosure, bypasses proxies/VPNs |
| getUserMedia (camera/mic) | SECURITY | HIGH | Media device access, should be rare |
| getDisplayMedia (screen capture) | SECURITY | HIGH | No typical gov use case |
| Battery Status API | FINGERPRINTING | MEDIUM | Deprecated fingerprinting vector |
| Vibration API | FINGERPRINTING | MEDIUM | No legitimate gov use case |
| Push Notifications | SECURITY | MEDIUM | Phishing vector if poorly explained |
| Clipboard Read | SECURITY | MEDIUM | Silent data capture risk |
| Device Motion/Orientation | FINGERPRINTING | LOW | Covert fingerprinting channel |
| Web Bluetooth | SECURITY | HIGH | Completely out of place |
| Payment Request API | SECURITY | MEDIUM | Worth verifying against site purpose |
| SharedWorker | SECURITY | LOW | Cross-tab side-channel surface |

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan one country
python main.py --country AE

# Scan all countries
python main.py --all

# Only privacy-related APIs
python main.py --all --category PRIVACY

# HIGH severity and above only
python main.py --all --severity HIGH

# Skip header policy check
python main.py --country DE --no-headers
```

## Output

Each run drops a timestamped directory under `results/` with:

| File | Contents |
|------|----------|
| `api_findings.csv` | One row per finding: country, domain, year, timestamp, API label, category, severity, line number, context snippet |
| `permissions_policy.csv` | One row per header file: whether a policy was found, which features it restricts, which sensitive features are NOT mentioned |
| `api_summary.json` | Aggregate counts by API, category, severity, year, country |

### `permissions_policy.csv` columns

```
country, domain, year, timestamp, header_found, header_name, raw_value,
features_restricted, features_unrestricted, is_restrictive
```

`features_unrestricted` lists sensitive APIs (geolocation, camera, microphone, etc.) that are NOT mentioned in the policy - meaning the server is not explicitly blocking them even if the code isn't using them.

## Research notes

The interesting finding from the AE pilot is where geolocation and getUserMedia turn up. Several sites use geolocation in mapping contexts, which is expected. But getUserMedia on a government service portal is harder to explain without looking at the specific page context - identity verification flows existed even in 2018-2019 for some e-government KYC implementations, so the year matters.

The Permissions-Policy adoption curve is almost flat in early years (the header didn't exist until 2020 under that name, and Feature-Policy before it had low adoption). Tracking when government sites started explicitly declaring API policies is a secondary finding worth including - it's a proxy for how security-aware the server configuration was.

Cross-referencing with the tracker mapper is also useful: sites that load analytics trackers AND use getUserMedia or geolocation are sending that sensitive data to third parties too, depending on how the tracker is configured.
