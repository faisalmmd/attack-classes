# Cookie Attribute Auditor

Parses HTTP response headers from archived snapshots and audits every `Set-Cookie` header for the three security attributes that matter most: `HttpOnly`, `Secure`, and `SameSite`.

## Why this exists

Cookies are the most persistent attack surface in client-side web security. A session cookie missing `HttpOnly` is trivially stolen by any XSS vulnerability on the page. One missing `Secure` can be intercepted on any non-HTTPS path. And the absence of `SameSite` leaves the cookie exposed to Cross-Site Request Forgery - a class of attack that `SameSite=Lax` mostly eliminates for free.

The authoritative longitudinal measurement here is Khodayari & Pellegrino's *"The State of the SameSite"* (IEEE S&P 2022), which tracked `SameSite` adoption across the Alexa top 500K sites from 2019 to 2021 and found only **18.94%** had adopted any SameSite value. The theoretical basis for why these attributes matter comes from Barth, Jackson & Mitchell's *"Robust Defenses for Cross-Site Request Forgery"* (CCS 2008), which remains the canonical CSRF paper.

What neither of those studies covers is government websites across the Global South and developing economies over a 20-year window. That's this dataset. The trajectory from the pre-HTTPS era (pre-2015) through HSTS adoption and into the SameSite era (2020+) is visible in the archive, and this tool makes it measurable.

## What it reads

Header JSON files in `snapshot_data/{COUNTRY}/{domain}/*_headers_*.json`.

The Wayback Machine stores the original site's response headers with an `x-archive-orig-` prefix. The auditor strips this prefix when present to reconstruct the real response, so the analysis reflects what the actual website was sending - not the archive wrapper.

## Risk flags

Each cookie is checked against these conditions:

| Flag | Meaning |
|------|---------|
| `NO_SECURE` | `Secure` attribute absent - cookie travels over HTTP |
| `NO_HTTPONLY_SESSION` | `HttpOnly` absent on a session/auth-named cookie |
| `NO_HTTPONLY` | `HttpOnly` absent on any cookie |
| `NO_SAMESITE` | No `SameSite` attribute at all |
| `SAMESITE_NONE` | `SameSite=None` - explicit CSRF protection opt-out |
| `SAMESITE_NONE_WITHOUT_SECURE` | Invalid per RFC 6265bis, indicates misconfiguration |

Session-like cookies are identified by name matching common patterns: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `session`, `auth`, `token`, `jwt`, `userid`, `remember_me`, and variants. These are flagged separately because the consequences of stealing them are higher than stealing a preferences cookie.

## Install

No third-party dependencies - pure stdlib.

```bash
# No installation needed beyond Python 3.6+
python main.py --help
```

## Usage

```bash
# Audit one country
python main.py --country AE

# Audit everything
python main.py --all

# Show only session cookies missing HttpOnly
python main.py --all --risk NO_HTTPONLY_SESSION

# Custom output path
python main.py --all --output /path/to/results
```

## Output

Each run creates a timestamped directory under `results/` with:

| File | Contents |
|------|----------|
| `cookie_findings.csv` | One row per cookie: name, flags present/absent, risk flags, provenance |
| `adoption_over_time.csv` | Per year/country: totals and percentages for each attribute |
| `cookie_summary.json` | Run metadata and counts |

### `adoption_over_time.csv` columns

```
year, country, total_cookies, with_httponly, with_secure, with_samesite,
pct_httponly, pct_secure, pct_samesite,
samesite_strict, samesite_lax, samesite_none,
session_cookies, session_no_httponly
```

This table is designed to feed directly into a longitudinal plot - one line per country showing how `HttpOnly`, `Secure`, and `SameSite` adoption rates changed from 2003 to 2024.

## Research notes

The Khodayari & Pellegrino study found that even by 2021, `SameSite` adoption was low and `SameSite=None` (the most permissive value) was used by 3.7% of all cookies - often as a deliberate opt-out for cross-site embeds. Government sites are generally not building cross-site embeds that require `SameSite=None`, so any occurrence in this dataset is worth flagging.

The `Secure` attribute adoption curve is interesting to correlate with HTTPS rollout timelines. Many government sites in this dataset moved to HTTPS between 2016 and 2020, and you'd expect `Secure` adoption to lag that transition by a year or two as developers updated their cookie configuration. The archive gives you the data to verify or refute that.
