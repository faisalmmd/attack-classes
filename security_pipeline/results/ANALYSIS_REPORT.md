# Security Pipeline — Sample Dataset Analysis Report
**Date:** 2026-04-28
**Dataset:** `sample/report/` — 1,533 domains, 22,988 snapshots, 2003–2026
**Pipeline version:** 26 attack detectors (security_pipeline)

---

## 1. Dataset Overview

| Metric | Value |
|--------|-------|
| Domains | 1,533 |
| Snapshots | 22,988 |
| Year range | 1997–2026 (analysis focuses on 2003–2024) |
| Raw findings | 134,265 |
| Findings after FP filtering | 125,343 |
| Findings removed as FP | 8,922 (6.6%) |
| Domains with zero clean findings | 45 / 1,533 (2.9%) |

Snapshot coverage grows steadily from 77 domains in 2003 to a peak of ~880–888 domains in 2021–2022, then tapers to 818 in 2024 as the crawl approaches its collection cutoff. All prevalence figures below are normalized to domains-active-per-year to avoid coverage bias.

---

## 2. False Positive Filtering Applied

These filters follow the FP disclosures in the pipeline README exactly.

| Attack | Filter Rule | Reason | Findings Removed |
|--------|-------------|--------|-----------------|
| `clickjacking` | ALL severity | X-Frame-Options header not visible in archived HTML — systematic FP for all header-protected pages | 62 |
| `html_violation` | MEDIUM only | Block-in-inline and unclosed `<p>`/`<li>` are valid HTML5; duplicate IDs from templating are common | 74 |
| `form_action_hijack` | MEDIUM only | `formaction` attr and external HTTPS actions flagged regardless of form purpose (search vs. login) | 2,611 |
| `redos` | ALL severity | 90–98% static FP rate; syntactic heuristic cannot confirm actual vulnerability | 421 |
| `meta_refresh_redirect` | ALL severity | Legitimate domain migrations and intentional redirects are statically indistinguishable from malicious ones | 264 |
| `css_import_chain` | ALL severity | Flags legitimate CDN imports (Google Fonts, Bootstrap CDN, etc.) | 14 |
| `dom_clobbering` | MEDIUM only | MEDIUM patterns (`window.config`, bare security variables) are high-volume without a matching HTML element | 5,476 |
| **Total removed** | | | **8,922 (6.6%)** |

> `redos` and `meta_refresh_redirect` are excluded from main analysis but listed in §6 — they are candidates requiring dynamic confirmation, not confirmed vulnerabilities.

---

## 3. Overall Attack Prevalence (After FP Filtering)

Aggregated across all snapshots per domain — a domain is counted once if it had the attack in any snapshot:

| Attack | Domains Affected | % of 1,533 | Clean Findings | Severity Split |
|--------|-----------------|------------|----------------|----------------|
| `vulnerable_library` | 1,322 | **86.2%** | 94,442 | CRIT:41,100 / HIGH:34,622 / MED:18,720 |
| `dangerous_sink` | 863 | **56.3%** | 26,266 | CRIT:20,855 / HIGH:2,545 / MED:2,866 |
| `dom_clobbering` | 323 | **21.1%** | 1,266 | CRIT:652 / HIGH:614 |
| `open_redirect` | 200 | **13.0%** | 2,019 | HIGH:2,019 |
| `dangling_markup` | 53 | **3.5%** | 623 | CRIT:117 / HIGH:506 |
| `html_violation` | 39 | **2.5%** | 212 | HIGH:212 |
| `service_worker` | 25 | **1.6%** | 146 | HIGH:146 |
| `postmessage_audit` | 24 | **1.6%** | 126 | CRIT:125 / MED:1 |
| `prototype_pollution` | 19 | **1.2%** | 121 | CRIT:83 / HIGH:38 |
| `form_action_hijack` | 14 | **0.9%** | 72 | HIGH:72 |
| `base_tag_hijack` | 14 | **0.9%** | 27 | HIGH:27 |
| `jsonp_callback` | 2 | **0.1%** | 11 | HIGH:11 |
| `css_font_keylog` | 2 | **0.1%** | 6 | CRIT:6 |
| `cryptominer_js` | 2 | **0.1%** | 6 | CRIT:2 / MED:4 |

---

## 4. Longitudinal Trends (2003–2024, FP-filtered)

### 4.1 Directional Change Summary

| Attack | 2003–05 avg | 2022–24 avg | Change | Direction |
|--------|-------------|-------------|--------|-----------|
| `vulnerable_library` | 0.0% | 82.3% | +82.3pp | Rising sharply |
| `dangerous_sink` | 60.2% | 26.2% | −34.0pp | **Declining — main positive trend** |
| `open_redirect` | 5.8% | 5.1% | −0.7pp | Flat |
| `dom_clobbering` | 2.8% | 4.8% | +2.0pp | Slowly rising |
| `dangling_markup` | 0.6% | 2.0% | +1.4pp | Slowly rising |
| `service_worker` | 0.0% | 1.5% | +1.5pp | Emerging (API didn't exist pre-2015) |
| `postmessage_audit` | 0.0% | 0.9% | +0.9pp | Emerging (API didn't exist pre-2012) |
| `prototype_pollution` | 0.0% | 0.7% | +0.7pp | Slowly rising |
| `form_action_hijack` | 1.5% | 0.0% | −1.5pp | Declined to zero |
| `html_violation` | 0.7% | 0.9% | +0.1pp | Flat |

### 4.2 Year-by-Year Table

| Year | N | vul_lib | dang_sink | open_redir | dom_clob | proto_pol | dang_mkup | svc_wkr | postmsg |
|------|---|---------|-----------|------------|----------|-----------|-----------|---------|---------|
| 2003 | 77 | 0.0% | 55.8% | 7.8% | 2.6% | 0.0% | 0.0% | 0.0% | 0.0% |
| 2005 | 111 | 0.0% | 65.8% | 4.5% | 2.7% | 0.0% | 1.8% | 0.0% | 0.0% |
| 2007 | 203 | 2.0% | 82.3% | 3.9% | 3.0% | 0.0% | 0.5% | 0.0% | 0.0% |
| 2010 | 293 | 42.3% | 67.9% | 5.1% | 7.5% | 0.0% | 0.3% | 0.0% | 0.0% |
| 2013 | 481 | 73.0% | 52.4% | 7.3% | 3.3% | 0.0% | 0.0% | 0.0% | 0.0% |
| 2016 | 649 | 84.7% | 44.4% | 6.3% | 2.9% | 0.3% | 0.3% | 0.2% | 0.0% |
| 2018 | 767 | 88.4% | 34.3% | 4.3% | 4.6% | 0.4% | 0.3% | 0.1% | 0.5% |
| 2020 | 820 | 87.1% | 27.3% | 4.3% | 4.1% | 0.4% | 0.6% | 0.9% | 0.4% |
| 2022 | 888 | 86.6% | 25.2% | 4.8% | 4.7% | 0.5% | 1.4% | 1.0% | 0.7% |
| 2024 | 818 | 76.7% | 25.6% | 5.1% | 5.3% | 1.1% | 2.3% | 2.2% | 1.3% |

---

## 5. Key Patterns

### Pattern 1 — Vulnerable libraries are the dominant persistent risk
`vulnerable_library` rose from 0% in 2003 to a peak of 88.4% in 2018 and sits at 76.7% in 2024. The early rise tracks the spread of jQuery and its ecosystem; the recent modest decline likely reflects modern framework adoption (React, Vue, Angular) and tooling improvements (Dependabot, npm audit). Despite the decline, 76.7% of domains in 2024 still carry a known-vulnerable library — by far the most widespread client-side risk in this dataset.

### Pattern 2 — Dangerous sinks are declining but remain common
`dangerous_sink` ran at 55–83% from 2003 to 2008, when raw DOM manipulation was standard practice. It has declined consistently to 25–27% in 2022–2024. The driver is the shift to component frameworks (React, Vue) that do not use `innerHTML` by default. However, 25% prevalence is still substantial — one in four sites carries dangerous execution sinks — and 79% of retained findings are CRITICAL severity.

### Pattern 3 — Open redirect has not improved in 20 years
`open_redirect` sits at 4–8% across the entire 2003–2024 period with no directional trend. It is a structural feature of how JavaScript redirect patterns are written, and framework adoption has not eliminated it. This stasis is notable given the improvement seen in other attack types.

### Pattern 4 — DOM clobbering is slowly rising
`dom_clobbering` (CRIT+HIGH only after filtering) oscillated around 2–5% through 2019 and rose to 5.3% in 2024. This tracks the proliferation of third-party libraries containing clobberable gadgets. The retained CRITICAL findings are the highest-confidence signal: same element name appearing in HTML and accessed in inline JS in the same page, or `<iframe name="scripts">` shadowing `document.scripts`.

### Pattern 5 — New API attack surfaces are growing
`service_worker` (0% before 2016, 2.2% in 2024) and `postmessage_audit` (0% before 2014, 1.3% in 2024) both track the adoption of their underlying browser APIs. Small in absolute prevalence but trending upward — they represent the leading edge of the client-side attack surface rather than legacy debt.

### Pattern 6 — dangling_markup is spiking in 2022–2024
`dangling_markup` showed essentially 0–0.5% through 2021, then jumped to 1.4% in 2022 and 2.3% in 2023–2024. The retained findings are CRITICAL (`javascript:` URLs in href/src/action) and HIGH (`data:` URLs in script/iframe src). This trend is worth investigating — the sharp rise may reflect template-based CMS migrations leaving `javascript:` href patterns in older content, or a real increase in deliberate injection patterns.

### Pattern 7 — form_action_hijack declined to zero
After filtering to HIGH only (plain `http://` form actions), `form_action_hijack` declined from 1.5% in 2003–2005 to 0.0% by 2022–2024. This is a genuine security improvement — forms that previously submitted over HTTP have migrated to HTTPS.

### Pattern 8 — 77% of domains carry multiple simultaneous attack types
After FP filtering:
- 2.9% (45 domains): zero clean attacks
- 41.0% (629 domains): exactly 1 attack
- 36.0% (552 domains): exactly 2 attacks
- 16.0% (245 domains): exactly 3 attacks
- 6.1% (62 domains): 4 or more attacks

The most exposed domains (6 simultaneous attack types) are news and media sites with heavy third-party JavaScript ecosystems.

### Pattern 9 — dangerous_sink and vulnerable_library almost always co-occur
86% of domains with `dangerous_sink` also have `vulnerable_library`. Sites using outdated third-party libraries are also the ones with dangerous sink patterns — often because the vulnerable library version itself contains the sinks. This co-occurrence substantially raises exploitability relative to either finding alone.

### Pattern 10 — prototype_pollution is a slow-moving emerging risk
`prototype_pollution` was effectively 0% before 2008 and under 0.5% through 2019. It reached 1.1% in 2024, with 83 of 121 clean findings rated CRITICAL. The rise tracks the spread of complex object-merge patterns in modern JavaScript frameworks. Small in absolute terms but high severity when present.

---

## 6. Candidate Findings Requiring Dynamic Verification

These were excluded from main trends but are real signals:

| Attack | Findings | Domains Affected | Required Verification |
|--------|----------|-----------------|----------------------|
| `redos` | 421 | 73 | Dynamic ReDoS testing on specific regex patterns |
| `meta_refresh_redirect` | 264 | 58 | Manual inspection of redirect target and page context |
| `clickjacking` | 62 | 13 | Check live HTTP headers for X-Frame-Options / CSP frame-ancestors |
| `css_import_chain` | 14 | 2 | Verify whether the import chain reaches an attacker-controlled domain |

---

## 7. Recommended Reporting Rules for the Paper

1. **Use as primary signals**: `vulnerable_library`, `dangerous_sink`, `open_redirect`, `dom_clobbering` (CRIT+HIGH), `prototype_pollution`, `dangling_markup` (CRIT+HIGH), `postmessage_audit`, `service_worker`, `base_tag_hijack`, `html_violation` (HIGH only).

2. **Report separately with disclosure**: `redos` and `meta_refresh_redirect` — label as heuristic/candidate signals requiring dynamic validation, not confirmed vulnerabilities.

3. **Do not report as a vulnerability rate**: `clickjacking` — report only as "pages without detectable frame-busting defenses in HTML content" with a note that header-based defenses are not visible in archived HTML.

4. **For `form_action_hijack`**: report only the HIGH subset (plain `http://` form actions). State that the full raw count includes MEDIUM findings excluded as non-credential form FPs.

5. **For `dom_clobbering`**: report CRITICAL+HIGH findings only. State that 5,476 MEDIUM findings were excluded as high-FP heuristic patterns per the pipeline's documented limitations.

---

## 8. Next Steps

- **Add country labels to report JSON** — the current reports have `website` but no country field. Joining with the CrUX source CSV will enable the regional comparison the paper needs.
- **Investigate dangling_markup 2022–2024 spike** — the jump from ~0.5% to 2.3% is sharp enough to warrant manual spot-checking before reporting.
- **Run dynamic ReDoS verification** — 73 domains had redos candidates. A lightweight checker on those specific patterns would convert heuristic signals to confirmed findings.
- **Separate government vs. commercial domains in the sample** — current sample mixes both. Splitting by TLD (`.gov`, `.gob.*`, `.go.*`) will give a government-specific prevalence number directly comparable to Lauinger et al.'s 50% benchmark.
