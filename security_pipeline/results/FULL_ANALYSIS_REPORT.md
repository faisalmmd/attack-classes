# Security Pipeline — Full Dataset Analysis Report
**Date:** 2026-04-28
**Dataset:** `report_all_websites_faisal/report/` — 39,958 domains, 597,586 snapshots
**Pipeline:** 26 attack detectors across JS, HTML, CSS, XML, WASM

---

## 1. Dataset Overview

| Metric | Value |
|--------|-------|
| Total domains | 39,958 |
| Total snapshots | 597,586 |
| Year range (usable) | 2003–2024 |
| Raw findings | 3,584,976 |
| Government domains | 4,399 (11.0%) |
| Education domains | 785 (2.0%) |
| Commercial / other | 34,774 (87.0%) |

### Confidence tier breakdown

Rather than removing findings that carry uncertainty, a three-tier model is used:

| Tier | Count | % | Meaning |
|------|-------|---|---------|
| **Confirmed** | 3,060,613 | 93.9% | Strong signal, directly reportable |
| **Candidate** | 195,171 | 6.0% | Real signal requiring context or dynamic confirmation |
| **Excluded** | 4,419 | 0.1% | Structural false positives with no clear path to validity |

**Excluded** (removed from all analysis):
- `clickjacking` — X-Frame-Options is a header, invisible in archived HTML; systematic FP for all header-protected pages
- `html_violation` MEDIUM — block-in-inline and unclosed `<p>`/`<li>` are valid HTML5
- `css_import_chain` — flags legitimate CDN imports (Google Fonts, Bootstrap CDN)

**Candidate** (included in analysis with disclosure):
- `redos` — syntactic heuristic; 90–98% static FP rate but 2–10% are real; trend data is valid
- `meta_refresh_redirect` — legitimate and malicious redirects are statically indistinguishable
- `dom_clobbering` MEDIUM — JS_RELIANCE side only; exploitable if the site has an HTML injection surface
- `form_action_hijack` MEDIUM — external HTTPS form actions and `formaction` attrs; context-dependent
- `dangling_markup` MEDIUM — unclosed attribute heuristic; CRITICAL/HIGH retained without caveats

---

## 2. Overall Attack Prevalence (All Domains, Confirmed + Candidate)

| Attack | Domains | % of 39,958 | Severity split |
|--------|---------|------------|----------------|
| `vulnerable_library` | 34,380 | **86.0%** | CRIT 44% / HIGH 37% / MED 19% |
| `dangerous_sink` | 22,178 | **55.5%** | CRIT 83% / HIGH 9% / MED 8% |
| `dom_clobbering` | 8,790 | **22.0%** | CRIT 7% / HIGH 16% / MED 77% (MED = candidate) |
| `form_action_hijack` | 8,032 | **20.1%** | HIGH 3% (confirmed) / MED 97% (candidate) |
| `open_redirect` | 5,330 | **13.3%** | HIGH 100% |
| `redos` | 2,022 | **5.1%** | MED 100% (candidate) |
| `dangling_markup` | 1,385 | **3.5%** | CRIT 19% / HIGH 81% |
| `meta_refresh_redirect` | 1,333 | **3.3%** | HIGH 100% (candidate) |
| `html_violation` | 998 | **2.5%** | HIGH 100% (confirmed) |
| `service_worker` | 745 | **1.9%** | HIGH 100% |
| `postmessage_audit` | 587 | **1.5%** | CRIT 99% |
| `prototype_pollution` | 546 | **1.4%** | CRIT 69% / HIGH 31% |
| `base_tag_hijack` | 371 | **0.9%** | HIGH 100% |
| `cryptominer_js` | 108 | **0.3%** | mixed |
| `jsonp_callback` | 88 | **0.2%** | HIGH 100% |
| `css_font_keylog` | 26 | **0.1%** | CRIT 100% |
| `xxe` | 3 | **0.008%** | CRIT |
| `xml_bomb` | 2 | **0.005%** | CRIT |
| `css_attr_exfil` | 3 | **0.008%** | — |

---

## 3. Attack Prevalence by Sector

| Attack | Government | Education | Commercial |
|--------|-----------|-----------|------------|
| `vulnerable_library` | 77.3% | 85.0% | 84.3% |
| `dangerous_sink` | 44.7% | 51.0% | 53.9% |
| `open_redirect` | 9.0% | 9.2% | 12.5% |
| `dom_clobbering` | 13.3% | 13.4% | 21.4% |
| `form_action_hijack` | 21.8% | 18.0% | 18.4% |
| `prototype_pollution` | 0.5% | 1.7% | 1.2% |
| `dangling_markup` | 1.5% | 1.7% | 3.1% |
| `html_violation` | 2.0% | 1.8% | 1.2% |
| `postmessage_audit` | 1.2% | 0.1% | 1.2% |
| `service_worker` | 0.2% | 0.5% | 1.6% |
| `redos` (candidate) | 3.3% | 3.7% | 5.0% |
| `cryptominer_js` | 0.0% | 0.0% | 0.3% |

**Key sector differences:**
- Government has *higher* `vulnerable_library` than commercial once normalized to active domains in 2022–24 (84.0% vs 82.0%)
- Government has *lower* `dangerous_sink` than commercial (19.1% vs 25.1% in 2022–24) — the one area where government tracks better
- Government has *higher* `form_action_hijack` than commercial (8.2% vs 6.1%) — likely legacy form infrastructure
- `service_worker` almost absent in government (0.2% vs 1.5%) — slower API adoption overall
- `cryptominer_js` is exclusively a commercial phenomenon (0.0% in government and education)

---

## 4. Longitudinal Trends (2003–2024)

### 4.1 Full Dataset

| Year | N | vul_lib | dang_sink | open_redir | dom_clob | form_act | dang_mkup | svc_wkr | postmsg |
|------|---|---------|-----------|------------|----------|----------|-----------|---------|---------|
| 2003 | 2,211 | 0.0% | 60.6% | 5.3% | 21.1% | 26.1% | 0.2% | 0.0% | 0.0% |
| 2005 | 2,938 | 0.0% | 64.7% | 4.9% | 24.9% | 28.9% | 1.1% | 0.0% | 0.0% |
| 2007 | 5,050 | 1.1% | 81.6% | 3.7% | 18.1% | 20.7% | 0.7% | 0.0% | 0.0% |
| 2010 | 6,868 | 41.2% | 66.0% | 5.0% | 17.9% | 17.3% | 0.7% | 0.0% | 0.0% |
| 2013 | 13,240 | 73.9% | 47.7% | 6.1% | 9.4% | 14.0% | 0.4% | 0.0% | 0.3% |
| 2016 | 17,549 | 85.3% | 42.3% | 5.8% | 7.3% | 9.5% | 0.4% | 0.0% | 0.2% |
| 2018 | 19,941 | 88.4% | 33.2% | 4.7% | 7.8% | 8.3% | 0.3% | 0.2% | 0.4% |
| 2020 | 21,140 | 88.6% | 25.5% | 4.8% | 8.3% | 7.2% | 0.6% | 0.9% | 0.4% |
| 2022 | 22,926 | 87.0% | 23.6% | 5.1% | 9.4% | 6.4% | 1.4% | 1.1% | 0.5% |
| 2024 | 20,821 | 76.4% | 25.4% | 6.2% | 11.4% | 6.2% | 2.1% | 1.6% | 0.7% |

### 4.2 Government Domains Only

| Year | N | vul_lib | dang_sink | open_redir | dom_clob | form_act | postmsg |
|------|---|---------|-----------|------------|----------|----------|---------|
| 2003 | 296 | 0.0% | 61.5% | 1.7% | 18.2% | 26.0% | 0.0% |
| 2006 | 375 | 0.0% | 58.7% | 1.6% | 14.4% | 40.0% | 0.0% |
| 2010 | 682 | 22.0% | 52.5% | 2.8% | 11.0% | 34.9% | 0.0% |
| 2014 | 1,436 | 68.9% | 34.5% | 8.8% | 5.8% | 16.8% | 0.1% |
| 2018 | 2,245 | 84.9% | 27.3% | 6.3% | 6.1% | 11.5% | 0.0% |
| 2020 | 2,441 | 87.3% | 23.0% | 5.6% | 6.8% | 8.6% | 0.2% |
| 2022 | 2,476 | 86.7% | 21.2% | 5.3% | 7.6% | 8.2% | 0.8% |
| 2024 | 2,003 | 81.2% | 17.1% | 5.2% | 8.5% | 8.1% | 2.0% |

### 4.3 Directional Change Summary

| Attack | 2003–05 | 2022–24 | Change | Direction |
|--------|---------|---------|--------|-----------|
| `vulnerable_library` | 0.0% | 82.3% | +82.3pp | Rising (plateau since 2018, declining since 2020) |
| `dangerous_sink` | 62.7% | 24.4% | −38.2pp | Declining — strongest positive trend |
| `form_action_hijack` | 27.4% | 6.3% | −21.1pp | Declining — HTTPS migration |
| `dom_clobbering` | 23.3% | 10.4% | −12.9pp | Net declining but V-shaped (rising since 2017) |
| `open_redirect` | 5.1% | 5.8% | +0.7pp | Flat — no improvement in 20 years |
| `dangling_markup` | 0.7% | 1.8% | +1.1pp | Slowly rising |
| `service_worker` | 0.0% | 1.3% | +1.3pp | Emerging (API post-2015) |
| `postmessage_audit` | 0.0% | 0.6% | +0.6pp | Emerging (API post-2012) |
| `prototype_pollution` | 0.0% | 0.6% | +0.6pp | Slowly rising |

---

## 5. Key Patterns

### Pattern 1 — Vulnerable libraries: the dominant, unresolved risk
`vulnerable_library` rose from effectively zero in 2003 to a peak of 88.6% of all domains in 2020, then declined to 76.4% in 2024. The rise tracks the spread of jQuery (which appeared in 2006 and had reached 84%+ of Alexa sites by 2016) and the ecosystem of plugins and frameworks built on top of it. The recent decline reflects modern framework adoption — React, Vue, and Angular replace jQuery in new projects and their ecosystems are more regularly updated.

However, 76.4% in 2024 is not a success story. Across 7,654 domains in this dataset, the vulnerable library finding persisted for ten consecutive years or more — representing chronic maintenance debt, not isolated incidents. Government domains sit at 84% in 2022–24, slightly *above* the commercial average, which matches and extends Lauinger et al.'s 2017 finding that government sites are disproportionately affected.

### Pattern 2 — Dangerous sinks: the clearest improvement
`dangerous_sink` ran at 60–82% from 2003 to 2008, when direct DOM manipulation was standard practice. It declined consistently to 24–25% in 2022–2024. This is the strongest positive security trend in the dataset. The driver is almost certainly the shift to component-based frameworks that discourage or eliminate direct `innerHTML` assignment and string-based `eval` calls.

The severity composition reveals something important: even as prevalence fell, the CRITICAL fraction *increased* — from 85–97% in 2003–2010 to 74–81% in 2021–2023. This means the remaining dangerous sink findings are concentrated in the most severe patterns, not the marginal ones. What got cleaned up was mostly HIGH and MEDIUM (template strings, `setAttribute('on*', var)`). The core `eval`/`innerHTML` patterns are sticky.

Government domains declined even faster than commercial: from 61.5% in 2003 to 17.1% in 2024 (−44pp vs −35pp for commercial). This may reflect later adoption of newer frameworks by government sites accelerating the cleanup.

### Pattern 3 — DOM clobbering: a V-shaped trajectory
`dom_clobbering` shows the most unusual shape in the dataset. It started high (21–25% in 2003–2005), declined steadily to 7% by 2016–2017, then rose back to 11.4% by 2024. The early high rate reflects legacy HTML where named form and anchor elements were common structural patterns. The decline from 2005–2017 tracks the shift to div-based layouts and JavaScript-driven content, which use fewer named elements. The rise since 2017 tracks the growing complexity of client-side code and the proliferation of third-party libraries containing clobberable gadgets — precisely the pattern Liu et al. documented in 2025.

Critically, the MEDIUM (candidate) fraction has been declining over time while HIGH and CRITICAL findings rise. In 2003, 94% of dom_clobbering findings were MEDIUM (JS_RELIANCE only, no confirmed HTML collision). By 2023, MEDIUM is 74% and HIGH+CRITICAL is 26%. The signal is becoming more confirmed over time, not less.

### Pattern 4 — form_action_hijack: tracking HTTPS adoption
`form_action_hijack` fell from 27% in 2003–2005 to 6% in 2022–2024, with government declining even more sharply (40% in 2006 to 8% now). After FP filtering to HIGH only (plain `http://` form actions), this represents a genuine security improvement tied directly to HTTPS adoption. 590 domains still had `http://` form actions for ten or more years — these are legacy portals with authentication forms that have never been migrated.

### Pattern 5 — Open redirect: 20 years of no improvement
`open_redirect` has sat at 4–6% since 2003. No other attack type in the dataset shows this degree of stasis. Every other metric has either improved, worsened, or tracked an obviously causal event (API adoption, framework shift). Open redirect has done none of these. It is structural: redirect patterns in JavaScript are written in ways that are functionally indistinguishable from a security standpoint whether the author intended to redirect to a user-supplied destination or not, and no dominant framework change has addressed this.

The 2022–2024 slight uptick (to 5.1–6.2%) may reflect the growth of single-page applications that handle routing client-side, creating more redirect sinks than server-side applications did.

### Pattern 6 — dangling_markup: a recent sharp rise
`dangling_markup` (CRITICAL + HIGH only: `javascript:` URLs and `data:` URLs in script/iframe src) was near zero through 2021, then rose to 1.4% in 2022 and 2.1% in 2024. This is the sharpest recent upward trend in the dataset after service_worker. The peak was 2024, which means it has not yet plateaued. Worth investigating before reporting — see §8.

### Pattern 7 — service_worker and postmessage_audit: emerging surfaces
Both of these track their underlying API introduction dates with a delay. `postmessage_audit` appeared around 2012–2014, `service_worker` around 2016–2017. Both are still rising in 2024, which means sites are adopting these APIs but not consistently applying the security practices that accompany them. Government sites are notably behind: service_worker at 0.2% vs 1.5% in commercial, reflecting slower API adoption overall.

### Pattern 8 — Persistence is widespread
7,654 domains (19% of the dataset) maintained a vulnerable library finding for ten or more consecutive years. 3,134 domains (8%) maintained dangerous sink patterns for a decade or more. These are not one-time vulnerabilities — they represent sites that have never addressed a known risk class across an entire decade of archived history.

### Pattern 9 — Multi-attack exposure is common
After FP filtering to confirmed findings only:
- 93% of domains have at least one confirmed attack type
- 55% have two or more
- 18% have three or more

Commercial sites are more likely to have multiple simultaneous attack types (14.6% with 3+) than government sites (8.0% with 3+). This reflects the more complex JavaScript ecosystems of commercial sites rather than government sites being safer overall.

### Pattern 10 — co-occurrence: dangerous_sink and vulnerable_library as a cluster
86% of domains with `dangerous_sink` also have `vulnerable_library`. 89% of domains with `prototype_pollution` have `vulnerable_library`. The pattern is consistent: sites that have vulnerable third-party dependencies are also the sites with dangerous code patterns — because the dangerous patterns often live *inside* the vulnerable library versions. Remediating library version currency would partially address several other attack types simultaneously.

---

## 6. Country-Level Observations

### Notable outliers in government domains

| Country | Gov domains | Notable pattern |
|---------|------------|-----------------|
| **BD** | 436 | 99.1% vulnerable_library — near-universal, but only 13.8% dangerous_sink — unusual decoupling |
| **FR** | 214 | 27.6% vulnerable_library (low), but 53.3% open_redirect — massive outlier for open redirect |
| **KR** | 86 | 20.9% vulnerable_library (low for government) but 61.6% dangerous_sink — opposite of BD |
| **NG** | 155 | 96.1% vulnerable_library — near-universal |
| **IN** | 148 | 96.6% vulnerable_library — near-universal |
| **MY** | 176 | 4 of the top 6 most-exposed government domains in the entire dataset are Malaysian (.gov.my) |
| **US** | 373 | 65.4% vulnerable_library (below average), 69.2% dangerous_sink (above average) |

The BD/KR contrast is worth investigating: both have unusual decoupling of vulnerable_library and dangerous_sink, in opposite directions. FR's 53.3% open redirect in government domains is the largest outlier by far — warrants a manual check to determine if it is a scanner pattern or structural.

### Cryptominer geography
108 domains had cryptominer findings. None are government or education domains. The most-affected are adult content sites (10 domains), news/media aggregators, and cryptocurrency-adjacent sites. Pinterest regional subdomains (`gr.pinterest.com`, `za.pinterest.com`, `ru.pinterest.com`, etc.) appear repeatedly — this likely reflects a period when third-party ad scripts served through Pinterest included Coinhive.

### Rare attacks at scale
- **XXE** (3 domains): `rumandmonkey.com`, `www.csmonitor.com`, `rus.delfi.lv` — all commercial news/media. These are the only sites in 39,958 domains serving XML with external entity declarations.
- **XML bomb** (2 domains): `www.perfil.com` (Argentinian news), `www.nyse.com` — both large media/financial properties.
- **CSS attr exfil** (3 domains): rare and isolated.

---

## 7. Most Exposed Government Domains

| Domain | Country | Attack count | Attacks |
|--------|---------|-------------|---------|
| `rurallink.gov.my` | MY | 6 | dangerous_sink, dom_clobbering, form_action_hijack, html_violation, open_redirect, vulnerable_library |
| `cidb.gov.my` | MY | 6 | dangerous_sink, dangling_markup, dom_clobbering, form_action_hijack, open_redirect, vulnerable_library |
| `bomba.gov.my` | MY | 6 | dangerous_sink, dom_clobbering, form_action_hijack, html_violation, open_redirect, vulnerable_library |
| `kejora.gov.my` | MY | 6 | dangerous_sink, dom_clobbering, form_action_hijack, html_violation, open_redirect, vulnerable_library |
| `safetyact.gov` | US | 5 | dangerous_sink, dom_clobbering, open_redirect, postmessage_audit, vulnerable_library |
| `disasterassistance.gov` | US | 5 | dangerous_sink, dom_clobbering, form_action_hijack, html_violation, vulnerable_library |
| `AMERICATHEBEAUTIFULQUARTERS.GOV` | US | 5 | dangerous_sink, dom_clobbering, form_action_hijack, open_redirect, vulnerable_library |
| `www.cancer.gov` | US | 5 | dangerous_sink, dom_clobbering, form_action_hijack, open_redirect, vulnerable_library |
| `icp.gov.ae` | AE | 5 | dangerous_sink, dangling_markup, form_action_hijack, html_violation, vulnerable_library |
| `rosstat.gov.ru` | RU | 5 | dangerous_sink, dom_clobbering, form_action_hijack, postmessage_audit, vulnerable_library |

---

## 8. Items Requiring Follow-up Before Paper Reporting

| Item | Why | Action |
|------|-----|--------|
| FR government 53.3% open_redirect | Massive outlier — 5× the rate of any other country's government domains | Spot-check 10 FR gov domains manually |
| dangling_markup 2022–2024 spike | Sharp rise with peak in 2024; only CRITICAL+HIGH retained | Verify it's not a scanner artifact; check specific files |
| BD gov: vulnerable_library 99.1% but dangerous_sink 13.8% | Unusual decoupling — may reflect sites that include many libraries but have minimal inline JS | Check whether BD sites are mostly static CMS pages |
| KR gov: low vulnerable_library, high dangerous_sink | Opposite decoupling — likely custom JS frameworks without third-party dependencies | Check if KR gov sites use government-specific JS frameworks |
| `www.nyse.com` with xml_bomb | High-profile financial site with XML entity bomb pattern | Confirm finding is genuine, not a scanner FP on financial data feeds |
| Pinterest cryptominer findings | Multiple Pinterest regional domains flag cryptominer | Confirm era of findings (likely 2017–2018 Coinhive window) |
| Country label for 15,575 "unknown" domains | These lack a recognizable ccTLD — they're likely US .com/.org/.net domains | Join against CrUX source CSV to assign country |

---

## 9. Recommended Reporting Tiers for the Paper

**Tier 1 — Report as confirmed findings:**
`vulnerable_library`, `dangerous_sink`, `open_redirect`, `dom_clobbering` (CRIT+HIGH), `prototype_pollution`, `dangling_markup` (CRIT+HIGH), `html_violation` (HIGH), `postmessage_audit`, `service_worker`, `base_tag_hijack`, `form_action_hijack` (HIGH only)

**Tier 2 — Report as candidate/heuristic findings with explicit disclosure:**
`redos` — "heuristic patterns with 90–98% static FP rate; trend data is reported, not individual vulnerability counts"
`meta_refresh_redirect` — "candidate redirects requiring manual triage"
`dom_clobbering` MEDIUM — "JS_RELIANCE patterns; exploitable where HTML injection is possible"
`form_action_hijack` MEDIUM — "external form destinations; context-dependent severity"

**Tier 3 — Report as pipeline limitations, not findings:**
`clickjacking` — frame defense status cannot be assessed from archived HTML
`css_import_chain` — cannot distinguish attacker-controlled from legitimate CDN imports
`html_violation` MEDIUM — HTML5-valid patterns flagged by an HTML4-based parser
