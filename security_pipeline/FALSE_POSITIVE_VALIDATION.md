# False Positive Validation — Security Pipeline Attack Detectors

**Purpose:** Source material for the validation/limitations section of the paper. Every claim
below is sourced from an existing pipeline document or an actual pipeline run; the source is
cited inline as `[file:line]` or `[file, section]`. Numbers described as "measured" come from
running the pipeline on real archived data. Numbers described as "literature" are FP-rate
claims from the cited academic papers themselves, not measurements this pipeline produced —
these two categories must not be conflated in the paper.

No numbers in this document were estimated or invented for this compilation; anything not
directly present in the pipeline's own docs/output is explicitly marked "not quantified."

---

## 1. Data provenance — three separate pipeline runs exist

There is **no single canonical run**. Three different runs, on three different dataset sizes,
produced the numbers below. They are not the same sample and their totals do not reconcile with
each other — cite the specific run you are drawing a number from.

| Run | Dataset | Domains | Snapshots | Raw findings | Report |
|-----|---------|---------|-----------|---------------|--------|
| **Dev/test run** | `random_50_dirs` (756 MB, 50 domains) | 50 | 1,206 | n/a (per-attack only) | `TEST_SUMMARY.md`, `results/<attack>/summary.json` |
| **Sample run** | `sample/report/` | 1,533 | 22,988 | 134,265 | `results/ANALYSIS_REPORT.md` (dated 2026-04-28) |
| **Full run** | `report_all_websites_faisal/report/` | 39,958 | 597,586 | 3,584,976 | `results/FULL_ANALYSIS_REPORT.md` (dated 2026-04-28) |

There is also a synthetic-test validation layer, independent of any real archive data:
`test_runner.py`, 59/59 assertions passing across all 26 attack detectors, run against
hand-written one-per-attack test files in `test_cases/`. This confirms the detector *fires
correctly on known-positive synthetic input*; it says nothing about real-world FP rate
`[TEST_SUMMARY.md]`.

---

## 2. Full-run quantified FP tiering (39,958 domains, 3,584,976 raw findings)

The full run is the only place the pipeline assigns every finding to an explicit confidence
tier with a dataset-wide count `[results/FULL_ANALYSIS_REPORT.md, §1]`:

| Tier | Count | % of raw findings | Meaning |
|------|-------|--------------------|---------|
| **Confirmed** | 3,060,613 | 93.9% | Strong signal, directly reportable |
| **Candidate** | 195,171 | 6.0% | Real signal requiring context or dynamic confirmation — not a false positive, but not confirmed either |
| **Excluded** | 4,419 | 0.1% | Structural false positives with no clear path to validity |

**Excluded (removed entirely from analysis) — 4,419 findings:**
- `clickjacking` — X-Frame-Options is an HTTP header, invisible in archived HTML; systematic FP for every header-protected page
- `html_violation` MEDIUM — block-in-inline and unclosed `<p>`/`<li>` are valid HTML5
- `css_import_chain` — flags legitimate CDN imports (Google Fonts, Bootstrap CDN)

**Candidate (kept, but flagged as needing dynamic/manual confirmation) — 195,171 findings:**
- `redos` — syntactic heuristic; 90–98% static FP rate per literature, but 2–10% are estimated real; trend data still valid
- `meta_refresh_redirect` — legitimate and malicious redirects are statically indistinguishable
- `dom_clobbering` MEDIUM (JS_RELIANCE side only) — exploitable only if the site also has an HTML injection surface
- `form_action_hijack` MEDIUM — external HTTPS form actions and `formaction` attrs; context-dependent
- `dangling_markup` MEDIUM — unclosed-attribute heuristic (CRITICAL/HIGH from this same attack are NOT candidate — they are confirmed without caveats)

**Note on the 0.1% figure:** this is deliberately small — it is *only* the findings the
pipeline authors judged had no path to validity at all. It is not a general FP-rate estimate
for the pipeline; the 6.0% Candidate tier is the more honest "could be a false positive"
bucket, and per-attack it is much higher for some detectors (see §4).

---

## 3. Sample-run quantified FP removal (1,533 domains, 134,265 raw findings)

This is an earlier/smaller run that used a stricter binary filter (remove vs. keep) rather
than the three-tier model, and reports actual per-attack removal counts
`[results/ANALYSIS_REPORT.md, §2]`:

| Attack | Filter applied | Findings removed | Reason |
|--------|-----------------|-------------------|--------|
| `clickjacking` | ALL severities removed | 62 | X-Frame-Options header not visible in archived HTML |
| `html_violation` | MEDIUM removed | 74 | Block-in-inline / unclosed tags are valid HTML5; duplicate IDs from templating are common |
| `form_action_hijack` | MEDIUM removed | 2,611 | `formaction` attr / external HTTPS actions flagged regardless of form purpose |
| `redos` | ALL severities removed (reported separately, §6 below) | 421 | 90–98% static FP rate; heuristic cannot confirm actual vulnerability |
| `meta_refresh_redirect` | ALL severities removed (reported separately) | 264 | Legitimate domain migrations statically indistinguishable from malicious redirects |
| `css_import_chain` | ALL severities removed | 14 | Flags legitimate CDN imports |
| `dom_clobbering` | MEDIUM removed | 5,476 | MEDIUM (`window.config`, bare security variables) is high-volume without a matching HTML element |
| **Total** | | **8,922 / 134,265 (6.6%)** | |

**Candidate findings excluded from main trend analysis but reported as a separate signal**
`[results/ANALYSIS_REPORT.md, §6]` — these are counted above in the 8,922 removed, listed
again here because they carry domain-level counts:

| Attack | Findings | Domains affected | What would confirm them |
|--------|----------|-------------------|---------------------------|
| `redos` | 421 | 73 | Dynamic ReDoS testing (actual regex execution against crafted input) on the specific patterns matched |
| `meta_refresh_redirect` | 264 | 58 | Manual inspection of the redirect target and page context |
| `clickjacking` | 62 | 13 | Live check of HTTP response headers (X-Frame-Options / CSP frame-ancestors) — not possible from archived HTML alone |
| `css_import_chain` | 14 | 2 | Verify whether the import chain resolves to an attacker-controlled domain |

---

## 4. Per-attack false-positive profile (all 25 detectors)

Combines the qualitative FP/FN disclosures in `verification/VERIFICATION_GUIDE.md` (every
attack has a "Known false negatives" writeup; only some have an explicit "Known false
positives" writeup — this is disclosed per row) with real counts wherever a pipeline run
produced one. "Not quantified" means the FP risk is documented in prose but no count of
actual false positives observed in real data exists in any pipeline doc.

| Attack | FP severity (README rating, where given) | FP description | Measured evidence |
|--------|---|---|---|
| `clickjacking` | **High** | Systematic MEDIUM false positive: pages defended only by the HTTP `X-Frame-Options` header (the standard, recommended defense) look "unprotected" because the header isn't present in archived HTML. `[VERIFICATION_GUIDE.md:789-796]` | 62 findings / 13 domains removed in sample run; excluded entirely (all severities) in full run's Excluded tier `[ANALYSIS_REPORT.md §2, §6; FULL_ANALYSIS_REPORT.md §1]` |
| `html_violation` | **High** (MEDIUM tier) | MEDIUM findings are high-volume on real HTML: `<a>` wrapping `<div>` (block-in-inline) is valid HTML5; unclosed `<p>`/`<li>`/`<td>` are standard; duplicate IDs from templating are common. Scanner uses HTML4-era inline/block rules. HIGH tier (nested `<form>`) is the only reliable signal. `[VERIFICATION_GUIDE.md:1000; README.md:111]` | 74 MEDIUM findings removed in sample run `[ANALYSIS_REPORT.md §2]`; MEDIUM tier placed in full run's Excluded tier `[FULL_ANALYSIS_REPORT.md §1]`. Full-run confirmed (HIGH-only) count: 998 domains, 2.5% `[FULL_ANALYSIS_REPORT.md §2]` |
| `form_action_hijack` | **Medium** | All `http://` form actions flagged HIGH regardless of form purpose (login vs. search). All `formaction` attributes flagged MEDIUM regardless of whether the target is internal or external — legitimate multi-step forms using `formaction` for internal endpoints are over-flagged. `[VERIFICATION_GUIDE.md:931; README.md:112]` | Sample run: 2,611 MEDIUM findings removed. Full run: MEDIUM = 97% of all form_action_hijack findings (8,032 domains total; only 3% HIGH/confirmed) `[FULL_ANALYSIS_REPORT.md §2]` — i.e. the large majority of raw hits for this attack are the flagged-as-candidate class, not confirmed |
| `dangling_markup` | **Medium** | Unclosed-attribute heuristic (HIGH/MEDIUM sub-detector) may false-positive on multi-line attributes or template-engine partial renders. The `javascript:`/`data:` URL detections (CRITICAL/HIGH) are separately described as reliable/low-FP. `[VERIFICATION_GUIDE.md:963; README.md:113]` | Full run: CRIT 19% / HIGH 81% of 1,385 domains — i.e. essentially none of the counted findings are the noisy MEDIUM heuristic; that sub-class is in the Candidate tier, not counted in the 1,385 `[FULL_ANALYSIS_REPORT.md §1,§2]` |
| `meta_refresh_redirect` | **Medium** | Legitimate intentional redirects (partner sites, domain migrations, affiliate pages) are statically indistinguishable from malicious ones; all findings require manual triage. Also a false-negative gap: HTTP 301/302 redirects (the more common mechanism) are invisible to this HTML-only scanner. `[VERIFICATION_GUIDE.md:897; README.md:114]` | Sample run: 264 findings / 58 domains, reported as candidate-only. Full run: 1,333 domains, 3.3%, entirely in Candidate tier `[ANALYSIS_REPORT.md §6; FULL_ANALYSIS_REPORT.md §1,§2]` |
| `redos` | **Medium** | Syntactic heuristic only (Star Height > 1 and QOD anti-patterns); does not detect QOA, the most common super-linear pattern (71% of vulnerable npm regexes per Davis et al.). **Literature figure, not measured by this pipeline:** all three anti-pattern classes have a 90–98% static false-positive rate before dynamic validation (Davis et al., ESEC/FSE 2018, Table 4). `[VERIFICATION_GUIDE.md:268,306; README.md:115]` | Sample run: 421 findings / 73 domains, reported as candidate-only, explicitly excluded from prevalence trends. Full run: 2,022 domains, 5.1%, 100% Candidate tier `[ANALYSIS_REPORT.md §6; FULL_ANALYSIS_REPORT.md §1,§2]` |
| `wasm_cryptominer` | **Low–Medium** | Common crypto-library strings (`keccak`, `scrypt`, `argon2`) appear in legitimate TLS/crypto WASM modules; generic export names (`hash`, `work`, `job`) are common outside mining code. Multi-signature escalation (3+ signatures → CRITICAL) is the mitigation. Hash-based confirmation is unavailable — `KNOWN_MINER_HASHES` is an empty placeholder. `[VERIFICATION_GUIDE.md:700; README.md:116]` | Not quantified in any real-data run (not in the sample/full-run prevalence tables — no domains in those two runs triggered it, or it wasn't reported) |
| `css_import_chain` | **Low–Medium** | All external `@import` URLs are flagged, including legitimate CDN imports (Google Fonts, etc.). The actual attack requires an attacker-controlled server responding with branching imports keyed on the Referer header — a server-side behavior invisible in a static archive. Detector identifies opportunity, not active exploitation. `[VERIFICATION_GUIDE.md:487; README.md:117]` | Sample run: 14 findings / 2 domains, removed entirely. Full run: excluded entirely (structural FP, no path to validity) `[ANALYSIS_REPORT.md §2,§6; FULL_ANALYSIS_REPORT.md §1]` |
| `css_font_keylog` | **Low** | Legitimate narrow-range font subsets (e.g. CJK) could in principle trigger it, though standard CJK subsetting uses broad ranges in practice, so this is rare. Two-condition requirement (single-codepoint range AND external URL) substantially limits FPs. No peer-reviewed source — practitioner blog + GitHub PoC only. `[VERIFICATION_GUIDE.md:523; README.md:118]` | Full run: 26 domains, 0.1%, 100% CRITICAL `[FULL_ANALYSIS_REPORT.md §2]` — low volume, consistent with the "Low" FP severity rating |
| `postmessage_audit` | **Low** | Pages using `message` listeners for legitimate cross-frame communication (OAuth flows, embedded widgets) are flagged if no `event.origin` check is visible within the scanner's 15-line handler window — a real handler could check origin outside that window. `[VERIFICATION_GUIDE.md:410; README.md:119]` | Full run: 587 domains, 1.5%, 99% CRITICAL `[FULL_ANALYSIS_REPORT.md §2]` |
| `dangerous_sink` | **Low** | `setTimeout(varName, ...)` flagged MEDIUM — callback-reference vs. string-argument is ambiguous without type information. `setAttribute('on*', var)` flagged HIGH — the second argument may in practice be a static string. `[VERIFICATION_GUIDE.md:1203; README.md:120]` | Full run: 22,178 domains, 55.5%, CRIT 83% / HIGH 9% / MED 8% `[FULL_ANALYSIS_REPORT.md §2]` — the disputed MEDIUM/HIGH-ambiguity classes are a small minority (17%) of this attack's findings |
| `missing_sri` | **Low (by design)** | Wayback-rewritten URLs (`web.archive.org/web/...`) are treated as external — stated as intentional, since they represent originally-external resources. `[VERIFICATION_GUIDE.md:743; README.md:121]` | Not in the full-run or sample-run prevalence tables (no count reported in either analysis doc) |
| `dom_clobbering` | **Low–Medium** | `window[variable]` (HIGH) fires on legitimate plugin-loader patterns where the variable name is not attacker-controlled. Two-level (`<form id><input name>`) flags the structure regardless of whether any JS actually exploits the `form.input` path — needs manual triage. `document.scripts` access may false-positive on defensive SRI-verification code. HTML_SINK findings for rare shadowed names (`scripts`, `nonce`) are separately described as high-precision. `[VERIFICATION_GUIDE.md:1163-1172; README.md:122]` | Sample run: 5,476 MEDIUM findings removed (of a much smaller CRIT+HIGH-only retained count). Full run: 8,790 domains, 22.0%, CRIT 7% / HIGH 16% / **MED 77% (candidate)** `[ANALYSIS_REPORT.md §2; FULL_ANALYSIS_REPORT.md §1,§2]` — MEDIUM is the dominant severity class for this attack by a wide margin |
| `prototype_pollution` | Not rated in README table (no FP severity assigned) | `hasOwnProperty`-guarded `for...in` loops are still flagged HIGH even though the guard makes them safe — the scanner does not parse guard presence. Disclosed as a known FP class in the methodology summary table. `[VERIFICATION_GUIDE.md:1201, §"Attack 1"]` | Dev/test run (50 domains): 7,751 findings / 40 domains — this count predates/includes the guard-FP class above and is the largest raw-finding-per-domain ratio of any attack in that run `[TEST_SUMMARY.md; results/prototype_pollution/summary.json]`. Full run: 546 domains, 1.4%, CRIT 69% / HIGH 31% `[FULL_ANALYSIS_REPORT.md §2]` |
| `open_redirect` | Not rated (no FP heading in VERIFICATION_GUIDE) | No "Known false positives" section exists for this attack — only false negatives are documented (multi-line source/sink flows beyond the 5-line window, aliased sink variables, `hashchange`-triggered redirects, same-origin `frame.src` changes flagged despite being non-vulnerable). That last item **is** a false-positive-shaped gap even though it's filed under false negatives in the source doc. `[VERIFICATION_GUIDE.md:122]` | Full run: 5,330 domains, 13.3%, 100% HIGH `[FULL_ANALYSIS_REPORT.md §2]` |
| `high_risk_api` | Not rated / no FP section | No "Known false positives" heading. All API calls are flagged regardless of whether user consent was obtained — an inherent limitation of static analysis, described as justified by literature-reported low legitimate-usage rates rather than as a false positive per se. `[VERIFICATION_GUIDE.md:162]` | Not in the full-run or sample-run per-attack prevalence table (not listed in either §2 table — may not have been included in that reporting pass) |
| `jsonp_callback` | Not rated / no FP section | No "Known false positives" heading; only false negatives documented (nonstandard callback param names, dynamically constructed URLs). | Dev/test run (50 domains): 921 findings / 33 domains, 100% MEDIUM `[results/jsonp_callback/summary.json]`. Full run: 88 domains, 0.2%, 100% HIGH `[FULL_ANALYSIS_REPORT.md §2]` (severity differs between the two runs — dev run predates a scanner revision) |
| `service_worker` | Not rated / no FP section | No "Known false positives" heading; only false negatives documented (computed scope values not detected). | Full run: 745 domains, 1.9%, 100% HIGH `[FULL_ANALYSIS_REPORT.md §2]` |
| `cryptominer_js` | Not rated / no FP section | No "Known false positives" heading. One specific pattern is disclosed as an accepted-risk FP source: `miner.start()` matches any object named `miner` with a `.start()` method, "expected and acceptable given the rarity of that pattern in legitimate code" (i.e., not mitigated, just judged low-risk). `[VERIFICATION_GUIDE.md:375]` | Full run: 108 domains, 0.3%, mixed severity, exclusively commercial domains (0% in government/education) `[FULL_ANALYSIS_REPORT.md §2,§6]` |
| `css_attr_exfil` | Not rated / no FP section | No "Known false positives" heading in VERIFICATION_GUIDE. | Full run: 3 domains, 0.008% — described in the full report as "rare and isolated" `[FULL_ANALYSIS_REPORT.md §2,§6]` |
| `xxe` | Not rated / no FP section | No "Known false positives" heading; false negatives documented (multi-line DOCTYPE splits, blind/OOB variants structurally identical to detected pattern). | Full run: 3 domains total in 39,958 (`rumandmonkey.com`, `www.csmonitor.com`, `rus.delfi.lv`) — flagged in the report itself as needing confirmation that the finding is genuine `[FULL_ANALYSIS_REPORT.md §6]`. Dev/test run (50 domains): 0 findings `[results/xxe/summary.json]` |
| `xml_bomb` | Not rated / no FP section | No "Known false positives" heading; false negative documented (Quadratic Blowup variant, one entity value repeated many times without nesting, is not detected). | Full run: 2 domains total (`www.perfil.com`, `www.nyse.com`) — the report explicitly flags the NYSE finding as needing confirmation it isn't a scanner FP on financial data feeds `[FULL_ANALYSIS_REPORT.md §6,§8]` |
| `xpath_injection` | Not rated / no FP section | No "Known false positives" heading; false negatives only (server-side XPath, JS string-concatenated XPath not covered). | Not in the full-run or sample-run prevalence table |
| `xslt_injection` | Not rated / no FP section | No "Known false positives" heading; false negatives only (`exsl:function`, `xt:document`, XSLT 3.0 `fn:transform()` not covered). | Not in the full-run or sample-run prevalence table |
| `base_tag_hijack` | Not rated / no FP section | No "Known false positives" heading; the documented behavior (flagging regardless of tag position in the document) is described as "correct for detection," not a limitation. | Full run: 371 domains, 0.9%, 100% HIGH `[FULL_ANALYSIS_REPORT.md §2]` |
| `vulnerable_library` | Not rated / no FP section (but see methodology table) | No "Known false positives" heading; false negatives documented (libraries outside the built-in DB, 200 KB read cutoff per file, bundled files only match the first library found). Separately, one database entry is flagged as questionable: React CVE-2015-1164 is actually a Node.js CVE and `dangerouslySetInnerHTML` is an intentional opt-in API, not a vulnerability — "consider removing this entry." `[VERIFICATION_GUIDE.md:1207]` | Full run: 34,380 domains, 86.0% — by far the highest-prevalence attack in the dataset; severity split CRIT 44% / HIGH 37% / MED 19% `[FULL_ANALYSIS_REPORT.md §2]` |

---

## 5. Paper-facing reporting tiers (as already drafted in the pipeline docs)

The full-run report already proposes a three-tier reporting structure for the paper
`[FULL_ANALYSIS_REPORT.md §9]`. Reproduced here verbatim since it is the most direct
input to a validation section:

**Tier 1 — report as confirmed findings:**
`vulnerable_library`, `dangerous_sink`, `open_redirect`, `dom_clobbering` (CRIT+HIGH only),
`prototype_pollution`, `dangling_markup` (CRIT+HIGH only), `html_violation` (HIGH only),
`postmessage_audit`, `service_worker`, `base_tag_hijack`, `form_action_hijack` (HIGH only)

**Tier 2 — report as candidate/heuristic findings with explicit disclosure:**
- `redos` — "heuristic patterns with 90–98% static FP rate (literature figure); trend data is reported, not individual vulnerability counts"
- `meta_refresh_redirect` — "candidate redirects requiring manual triage"
- `dom_clobbering` MEDIUM — "JS_RELIANCE patterns; exploitable where HTML injection is possible"
- `form_action_hijack` MEDIUM — "external form destinations; context-dependent severity"

**Tier 3 — report as pipeline limitations, not findings at all:**
- `clickjacking` — frame-defense status cannot be assessed from archived HTML (header-based defense invisible)
- `css_import_chain` — cannot distinguish attacker-controlled from legitimate CDN imports
- `html_violation` MEDIUM — HTML5-valid patterns flagged by an HTML4-era parser

The sample-run report independently arrived at an equivalent split (§7 of `ANALYSIS_REPORT.md`),
including the additional instruction to report `clickjacking` only as "pages without detectable
frame-busting defenses in HTML content," never as a vulnerability rate.

---

## 6. Gaps to flag explicitly in the paper's validation section

1. **FP disclosure coverage is uneven.** Only 13 of 25 attacks have an explicit FP severity
   rating in `README.md`'s summary table. `VERIFICATION_GUIDE.md` has a "Known false
   positives" subsection for even fewer (clickjacking, html_violation, form_action_hijack,
   dangling_markup, meta_refresh_redirect, css_font_keylog, dom_clobbering, and prototype
   pollution's guard-FP note in the summary table) — the remaining attacks document false
   *negatives* only, which is not the same disclosure and should not be read as "no FP risk."
2. **The 90–98% ReDoS FP figure is a literature citation (Davis et al., ESEC/FSE 2018),
   not a measurement from this pipeline's own data.** The pipeline's own runs report ReDoS
   findings as 100% Candidate-tier / excluded from prevalence trends but do not independently
   verify what fraction are real.
3. **Three different dataset runs, three different totals.** The 50-domain dev run, the
   1,533-domain sample run, and the 39,958-domain full run are not the same data and were
   run with the scanner at different revision points (e.g., `prototype_pollution`'s scanner
   was explicitly upgraded on 2025-04, and `jsonp_callback` severity differs between the
   50-domain run (100% MEDIUM) and the full run (100% HIGH) — this is a scanner-version
   difference, not a data difference, and should be reconciled or disclosed before citing
   both numbers in the same paper).
4. **Several attacks have no prevalence-table entry in either real-data report at all**
   (`missing_sri`, `high_risk_api`, `xpath_injection`, `xslt_injection`) — meaning there is
   currently no measured false-positive-relevant volume for them to cite, positive or negative.
5. **Two findings are individually flagged by the pipeline's own authors as needing manual
   confirmation before being cited as real**, not just as a class-level FP disclosure:
   `www.nyse.com`'s `xml_bomb` finding, and the France-government `open_redirect` outlier
   (53.3%, ~5x any other country) `[FULL_ANALYSIS_REPORT.md §8]`.
