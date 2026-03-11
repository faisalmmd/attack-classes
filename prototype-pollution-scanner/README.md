# Prototype Pollution Scanner

Static analysis tool for detecting JavaScript code patterns associated with prototype pollution vulnerabilities and their defenses in archived web snapshots.

## Background

Prototype pollution is a class of JavaScript vulnerability where an attacker injects properties into `Object.prototype` through a merge or assignment operation that doesn't sanitize property keys. Because `Object.prototype` sits at the top of every object's inheritance chain, any property added there becomes visible on all objects in the runtime. The impact ranges from XSS (if the polluted property is rendered to the DOM) to authentication bypass (if something like `isAdmin` gets inherited by the auth check object).

The foundational measurement paper is Kang, Li & Cao's "Probe the Proto: Measuring Client-Side Prototype Pollution Vulnerabilities of One Million Real-world Websites" (NDSS 2022). They crawled the Alexa top 1M, sent crafted prototype-polluting URLs at each site, and observed whether the pollution propagated. They found **2,738 vulnerable sites** - including 10 in the top 1,000. Of those, 48 had gadget chains that led to XSS, 736 could be used for cookie manipulation, and 830 for URL manipulation. These aren't obscure edge cases; they're on major websites.

The vulnerable code pattern is almost always a recursive object merge without sanitizing the keys. Libraries like lodash (before 4.17.11, CVE-2019-10744) and jQuery (before 3.4.0, CVE-2019-11358) had this exact bug in their deep merge implementations. Government sites from 2015-2019 are exactly the age range where these vulnerable library versions were common.

This tool is static analysis, not dynamic testing like Kang et al. did. That means it can't confirm exploitability - for that you'd need taint tracking or active probing. What it does is flag the code structures that make a codebase exploitable if user input reaches them. The for-in-without-hasOwnProperty pattern in particular is a strong signal: 431 JS files in AE alone contain it. Not all are vulnerable, but the ones in merge utility functions that process URL parameters or request bodies are.

The defensive patterns are tracked too. Finding `Object.freeze(Object.prototype)` or hasOwnProperty guards near merge functions means the developer knew about the risk. The absence of those defenses alongside vulnerable patterns is the real finding.

## Detection categories

**VULNERABLE** - code structures that are directly exploitable if user-controlled data reaches them:
- Unsafe for-in loop with bracket assignment (the core pattern)
- jQuery `.extend(true, ...)` deep merge (CVE-2019-11358)
- Lodash `merge()` / `defaultsDeep()` (CVE-2019-10744)
- `Object.prototype[key] = ` direct assignment
- JSON.parse result fed into a merge operation

**INDICATOR** - not inherently exploitable, but warrants a look:
- `__proto__` string references in code
- `.constructor.prototype` access
- `Object.assign()` calls (safe by itself, but often near vulnerable recursive branches)
- General for-in loops (lower confidence than the bracket-assign variant)

**DEFENSIVE** - patterns showing prototype-awareness (good signals):
- `Object.freeze(Object.prototype)`
- `Object.create(null)` for null-prototype dictionaries
- `hasOwnProperty.call()` guards
- Explicit key blocklist checks for `__proto__` and `constructor`

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

# Only vulnerable and indicator patterns (skip defensive INFO rows)
python main.py --all --no-defensive

# Only confirmed VULNERABLE category
python main.py --all --category VULNERABLE

# Skip HTML inline scripts
python main.py --country DE --no-html
```

## Output

Each run produces a timestamped directory under `results/` with:

| File | Contents |
|------|----------|
| `pollution_findings.csv` | One row per pattern match: country, domain, year, timestamp, category, severity, pattern label, line number, context snippet |
| `domain_summary.csv` | One row per (country, domain, year): counts of VULNERABLE/INDICATOR/DEFENSIVE patterns and whether any defense was found |
| `pollution_summary.json` | Aggregate stats by category, pattern, year |

### `domain_summary.csv` - the main analysis table

```
country, domain, year,
vulnerable_patterns, indicator_patterns, defensive_patterns,
forin_bracket_assign_count, jquery_deep_extend_count, lodash_merge_count,
has_any_defense
```

The `has_any_defense` column vs. `vulnerable_patterns` count is the core longitudinal signal: you can see whether domains that had many vulnerable merge patterns also had any defensive code, and whether that changed over the years as awareness of prototype pollution grew (the CVEs landed in 2018-2019, so you'd expect post-2019 code to be more defensive).

## A note on false positives

The for-in-with-bracket-assignment pattern is the highest volume signal and also has the highest false positive rate. A lot of it is internal framework code that iterates over trusted configuration objects, never touching user input. The pattern count per domain is more useful than individual findings - a domain with 50 for-in matches and 0 defensive patterns is a different story than one with 5 for-in matches and 3 defensive patterns. Use `domain_summary.csv` for prioritization and `pollution_findings.csv` for drilling into specific cases.

Cross-referencing with the RetireJS output is important for the jQuery and lodash findings - they're only exploitable if the version present is actually before the patch.
