#!/usr/bin/env python3
"""
Run prototype_pollution attack on data/ and write results.
Usage: python run_pp.py
"""
import sys, os, json, csv, time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from driver import PipelineDriver, format_text, format_matrix

BASE   = os.path.dirname(os.path.abspath(__file__))
DATA   = os.path.join(BASE, 'data')
OUTDIR = os.path.join(BASE, 'results', 'prototype_pollution')
os.makedirs(OUTDIR, exist_ok=True)

ATTACK = 'prototype_pollution'

print(f'[*] Scanning {DATA} ...')
t0 = time.time()
driver = PipelineDriver()
all_findings = driver.scan_all(DATA)
elapsed = time.time() - t0
print(f'[*] Done in {elapsed:.1f}s  -- total findings (all attacks): {len(all_findings)}')

pp = [f for f in all_findings if f.test_name == ATTACK]
print(f'[*] {ATTACK}: {len(pp)} findings')

# ── 1. Evidence report (full text, filtered to this attack) ──────────────────
by_domain = defaultdict(list)
for f in pp:
    rel = os.path.relpath(os.path.abspath(f.file_path), os.path.abspath(DATA))
    domain = rel.replace('\\', '/').split('/')[0]
    by_domain[domain].append(f)

evidence_lines = []
evidence_lines.append('=' * 70)
evidence_lines.append(f'  PROTOTYPE POLLUTION -- EVIDENCE REPORT')
evidence_lines.append(f'  Dataset : data/  ({len(os.listdir(DATA))} domains, 1,206 snapshots)')
evidence_lines.append(f'  Scan time: {elapsed:.1f}s')
evidence_lines.append(f'  Total findings : {len(pp)}')
evidence_lines.append(f'  Domains affected : {len(by_domain)} / {len(os.listdir(DATA))}')
evidence_lines.append('=' * 70)

for domain in sorted(by_domain):
    findings = by_domain[domain]
    evidence_lines.append('')
    evidence_lines.append(f'DOMAIN: {domain}  ({len(findings)} findings)')
    evidence_lines.append('-' * 50)
    for f in sorted(findings, key=lambda x: (x.file_path, x.line_number)):
        rel_file = os.path.relpath(os.path.abspath(f.file_path), os.path.abspath(DATA))
        evidence_lines.append(f'  [FOUND] [{f.severity}] {f.description}')
        evidence_lines.append(f'    File   : {rel_file}')
        evidence_lines.append(f'    Line   : {f.line_number}')
        evidence_lines.append(f'    Code   : {f.line_content[:120]}')

evidence_path = os.path.join(OUTDIR, 'evidence.txt')
with open(evidence_path, 'w', encoding='utf-8') as fh:
    fh.write('\n'.join(evidence_lines) + '\n')
print(f'[*] Evidence written -> {evidence_path}')

# ── 2. Per-domain CSV summary ────────────────────────────────────────────────
csv_rows = []
all_domains = sorted(os.listdir(DATA))
severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
for domain in all_domains:
    domain_findings = by_domain.get(domain, [])
    sev_counts = defaultdict(int)
    pattern_counts = defaultdict(int)
    for f in domain_findings:
        sev_counts[f.severity] += 1
        # Extract short pattern label from description
        label = f.description.split(' - ')[0][:60]
        pattern_counts[label] += 1
    csv_rows.append({
        'domain': domain,
        'total_findings': len(domain_findings),
        'CRITICAL': sev_counts['CRITICAL'],
        'HIGH': sev_counts['HIGH'],
        'MEDIUM': sev_counts['MEDIUM'],
        'affected': 1 if domain_findings else 0,
        'top_pattern': max(pattern_counts, key=pattern_counts.get) if pattern_counts else '',
    })

csv_path = os.path.join(OUTDIR, 'domain_summary.csv')
with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
    w = csv.DictWriter(fh, fieldnames=['domain','total_findings','CRITICAL','HIGH','MEDIUM','affected','top_pattern'])
    w.writeheader()
    w.writerows(csv_rows)
print(f'[*] Domain summary -> {csv_path}')

# ── 3. Attack matrix (prototype_pollution column only) ────────────────────────
matrix_path = os.path.join(OUTDIR, 'attack_matrix.csv')
with open(matrix_path, 'w', newline='', encoding='utf-8') as fh:
    w = csv.writer(fh)
    w.writerow(['domain', 'prototype_pollution'])
    for domain in all_domains:
        w.writerow([domain, 1 if domain in by_domain else 0])
print(f'[*] Attack matrix   -> {matrix_path}')

# ── 4. JSON summary ──────────────────────────────────────────────────────────
sev_totals = defaultdict(int)
pattern_totals = defaultdict(int)
for f in pp:
    sev_totals[f.severity] += 1
    label = f.description.split(' - ')[0][:60]
    pattern_totals[label] += 1

summary = {
    'attack': ATTACK,
    'data_directory': DATA,
    'scan_time_seconds': round(elapsed, 1),
    'total_findings': len(pp),
    'domains_affected': len(by_domain),
    'domains_total': len(all_domains),
    'by_severity': dict(sev_totals),
    'by_pattern': dict(sorted(pattern_totals.items(), key=lambda x: -x[1])),
    'domains_with_findings': sorted(by_domain.keys()),
}
summary_path = os.path.join(OUTDIR, 'summary.json')
with open(summary_path, 'w', encoding='utf-8') as fh:
    json.dump(summary, fh, indent=2)
print(f'[*] Summary JSON    -> {summary_path}')

print()
print('=' * 70)
print(f'  PROTOTYPE POLLUTION RESULTS')
print('=' * 70)
print(f'  Domains affected : {len(by_domain)} / {len(all_domains)}')
print(f'  Total findings   : {len(pp)}')
print()
print('  By severity:')
for sev in ('CRITICAL', 'HIGH', 'MEDIUM'):
    print(f'    {sev:<10} {sev_totals.get(sev, 0)}')
print()
print('  By pattern (top 8):')
for pat, cnt in list(sorted(pattern_totals.items(), key=lambda x: -x[1]))[:8]:
    print(f'    {cnt:>5}  {pat}')
print('=' * 70)
