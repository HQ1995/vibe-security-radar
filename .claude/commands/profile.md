# Pipeline Performance Profiler

Post-run performance analysis. Use after batch runs to identify bottlenecks and measure optimization impact.

## Context

Pipeline phases:
```
Setup (OSV/GHSA/NVD load) → Pass 1 (Discovery) → Clone → Pass 2a (Blame) → PR prefetch → Pass 2b (Enrich/LLM/Tribunal)
```

Config: workers=min(32, cpu_count), git_throttle=32, rate limits: GH REST 1.39/s, GraphQL 0.5/s, NVD 1.5/s.

## Execution

Run this single comprehensive profiler script. ONE command, ONE confirmation:

```bash
python3 /home/hanqing/agents/ai-slop/scripts/profile.py
```

If the script doesn't exist, inform the user and run inline (see Fallback below).

## Report

After running the script, present results as a structured report:

```markdown
# Performance Report — YYYY-MM-DD

## Timeline
- Wall time: Xs (first→last result)
- Setup overhead: estimated Xs (before first result)
- Throughput: X results/min

## Phase Timing
| Phase | n | mean | p50 | p95 | total | % |
|-------|---|------|-----|-----|-------|---|

## Bottlenecks
1. ...

## Top 5 Repo Hotspots
| Repo | CVEs | Blame time | Errors |
|------|------|------------|--------|

## Error Categories
| Category | Count | % |
|----------|-------|---|

## Recommendations
- [ ] ...
```

Focus diagnosis on:
1. **Wall time vs CPU time ratio** — >2x means setup/rate-limiter overhead dominates
2. **Phase B (blame) p95 vs mean** — large gap = outlier repos dragging things down
3. **Error categories** — which are fixable vs expected
4. **Concurrency efficiency** — load avg vs cores, are workers idle

## Fallback (inline)

If `scripts/profile.py` doesn't exist, run these as a single python3 inline:

```python
python3 -c "
import json, statistics, time
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

cache = Path.home() / '.cache/cve-analyzer/results'
if not cache.exists() or not any(cache.glob('*.json')):
    print('No results to profile.'); exit()

files = sorted(cache.glob('*.json'), key=lambda f: f.stat().st_mtime)
total = len(files)

# --- Timeline ---
first_t = files[0].stat().st_mtime
last_t = files[-1].stat().st_mtime
wall = last_t - first_t

# --- Phase timing ---
phase_times = defaultdict(list)
error_cats = Counter()
sources = Counter()
repo_blame = defaultdict(lambda: {'blame': 0, 'cves': 0, 'errors': 0})
signals = tribunal_v = 0

for f in files:
    try:
        d = json.loads(f.read_text())
    except Exception:
        continue
    for phase, dur in d.get('phase_times', {}).items():
        if isinstance(dur, (int, float)):
            phase_times[phase].append(dur)
    cat = d.get('error_category') or ('success' if d.get('fix_commits') else 'no_data')
    error_cats[cat] += 1
    for fc in d.get('fix_commits', []):
        sources[fc.get('source', '?')] += 1
        repo = fc.get('repo_url', '?').replace('https://github.com/', '')
        repo_blame[repo]['cves'] += 1
        repo_blame[repo]['blame'] += d.get('phase_times', {}).get('Phase B (blame)', 0)
    if d.get('error'):
        for fc in d.get('fix_commits', []):
            repo_blame[fc.get('repo_url','?').replace('https://github.com/','')]['errors'] += 1
    if d.get('ai_signals'): signals += 1
    for b in d.get('bug_introducing_commits', []):
        if b.get('tribunal_verdict'): tribunal_v += 1

# --- Results timeline ---
buckets = defaultdict(int)
for f in files:
    m = int((f.stat().st_mtime - first_t) / 60)
    buckets[m] += 1

# --- Print ---
cpu_total = sum(sum(v) for v in phase_times.values())
print(f'=== Timeline ===')
print(f'Results: {total} | Signals: {signals} | Tribunal verdicts: {tribunal_v}')
print(f'Wall time (first→last): {wall:.0f}s ({wall/60:.1f}min)')
print(f'CPU time (sum phases):  {cpu_total:.0f}s ({cpu_total/60:.1f}min)')
print(f'Parallelism factor:     {cpu_total/max(wall,1):.1f}x')
print(f'Throughput:             {total/max(wall,1)*60:.1f} results/min')
print()

if phase_times:
    print(f'=== Phase Timing ===')
    print(f'{\"Phase\":25s} {\"n\":>5s} {\"mean\":>7s} {\"p50\":>7s} {\"p95\":>7s} {\"total\":>8s} {\"pct\":>5s}')
    print('-' * 65)
    for phase in sorted(phase_times):
        t = phase_times[phase]
        n = len(t)
        s = sorted(t)
        tot = sum(s)
        print(f'{phase:25s} {n:>5d} {statistics.mean(s):>6.1f}s {s[n//2]:>6.1f}s {s[min(int(n*0.95),n-1)]:>6.1f}s {tot/60:>7.1f}m {tot/cpu_total*100:>4.0f}%')
    print()

print(f'=== Error Categories ===')
for cat, n in error_cats.most_common():
    print(f'  {cat:25s} {n:>5d} ({n*100//total:>2d}%)')
print()

print(f'=== Fix Sources ===')
for src, n in sources.most_common():
    print(f'  {src:25s} {n:>5d}')
print()

top_repos = sorted(repo_blame.items(), key=lambda x: -x[1]['blame'])[:10]
if top_repos and any(r[1]['blame'] > 0 for r in top_repos):
    print(f'=== Top Repo Hotspots ===')
    for repo, s in top_repos:
        if s['blame'] > 0:
            print(f'  {repo:50s} {s[\"cves\"]:>3d} CVEs  {s[\"blame\"]/60:>5.1f}m blame  {s[\"errors\"]:>2d} err')
    print()

if buckets:
    print(f'=== Throughput Timeline ===')
    for m in range(max(buckets.keys()) + 1):
        c = buckets.get(m, 0)
        print(f'  min {m:>2d}: {c:>4d} {\"#\" * min(c, 80)}')
"
```
