#!/bin/bash
# Pipeline monitor — single command, rich output
set -euo pipefail

NOW=$(date +%H:%M)
CACHE_DIR="$HOME/.cache/cve-analyzer/results"
API_DIR="$HOME/.cache/cve-analyzer/api-responses"

# --- Process status ---
PIDS=$(pgrep -f 'cve.analyzer' 2>/dev/null || true)
LOAD=$(cat /proc/loadavg | cut -d' ' -f1)
MEM_PCT=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
GIT_PROCS=$(pgrep -c git 2>/dev/null || echo 0)

# --- Cache stats ---
TOTAL=0; RECENT=0; ERRORS=0; SIGNALS=0; NO_FIX=0; HAS_BLAME=0
if [ -d "$CACHE_DIR" ]; then
    TOTAL=$(find "$CACHE_DIR" -name '*.json' 2>/dev/null | wc -l)
    RECENT=$(find "$CACHE_DIR" -name '*.json' -mmin -5 2>/dev/null | wc -l)

    # Quick scan of recent files for errors/signals
    if [ "$RECENT" -gt 0 ]; then
        for f in $(find "$CACHE_DIR" -name '*.json' -mmin -5 2>/dev/null | tail -20); do
            python3 -c "
import json, sys
d = json.loads(open('$f').read())
if d.get('error'): print('ERR')
elif d.get('ai_signals'): print('SIG')
elif d.get('bug_introducing_commits'): print('BIC')
elif not d.get('fix_commits'): print('NOFIX')
else: print('OK')
" 2>/dev/null
        done | sort | uniq -c | while read count label; do
            echo "  recent: $count $label"
        done
    fi
fi

# --- Phase detection ---
PHASE="unknown"
if [ -n "$PIDS" ]; then
    if [ "$TOTAL" -eq 0 ]; then
        PHASE="setup (loading OSV/GHSA/NVD)"
    elif [ "$RECENT" -gt 5 ]; then
        PHASE="active (writing results)"
    elif [ "$GIT_PROCS" -gt 1 ]; then
        PHASE="blame/clone (git active)"
    else
        PHASE="prefetch/enrich (API calls)"
    fi
    STATUS="RUNNING"
    if [ "$RECENT" -eq 0 ] && [ "$TOTAL" -gt 0 ]; then
        STATUS="STALLED?"
    fi
else
    STATUS="IDLE"
    PHASE="done"
fi

# --- Full summary (IDLE) or one-liner (RUNNING) ---
if [ "$STATUS" = "IDLE" ] && [ "$TOTAL" -gt 0 ]; then
    echo "[$NOW] $STATUS | $TOTAL cached | phase: $PHASE | load $LOAD | mem ${MEM_PCT}% | git $GIT_PROCS"
    python3 -c "
import json
from pathlib import Path
from collections import Counter

home = Path.home()
cache = home / '.cache/cve-analyzer/results'
infer_dir = home / '.cache/cve-analyzer/fix-inference'
web_stats = home / 'agents/ai-slop/web/data/stats.json'

# --- Pipeline results ---
cats = Counter()
verdicts = Counter()
signals = fixes = verified = bic_total = 0
ai_tools = Counter()
for f in cache.glob('*.json'):
    try:
        d = json.loads(f.read_text())
    except: continue
    cat = d.get('error_category') or ('success' if d.get('fix_commits') else 'no_data')
    cats[cat] += 1
    if d.get('ai_signals'): signals += 1
    if d.get('fix_commits'): fixes += 1
    bics = d.get('bug_introducing_commits', [])
    bic_total += len(bics)
    for b in bics:
        vv = b.get('deep_verification') or b.get('verification_verdict')
        tv = b.get('tribunal_verdict')
        if vv:
            verified += 1
            verdicts[vv.get('verdict', '?')] += 1
        elif tv:
            verified += 1
            verdicts['tribunal:' + tv.get('verdict', '?')] += 1
        for s in b.get('commit', {}).get('ai_signals', []):
            ai_tools[s.get('tool', '?')] += 1

print(f'  fixes: {fixes} | signals: {signals} | BICs: {bic_total} | verified: {verified}')
if verdicts:
    parts = [f'{v} {n}' for v, n in verdicts.most_common()]
    print(f'  verdicts: {', '.join(parts)}')
if ai_tools:
    parts = [f'{t} {n}' for t, n in ai_tools.most_common(5)]
    print(f'  ai_tools: {', '.join(parts)}')
for cat, n in cats.most_common():
    print(f'  {cat}: {n}')

# --- AI fix inference ---
if infer_dir.exists():
    infer_stats = Counter()
    infer_bics = 0
    for f in infer_dir.glob('*.json'):
        try:
            d = json.loads(f.read_text())
            infer_stats[d.get('status', '?')] += 1
            if d.get('status') == 'FOUND':
                sha = d.get('result', {}).get('sha', '')
                rp = cache / f'{d[\"cve_id\"]}.json'
                if rp.exists():
                    rd = json.loads(rp.read_text())
                    infer_bics += len(rd.get('bug_introducing_commits', []))
        except: continue
    total_infer = sum(infer_stats.values())
    if total_infer:
        parts = [f'{k}={v}' for k, v in sorted(infer_stats.items())]
        print(f'  inference: {total_infer} runs — {', '.join(parts)} — {infer_bics} BICs from FOUND')

# --- Website stats ---
if web_stats.exists():
    try:
        ws = json.loads(web_stats.read_text())
        tp = ws.get('total_cves', 0)
        analyzed = ws.get('total_analyzed', 0)
        wfc = ws.get('with_fix_commits', 0)
        by_tool = ws.get('by_tool', {})
        tool_str = ', '.join(f'{t}={n}' for t, n in sorted(by_tool.items(), key=lambda x: -x[1])[:5])
        print(f'  website: {tp} true positives | {analyzed} analyzed | {wfc} with fix commits')
        print(f'  website tools: {tool_str}')
    except: pass
" 2>/dev/null
else
    echo "[$NOW] $STATUS | $TOTAL cached | +$RECENT/5min | phase: $PHASE | load $LOAD | mem ${MEM_PCT}% | git $GIT_PROCS"
fi
