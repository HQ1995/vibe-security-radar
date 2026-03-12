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

# --- Error category breakdown (full cache) ---
if [ "$STATUS" = "IDLE" ] && [ "$TOTAL" -gt 0 ]; then
    echo "[$NOW] $STATUS | $TOTAL cached | phase: $PHASE | load $LOAD | mem ${MEM_PCT}% | git $GIT_PROCS"
    python3 -c "
import json
from pathlib import Path
from collections import Counter
cache = Path.home() / '.cache/cve-analyzer/results'
cats = Counter()
signals = fixes = tribunal = 0
for f in cache.glob('*.json'):
    try:
        d = json.loads(f.read_text())
    except: continue
    cat = d.get('error_category', 'success' if d.get('fix_commits') else 'no_data')
    cats[cat] += 1
    if d.get('ai_signals'): signals += 1
    if d.get('fix_commits'): fixes += 1
    for b in d.get('bug_introducing_commits', []):
        if b.get('tribunal_verdict'): tribunal += 1
print(f'  fixes: {fixes} | signals: {signals} | tribunal: {tribunal}')
for cat, n in cats.most_common():
    print(f'  {cat}: {n}')
" 2>/dev/null
else
    echo "[$NOW] $STATUS | $TOTAL cached | +$RECENT/5min | phase: $PHASE | load $LOAD | mem ${MEM_PCT}% | git $GIT_PROCS"
fi
