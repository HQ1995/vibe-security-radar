# Pipeline Monitor

Lightweight health check for a running or recently-completed CVE analyzer batch. Designed for `/loop 2m /monitor`.

## Execution

**IMPORTANT: Always run this as a background Bash command** (`run_in_background: true`) to avoid polluting the main context window. Do NOT use a sub-agent — just run bash directly in the background.

```bash
bash /home/hanqing/agents/ai-slop/scripts/monitor.sh
```

If the script doesn't exist or fails, fall back to this inline version:

```bash
NOW=$(date +%H:%M)
PIDS=$(pgrep -f 'cve.analyzer' 2>/dev/null)
LOAD=$(cat /proc/loadavg | cut -d' ' -f1)
MEM_PCT=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
GIT_PROCS=$(pgrep -c git 2>/dev/null || echo 0)
CACHE_DIR="$HOME/.cache/cve-analyzer/results"
TOTAL=0; RECENT=0; ERRORS=0; PHASE="unknown"
if [ -d "$CACHE_DIR" ]; then
    TOTAL=$(find "$CACHE_DIR" -name '*.json' 2>/dev/null | wc -l)
    RECENT=$(find "$CACHE_DIR" -name '*.json' -mmin -5 2>/dev/null | wc -l)
fi
if [ -n "$PIDS" ]; then
    if [ "$TOTAL" -eq 0 ]; then PHASE="setup"
    elif [ "$RECENT" -gt 0 ]; then PHASE="processing"
    else PHASE="blame/clone (no new results)"
    fi
    STATUS="RUNNING"
    [ "$RECENT" -eq 0 ] && [ "$TOTAL" -gt 0 ] && STATUS="STALLED?"
else
    STATUS="IDLE"
    PHASE="done"
fi
echo "[$NOW] $STATUS | $TOTAL cached | +$RECENT/5min | phase: $PHASE | load $LOAD | mem ${MEM_PCT}% | git $GIT_PROCS"
```

## Reporting to user

- **IDLE / no changes from last check**: Say NOTHING to the user. Completely silent. Do not respond at all.
- **RUNNING and healthy**: One-line status summary, only if status changed from previous check.
- **STALLED or ALERT**: Surface the full output and flag prominently.

Do NOT dump raw monitor output into the main conversation. Only notify user on state transitions or alerts.

## Output format

Single line:
```
[HH:MM] STATUS | N cached | +N/5min | phase: X | load X | mem X% | git X
```

Status values:
- **RUNNING** — pipeline active, results flowing
- **STALLED?** — pipeline active but no new results in 5min (likely blame/clone phase on large repos)
- **IDLE** — pipeline not running
