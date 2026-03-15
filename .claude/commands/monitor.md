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
PIDS=$(pgrep -f 'cve.analyzer' 2>/dev/null || true)
LOAD=$(cut -d' ' -f1 /proc/loadavg)
MEM_PCT=$(free | awk '/Mem/{printf "%.0f", 100*$3/$2}')
GIT_PROCS=$(pgrep -c git 2>/dev/null || echo 0)
CACHE_DIR="$HOME/.cache/cve-analyzer/results"
TOTAL=0; RECENT=0
if [ -d "$CACHE_DIR" ]; then
    TOTAL=$(find "$CACHE_DIR" -name '*.json' 2>/dev/null | wc -l)
    RECENT=$(find "$CACHE_DIR" -name '*.json' -mmin -5 2>/dev/null | wc -l)
fi
if [ -n "$PIDS" ]; then
    if [ "$TOTAL" -eq 0 ]; then PHASE="setup"
    elif [ "$RECENT" -gt 5 ]; then PHASE="active (writing results)"
    elif [ "$GIT_PROCS" -gt 1 ]; then PHASE="blame/clone (git active)"
    else PHASE="prefetch/enrich (API calls)"
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

When RUNNING:
```
  recent: N BIC
  recent: N ERR
[HH:MM] RUNNING | N cached | +N/5min | phase: X | load X | mem X% | git X
```

When IDLE (full summary):
```
[HH:MM] IDLE | N cached | phase: done | load X | mem X% | git X
  fixes: N | signals: N | BICs: N | verified: N
  verdicts: UNLIKELY N, UNRELATED N, CONFIRMED N
  ai_tools: claude_code N, github_copilot N, ...
  no_fix_commits: N
  success: N
  inference: N runs — FOUND=N, NOT_FOUND=N, NO_TAGS=N — N BICs from FOUND
  website: N true positives | N analyzed | N with fix commits
  website tools: claude_code=N, github_copilot=N, ...
```

Key metrics:
- **true positives** — CVEs displayed on the website with confirmed AI involvement
- **signals** — CVEs where AI authorship signals were detected in BICs
- **inference** — AI-inferred fix commit discovery stats (FOUND = LLM identified the real fix commit)
- **BICs from FOUND** — new bug-introducing commits discovered via AI inference

Status values:
- **RUNNING** — pipeline active, results flowing
- **STALLED?** — pipeline active but no new results in 5min (likely blame/clone phase on large repos)
- **IDLE** — pipeline not running
