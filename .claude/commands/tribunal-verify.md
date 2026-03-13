# Tribunal Verify

Re-verify all confirmed TPs using the multi-model tribunal system.

The tribunal launches 3 independent LLM agents (GPT, Claude, Gemini) that investigate each BIC with tool calls, then aggregates their verdicts via majority vote. This catches false positives that single-model verification misses.

## Prerequisites

At least one LLM backend must be configured:
```bash
# Option 1: LiteLLM proxy (preferred — supports all 3 tribunal models)
export LITELLM_API_BASE="http://localhost:8000/v1"
export LITELLM_API_KEY="sk-..."

# Option 2: Gemini direct
export GEMINI_API_KEY="AIza..."
```

Verify with:
```bash
env | grep -E 'LITELLM|GEMINI_API_KEY'
```
If neither is set, stop and tell the user — tribunal will silently skip without API keys.

## Phase 1: Identify Unverified TPs

Find TPs with confirmed BICs that lack `tribunal_verdict`:

```python
python3 -c "
import json
from pathlib import Path

cache = Path.home() / '.cache/cve-analyzer/results'
unverified = []
verified = []
for f in sorted(cache.glob('*.json')):
    try:
        data = json.loads(f.read_text())
    except (json.JSONDecodeError, ValueError):
        continue
    confirmed = [b for b in data.get('bug_introducing_commits', [])
                 if (b.get('llm_verdict') or {}).get('verdict','').upper() == 'CONFIRMED']
    if not confirmed:
        continue
    cve_id = data.get('cve_id', f.stem)
    has_tribunal = any(b.get('tribunal_verdict') for b in confirmed)
    if has_tribunal:
        verified.append(cve_id)
    else:
        unverified.append(cve_id)

print(f'Verified:   {len(verified)}')
print(f'Unverified: {len(unverified)}')
print()
for cve in unverified:
    print(f'  {cve}')
"
```

If all TPs are already verified, report that and stop.

## Phase 2: Batch Re-Analyze

Run tribunal verification on each unverified TP. Use background tasks for parallelism (5-10 concurrent to avoid API rate limits).

**Important**: Global flags go BEFORE the subcommand:
```bash
cd cve-analyzer && uv run cve-analyzer --verbose analyze <CVE-ID> --llm-verify --force-tribunal
```

Do NOT use `--no-cache` — the pipeline cache saves time by reusing fix commits and blame results, and tribunal results are always saved back (even without `--no-cache`). The tribunal has its own separate API cache (`~/.cache/cve-analyzer/api-responses/tribunal/`), so previously-verified BICs won't re-call LLMs.

The `--force-tribunal` flag bypasses `_should_tribunal()` which normally only runs tribunal for ambiguous BICs. Without it, high-confidence TPs are skipped.

### Execution strategy

1. Take the unverified list from Phase 1
2. Launch them in batches of 5-10 concurrent background tasks
3. Wait for each batch to complete before starting the next
4. After each batch, report: which CVEs completed, any failures, running token totals

### Handling failures

If a CVE fails (timeout, API error, no repo access):
- Log it as skipped with the error reason
- Continue with the remaining CVEs
- Report all skipped CVEs at the end

## Phase 3: Verify and Report

After all batches complete:

1. Re-run the Phase 1 scan to confirm tribunal_verdict is now populated
2. Report summary:

```
## Tribunal Verification Complete

| Metric | Count |
|--------|-------|
| Already verified | X |
| Newly verified | Y |
| Skipped (errors) | Z |
| Total TPs | N |

### Verdict Breakdown
| Verdict | Count |
|---------|-------|
| CONFIRMED (high) | X |
| CONFIRMED (medium) | X |
| UNLIKELY | X |
| UNRELATED | X |

### Token Usage
| Metric | Value |
|--------|-------|
| API calls | X |
| Prompt tokens | X |
| Completion tokens | X |
| Total tokens | X |
| Estimated cost | $X.XX |

### Skipped CVEs
- CVE-XXXX: <reason>
```

3. If any TPs flipped from CONFIRMED to UNLIKELY/UNRELATED, flag them prominently — these may be false positives that need investigation.

## Cost Estimation

Each tribunal run invokes 3 LLM agents, each making ~5-15 tool calls. Rough estimates per TP:
- ~3,000-10,000 input tokens per agent (context + tool results)
- ~500-2,000 output tokens per agent (reasoning + verdict)
- Total: ~10,000-36,000 tokens per TP

For 92 TPs: ~1M-3M tokens total. At typical API pricing, expect $2-10.
