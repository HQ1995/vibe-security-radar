# Deep Verify

Re-verify all confirmed TPs using the single-model deep verifier.

The verifier launches an agentic investigation loop — one strong model with tool access (git log, file read, blame, diff) investigates each BIC before submitting a verdict. This catches false positives that single-pass LLM screening misses.

## Prerequisites

Configure the LiteLLM gateway:
```bash
export LITELLM_API_BASE="http://localhost:8000/v1"
export LITELLM_KEY="sk-..."
export CVE_LLM_MODEL_OVERRIDE="gpt-5.6-luna"
export CVE_LLM_STRICT_MODEL=1
export CVE_REASONING_EFFORT=max
```

Verify with:
```bash
uv run python scripts/e2e_litellm_smoke.py \
  --model gpt-5.6-luna --reasoning-effort max
```
The gateway base and key aliases must resolve to one value. Missing or
conflicting settings stop verification before any model call.
The Luna/max smoke uses the production Responses path and the verifier tool-call
path. Chat/max is recorded as an unsupported compatibility boundary and strict
campaigns never downgrade a failed Responses call to Chat Completions.

## Phase 1: Identify Unverified TPs

Find BICs with AI signals that lack deep verification. Any BIC with AI signals should be deep-verified, regardless of screening verdict (screening is advisory only):

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
    # Select BICs with AI signals (the actual gating criterion for deep verify)
    ai_bics = [b for b in data.get('bug_introducing_commits', [])
               if b.get('commit', {}).get('ai_signals')]
    if not ai_bics:
        continue
    cve_id = data.get('cve_id', f.stem)
    has_verified = any(b.get('deep_verification') for b in ai_bics)
    if has_verified:
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

Run deep verification on each unverified TP. Use background tasks for parallelism (5-10 concurrent to avoid API rate limits).

**Important**: Global flags go BEFORE the subcommand:
```bash
cd cve-analyzer && \
  CVE_LLM_MODEL_OVERRIDE=gpt-5.6-luna \
  CVE_LLM_STRICT_MODEL=1 \
  CVE_REASONING_EFFORT=max \
  uv run cve-analyzer --verbose analyze <CVE-ID> \
    --llm-verify --force-verify --verify-model gpt-5.6-luna
```

Do NOT use `--no-cache` — the pipeline cache saves time by reusing fix commits and blame results. The verifier has its own API cache (`~/.cache/cve-analyzer/api-responses/verifier/`), so previously-verified BICs won't re-call LLMs.

The `--force-verify` flag marks existing verdicts stale before re-verification,
so a failed forced pass cannot publish an earlier verdict. Without it, only
unverified BICs are processed.

The command pins the requested and verifier model to `gpt-5.6-luna`. Strict
mode rejects proxy prefix remapping, model fallback, missing actual-model
metadata, and any observed model that differs from the requested ID.

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

1. Re-run the Phase 1 scan to confirm verification verdicts are now populated
2. Report summary:

```
## Deep Verification Complete

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

Each verification invokes 1 LLM agent making ~10-25 tool calls. Rough estimates per TP:
- ~5,000-15,000 input tokens (context + tool results)
- ~1,000-3,000 output tokens (reasoning + verdict)
- Total: ~6,000-18,000 tokens per TP

Scale linearly with your TP count. At typical API pricing, expect ~$0.05-0.10 per TP.
