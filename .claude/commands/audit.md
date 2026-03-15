# Independent CVE Audit

Independently determine whether AI-authored code introduced a security vulnerability. Then compare your conclusion with the pipeline's to find pipeline blind spots.

**Arguments**: `$ARGUMENTS` (a CVE ID, or empty to auto-pick one)

## Critical Rules

1. **DO NOT read the pipeline's cached result until you have finished your own investigation.** Reading it first will anchor your thinking and make you replicate the pipeline's blind spots. The whole point of this audit is independence.

2. **AI fixing a bug ≠ AI causing a bug.** AI co-author on a fix commit means AI helped remediate, not introduce.

3. **Time-box to 30 minutes.** If you can't determine the origin after 30 min of tracing, save a partial finding with `confidence: "LOW"` and move on.

## Phase 0: Select Target & Claim

If a CVE ID was provided, use it. Otherwise:
```bash
cd ~/agents/ai-slop/scripts && python3 audit_queue.py
```

Claim before starting:
```bash
cd ~/agents/ai-slop/scripts && python3 audit_lock.py claim <CVE-ID> --worker "$(hostname)-$$"
```

If claim fails, pick the next candidate. On ANY early exit (error, timeout, missing data), release the claim before stopping.

## Phase 1: Independent Investigation (do this FIRST)

Get fix commit SHAs and repo URL — read ONLY these fields, not the full result:
```bash
jq '{fix_commits: [.fix_commits[] | {sha, repo_url}]}' ~/.cache/cve-analyzer/results/<CVE-ID>.json
```

If this fails (file missing, null fix commits), release claim and stop.

### 1a. Understand the vulnerability

Read the fix diff in `~/.cache/cve-analyzer/repos/<owner>_<repo>/`:
```bash
git show <fix_sha> --stat    # overview
git show <fix_sha>            # full diff
```

If multiple fix commits exist, check each — find the one with the actual security fix (not changelogs/tests). Identify:
- The **vulnerable code pattern** (the specific insecure construct)
- The **secure replacement** (what the fix changed it to)
- The **vulnerability type** (injection, auth bypass, path traversal, etc.)

### 1b. Trace the vulnerable code to its origin

You are a security researcher. Trace the vulnerable code to the commit that FIRST introduced the insecure pattern. Use whatever git forensics you need:

- Search the repo history for when the vulnerable pattern first appeared
- Trace code through file moves, renames, and extractions
- Check if blamed commits are the true origin or just moved/reformatted existing code
- Look at the full file history, not just the current file

**Think like a detective, not a script runner.** The pipeline already ran `git blame` on the fix-commit files — if you do the same thing mechanically, you'll get the same (possibly wrong) answer.

### 1c. Check AI involvement on origin commit(s)

For each origin commit found:
```bash
git show --format=fuller <origin_sha> | head -30
```

Check for: `Co-Authored-By` trailers (Claude, Copilot, etc.), bot author emails (`noreply@anthropic.com`, `Copilot@users.noreply.github.com`), AI markers in commit message (`Generated with [Claude Code]`, `[AI-assisted]`).

If the origin is a squash merge, decompose it and check which sub-commit actually wrote the vulnerable code.

### 1d. Verify causality

Confirm the origin commit actually CREATED the vulnerability (not just modified existing vulnerable code):
```bash
# Did the vulnerable pattern exist BEFORE this commit?
git show <origin_sha>^:<file> 2>/dev/null | grep '<vulnerable_pattern>'
```

If the pattern existed before → the commit is not the true origin. Keep tracing back.

## Phase 2: Compare with Pipeline (do this AFTER Phase 1)

Now read the full cached result:
```bash
cat ~/.cache/cve-analyzer/results/<CVE-ID>.json | python3 -m json.tool
```

Compare:
- **Did the pipeline find the same origin commit you found?** If not, why?
- **Did the pipeline detect AI involvement that you didn't, or vice versa?**
- **Is the pipeline's confidence score appropriate for what you found?**

**Pipeline verdict**: check `verification_verdict.verdict` first, fall back to `tribunal_verdict.final_verdict`. Screening (`llm_verdict`) is advisory only.

Classify any discrepancy:
- **SHALLOW_BLAME**: Pipeline blamed a move/copy commit, true origin is earlier/in a different file
- **WRONG_FIX**: Pipeline used wrong fix commit from OSV/GHSA
- **SIGNAL_ON_FIX**: Pipeline detected AI on fix commit, confused with bug introduction
- **COSMETIC_BLAME**: Pipeline blamed AI commit that only touched docs/tests/formatting
- **SCORING_BUG**: Pipeline found the right data but computed wrong confidence
- **STALE_CACHE**: Pipeline result is outdated
- **CORRECT**: Pipeline and audit agree

## Phase 3: Save Finding & Release

```bash
cd ~/agents/ai-slop/scripts && python3 -c "
from audit_lock import save_finding
import json, sys
save_finding(json.load(sys.stdin))
print('Saved.')
" <<'FINDING'
{
  "cve_id": "<CVE-ID>",
  "timestamp": "<ISO-8601>",
  "independent_verdict": "CONFIRMED|UNLIKELY|UNRELATED|NO_AI|FIX_ONLY",
  "confidence": "HIGH|MEDIUM|LOW",
  "vulnerability_type": "<CWE or description>",
  "fix_commit_valid": true,
  "pipeline_verdict": "<from verification_verdict or tribunal_verdict>",
  "agreement": <true|false>,
  "stages": {
    "fix_validation": "CORRECT|PARTIAL|WRONG",
    "blame_agreement": "SAME|DIFFERENT|EXTRA|MISSING|SHALLOW",
    "signal_verification": "REAL_SIGNAL|INHERITED|FALSE_SIGNAL|FIX_ONLY",
    "causality": "CONFIRMED|UNLIKELY|UNRELATED"
  },
  "disagreement_phase": "<blame|signal|causality|null>",
  "root_cause": "<explanation if disagreement, null otherwise>",
  "improvement_suggestions": [
    {"suggestion": "...", "priority": "FIX|OBSERVE|WONTFIX", "rationale": "..."}
  ],
  "fix_applied": null
}
FINDING
```

`fix_applied` is set when a pipeline code fix is implemented based on this finding. Format: `{"commit": "<sha>", "description": "...", "files": ["..."]}`. Leave null if no fix was made.

Release claim (always, even on error):
```bash
cd ~/agents/ai-slop/scripts && python3 audit_lock.py release <CVE-ID>
```

Verify release:
```bash
cd ~/agents/ai-slop/scripts && python3 audit_lock.py check <CVE-ID>
```

## Phase 4: Pattern Analysis

Run after every 10th saved finding:

```python
python3 -c "
import json; from pathlib import Path; from collections import Counter
findings = json.loads((Path.home() / '.cache/cve-analyzer/audit/findings.json').read_text())
total = len(findings)
if total % 10 != 0:
    print(f'Total: {total} (next analysis at {total + (10 - total % 10)})')
else:
    print(f'Total: {total}')
    agree = sum(1 for f in findings if f.get('agreement'))
    print(f'Agreement: {agree}/{total} ({100*agree/total:.0f}%)')
    unfixed = [f for f in findings if not f.get('fix_applied')]
    phases = Counter(f.get('disagreement_phase') for f in unfixed if not f.get('agreement'))
    print(f'Disagreements by phase: {dict(phases)}')
    blames = Counter(f['stages'].get('blame_agreement') for f in unfixed)
    print(f'Blame accuracy: {dict(blames)}')
    # Check for OBSERVE items that should promote to FIX (>=3 occurrences)
    suggestions = Counter()
    for f in unfixed:
        for s in f.get('improvement_suggestions', []):
            if isinstance(s, dict) and s.get('priority') == 'OBSERVE':
                suggestions[s.get('suggestion', '')[:80]] += 1
    promotable = {k: v for k, v in suggestions.items() if v >= 3}
    if promotable:
        print(f'Promote OBSERVE->FIX (>=3 occurrences): {promotable}')
"
```
