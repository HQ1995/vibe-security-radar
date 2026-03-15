# Independent CVE Audit

Independently verify a CVE analysis result by reading actual code, diffs, and advisories — without reusing any pipeline code. This catches errors that mechanical git-blame + pattern-matching miss, because it reasons about code semantics.

**Arguments**: `$ARGUMENTS` (a CVE ID, or empty to auto-pick one)

## Why This Matters

The pipeline is mechanical: it runs `git blame`, matches AI signal patterns, and runs a single-model deep verifier. But it can't reason about whether the blamed code actually contains the vulnerable pattern, or whether a squash-decomposed AI signal really means the AI commit introduced the bug. This audit fills that gap and accumulates findings to drive pipeline improvements.

## Critical: Bug Introduction vs Fix Authorship

**This audit investigates whether AI-authored code INTRODUCED the vulnerability, NOT whether AI authored the fix.** A common audit error is seeing an AI-authored fix commit (e.g., copilot-swe-agent[bot] submitting a security patch) and concluding "AI involved = CONFIRMED". That is wrong — the question is always: did AI write the code that CAUSED the bug?

## Pipeline Architecture

The pipeline has a 3-tier verdict system:

1. **`verification_verdict`** (deep verifier) — authoritative, single-model investigator with tool access
2. **`tribunal_verdict`** (legacy) — old 3-model voting, kept for backward compatibility
3. **`llm_verdict`** (screening) — **advisory only**, never gates deep verify, never excludes from scoring

Only `UNRELATED` verdicts from verification/tribunal exclude a BIC. `UNLIKELY` means "not sure" — it lowers confidence but does NOT exclude. Screening verdicts never exclude.

## Phase 0: Select Target & Claim

If a CVE ID was provided, use it. Otherwise, use `audit_queue.py` for smart prioritization:

```bash
cd ~/agents/ai-slop/scripts && python3 audit_queue.py
```

This scores candidates by FP risk signals (verifier-overturned, squash-signal, noisy-blame, etc.) and recommends the highest-priority target. The queue automatically excludes CVEs that are already claimed by other audit sessions.

If the script is unavailable, manually pick the first unaudited CVE with AI signals from `~/.cache/cve-analyzer/results/`, prioritizing deep-confirmed over deep-denied over no-deep-verify. Cross-check against `~/.cache/cve-analyzer/audit/findings.json` and `~/.cache/cve-analyzer/audit/claims/` to skip already-audited or in-progress CVEs.

If nothing to audit, report that and stop.

### Claim the target (required for parallel safety)

Before starting analysis, claim the CVE to prevent other sessions from auditing it simultaneously:

```bash
cd ~/agents/ai-slop/scripts && python3 audit_lock.py claim <CVE-ID> --worker "$(hostname)-$$"
```

If the claim fails (another session already claimed it), go back to `audit_queue.py` and pick the next candidate. Do NOT proceed without a successful claim.

## Phase 1: Load Cached Result

Load the cached result from `~/.cache/cve-analyzer/results/<CVE-ID>.json`. If the file does not exist, report that the CVE has no cached analysis, release the claim (`python3 audit_lock.py release <CVE-ID>`), and stop.

Read it and extract:

- `cve_id`, `description`, `severity`, `cwes`
- `fix_commits` — each has `sha`, `repo_url`, `source`
- `bug_introducing_commits` — each has `commit` (with `sha`, `author_name`, `ai_signals`), `blamed_file`, `blame_confidence`, `blame_strategy`, plus verdict fields:
  - `llm_verdict` — screening (advisory only, never authoritative)
  - `verification_verdict` — deep verifier (authoritative, dict with `verdict`/`confidence`/`model`)
  - `tribunal_verdict` — legacy 3-model voting (backward compat, dict with `final_verdict`)

To determine the pipeline's effective verdict for a BIC, check `verification_verdict.verdict` first, fall back to `tribunal_verdict.final_verdict`. Ignore `llm_verdict` for exclusion decisions (it's advisory).

Print a summary of what the pipeline found before starting independent analysis.

## Phase 2: Understand the Vulnerability

This is where you build your independent understanding. Do NOT skip or rush this — everything downstream depends on getting this right.

### 2a. Read the fix diff

Find the local repo clone in `~/.cache/cve-analyzer/repos/`. The directory name is `{owner}_{repo}` (derived from `fix_commits[0].repo_url`).

```bash
cd ~/.cache/cve-analyzer/repos/<owner>_<repo>
git show <fix_sha> --stat   # overview of what changed
git show <fix_sha>          # full diff
```

Read the diff carefully. Understand:
- What files were changed?
- What was the vulnerable code (lines removed/modified)?
- What is the secure replacement (lines added)?
- What is the vulnerability type? (injection, auth bypass, path traversal, etc.)

### 2b. Research the CVE

Search the web for the CVE ID to find:
- NVD/GHSA advisory details
- Security blog posts or write-ups
- The original bug report or disclosure

This gives you independent context that the pipeline doesn't have.

### 2c. Extract vulnerability pattern

Write down explicitly:
- **Vulnerable pattern**: the specific code construct that was insecure (e.g., "user input passed directly to `exec()` without sanitization")
- **Secure pattern**: what the fix replaced it with (e.g., "input validated against allowlist before execution")

This is your ground truth for all subsequent causality analysis.

## Phase 3: Independent Blame

Now find which commits introduced the vulnerable code, independently of the pipeline.

### 3a. Blame the fix diff

For each file in the fix diff, blame the lines that were removed or modified:

```bash
# For a specific line range in the parent of the fix commit
git blame <fix_sha>^ -- <file> -L <start>,<end>
```

Or for the full file context:
```bash
git blame <fix_sha>^ -- <file>
```

Focus on the lines that contain the vulnerable pattern identified in Phase 2.

### 3b. For add-only fixes

If the fix only adds code (e.g., adds a validation check that was missing), use function history:

```bash
git log --follow -p -- <file>
```

Look for who wrote the function that lacked the security check.

### 3c. Compare with pipeline

For each BIC the pipeline found:
- Did your independent blame find the same commit? → `SAME`
- Did you find a different commit? → `DIFFERENT` (explain why)
- Did you find BICs the pipeline missed? → `EXTRA`
- Can you confirm the pipeline's BIC via blame? → If not, `MISSING`

## Phase 4: AI Signal Forensics

For each BIC (both pipeline's and your own), verify AI tool attribution:

```bash
git show --format=fuller <bic_sha> | head -20   # full commit metadata
git log --format="%H %an <%ae> %s" <bic_sha> -1  # author info
```

Check:
1. **Co-author trailers**: Is there a `Co-Authored-By: <AI tool>` line? Is it in the original commit or was it inherited from a squash/merge?
2. **Author email**: Is it an AI tool's noreply address (e.g., `noreply@anthropic.com`, `copilot@users.noreply.github.com`)?
3. **Commit message patterns**: Does it have AI-generated characteristics?

### Squash commit deep-dive (critical)

If the BIC is a squash merge (committer is "GitHub" noreply, or pipeline has `squash_decomposed_*` signals):

This is where the pipeline's biggest blind spot is. The pipeline knows "some commit in this PR was AI-assisted" but can't tell if that specific commit introduced the vulnerability. You can:

1. Find the PR number from the commit message or API cache
2. List individual commits in the PR
3. Read each individual commit's diff
4. Identify which specific commit introduced the vulnerable code from Phase 2
5. Check if THAT specific commit (not just "any commit in the PR") has AI signals

Classify each signal: `REAL_SIGNAL` / `INHERITED` / `FALSE_SIGNAL`

## Phase 5: Causality Analysis

This is the core judgment. For each BIC with AI signals, answer:

**Did the AI-authored code actually introduce the vulnerability?**

Use this decision framework:

| | BIC diff contains vulnerable pattern | BIC diff does NOT contain vulnerable pattern |
|---|---|---|
| **Without this BIC, vulnerability wouldn't exist** | **CONFIRMED** — AI code directly caused the vuln | **UNLIKELY** — vulnerability exists but through different code path |
| **Vulnerability existed before this BIC** | **UNRELATED** — BIC modified vulnerable code but didn't create it | **UNRELATED** — BIC is tangential |

Also consider:
- **Commit size**: A 2000-line commit that touched 50 files has lower causal confidence than a 20-line commit to one security-critical function
- **Code path**: Is the BIC on the actual vulnerable code path, or just in the same file?
- **Temporal**: Was the vulnerable pattern already present before this commit? Check `git blame` on the parent
- **Refactoring**: Did this commit just move code around without changing semantics?

Write your independent verdict: `CONFIRMED` / `UNLIKELY` / `UNRELATED` with confidence `HIGH` / `MEDIUM` / `LOW`.

## Phase 6: Pipeline Comparison & Diagnosis

Now compare your findings with the pipeline's at every layer:

| Layer | Your Finding | Pipeline's Finding | Agreement? |
|-------|-------------|-------------------|------------|
| Fix commit validity | CORRECT/PARTIAL/WRONG | (assumed correct) | |
| Blame (BIC identification) | your BICs | pipeline's BICs | SAME/DIFFERENT |
| AI signals | REAL/INHERITED/FALSE | detected signals | |
| Causality verdict | your verdict | Screening (advisory) | AGREE/DISAGREE |
| | | Deep verify verdict | AGREE/DISAGREE |

**Determining the pipeline's effective verdict**: Use `verification_verdict.verdict` if present, else `tribunal_verdict.final_verdict`. Screening (`llm_verdict`) is advisory only — note it but don't treat it as the pipeline's verdict.

**Common audit pitfalls to avoid**:
- Don't confuse AI fix authorship with AI bug introduction (see top of this skill)
- Don't confuse bundled fix commits — verify the BIC relates to the *specific* CVE vulnerability, not just any bug the fix commit touches
- Don't trust squash-merge AI signals blindly — check if the specific sub-commit that introduced the vulnerable code has AI signals

For each disagreement, diagnose:
- **Which pipeline phase** went wrong?
- **Is it an algorithm problem** (the pipeline logic is flawed) or a **data problem** (bad input data)?
- **What specific code change** would fix it? (file path + description)

## Phase 7: Save Finding

Save the finding atomically using the lock-safe helper (prevents concurrent write corruption):

```bash
cd ~/agents/ai-slop/scripts && python3 -c "
from audit_lock import save_finding
import json, sys
save_finding(json.load(sys.stdin))
print('Saved.')
" <<'FINDING'
<FINDING_JSON>
FINDING
```

Alternatively, manually append to `~/.cache/cve-analyzer/audit/findings.json` if the helper is unavailable. **Warning:** manual append is NOT safe for concurrent sessions — only use when `audit_lock.py` is unavailable and you are the only auditor.

**How to determine `pipeline_verdict`**: Check AI BICs in priority order:
1. If any BIC has `verification_verdict.verdict` == CONFIRMED → pipeline_verdict = "CONFIRMED"
2. Else if any BIC has `tribunal_verdict.final_verdict` == CONFIRMED → pipeline_verdict = "CONFIRMED"
3. If all deep verdicts are UNRELATED → pipeline_verdict = "UNRELATED"
4. If any deep verdict is UNLIKELY (and none CONFIRMED) → pipeline_verdict = "UNLIKELY"
5. If no deep verdicts exist → pipeline_verdict = "NO_DEEP_VERIFY"
6. Screening (`llm_verdict`) is advisory — never use it as `pipeline_verdict`

```json
{
  "cve_id": "CVE-XXXX-XXXXX",
  "timestamp": "ISO-8601",
  "audit_type": "fp_detection",
  "independent_verdict": "CONFIRMED|UNLIKELY|UNRELATED",
  "confidence": "HIGH|MEDIUM|LOW",
  "fix_commit_valid": true,
  "pipeline_verdict": "CONFIRMED|UNLIKELY|UNRELATED|NO_DEEP_VERIFY",
  "agreement": true,
  "stages": {
    "fix_validation": "CORRECT|PARTIAL|WRONG",
    "blame_agreement": "SAME|DIFFERENT|EXTRA|MISSING",
    "signal_verification": "REAL_SIGNAL|INHERITED|FALSE_SIGNAL",
    "causality": "CONFIRMED|UNLIKELY|UNRELATED"
  },
  "disagreement_phase": null,
  "root_cause": null,
  "improvement_suggestions": [],
  "fix_applied": null
}
```

## Phase 7b: Offer Immediate Fix (if actionable)

If `improvement_suggestions` contains changes that could improve the pipeline (algorithm bugs, missing patterns, incorrect logic), ask the user:

> **Actionable improvement found:** <one-line summary>
> Want me to fix this now? (The fix will be recorded in this finding so it won't clutter the Phase 8 pattern report.)

If the user says yes:

1. Implement the fix in the pipeline code
2. Commit with a message referencing the CVE (e.g., `fix: <description>, found via /audit CVE-XXXX-XXXXX`)
3. Update the finding's `fix_applied` field:

```json
{
  "fix_applied": {
    "commit": "<sha>",
    "description": "Brief description of what was changed",
    "files": ["path/to/changed/file.py"]
  }
}
```

If the user says no or the suggestions are minor observations (not code bugs), skip this phase.

Phase 8's pattern analysis should **exclude findings where `fix_applied` is set** from improvement tallies, since those are already resolved.

### Release the claim

After saving the finding (and any Phase 7b fix), release the claim so the CVE shows as completed (not just claimed):

```bash
cd ~/agents/ai-slop/scripts && python3 audit_lock.py release <CVE-ID>
```

If the audit was aborted early for any reason (missing result file, error, etc.), still release the claim before stopping. Claims auto-expire after 2 hours as a fallback, but explicit release is preferred.

## Phase 8: Pattern Analysis (every 10 findings)

After saving, check if there are ≥10 findings. If so, analyze patterns:

```python
python3 -c "
import json; from pathlib import Path
findings = json.loads((Path.home() / '.cache/cve-analyzer/audit/findings.json').read_text())
print(f'Total findings: {len(findings)}')

# Agreement rate
agree = sum(1 for f in findings if f.get('agreement'))
print(f'Agreement rate: {agree}/{len(findings)} ({100*agree/len(findings):.0f}%)')

# Exclude already-fixed findings from improvement tallies
unfixed = [f for f in findings if not f.get('fix_applied')]
fixed = len(findings) - len(unfixed)
if fixed:
    print(f'Already fixed: {fixed} (excluded from improvement counts below)')

# Disagreements by phase (unfixed only)
from collections import Counter
phases = Counter(f.get('disagreement_phase') for f in unfixed if not f.get('agreement'))
print(f'Disagreements by phase: {dict(phases)}')

# Signal type issues
signals = Counter(f['stages'].get('signal_verification') for f in unfixed)
print(f'Signal verification: {dict(signals)}')

# Blame accuracy
blames = Counter(f['stages'].get('blame_agreement') for f in unfixed)
print(f'Blame agreement: {dict(blames)}')
"
```

Then write a brief **Pipeline Accuracy Report** summarizing:
1. Overall agreement rate
2. Most problematic pipeline phase
3. Top improvement recommendations with specific file:line references
4. Patterns: which blame strategies / signal types / vuln types have the most issues

## Output Format

Present results to the user as a structured report:

```markdown
## Audit: <CVE-ID>

### Summary
- **CVE**: <id> — <brief description>
- **Vulnerability**: <type> in <file>
- **Pipeline verdict**: <deep verify verdict> (screening: <screening verdict, advisory>)
- **Independent verdict**: <verdict> (confidence: <X>)
- **Agreement**: YES/NO

### Fix Commit Analysis
<what the fix does, is it valid>

### Blame Analysis
<your independent blame vs pipeline's, any discrepancies>

### AI Signal Verification
<are the signals real, inherited, or false>

### Causality Chain
<detailed reasoning about whether the AI code INTRODUCED the vulnerability — not whether AI authored the fix>

### Pipeline Diagnosis
<if disagreement: what went wrong, which phase, root cause>

### Improvement Suggestions
<specific, actionable suggestions with affected file paths>
```

## Phase 9: Regression Verification (after improvements)

When audit findings led to pipeline code changes that have since been implemented, re-run the pipeline on the triggering CVE(s) to verify the fixes work.

**When to trigger**: After Phase 7 save, check if the current CVE's `improvement_suggestions` from a previous audit led to code changes (check git log for related commits). If so, run this phase.

**Steps**:

1. Re-run the analyzer on the triggering CVE with `--no-cache`:
```bash
cd ~/agents/ai-slop/cve-analyzer
uv run cve-analyzer --no-cache analyze <CVE-ID> --llm-verify --force-verify
```

2. Load the new result and compare against the original audit finding:
```python
python3 -c "
import json; from pathlib import Path
new = json.loads((Path.home() / '.cache/cve-analyzer/results/<CVE-ID>.json').read_text())
findings = json.loads((Path.home() / '.cache/cve-analyzer/audit/findings.json').read_text())
old = next((f for f in findings if f['cve_id'] == '<CVE-ID>'), None)
if old:
    new_bics = len(new.get('bug_introducing_commits', []))
    print(f'BIC count: {old.get(\"notes\",\"\").split(\"BIC\")[0]} → {new_bics}')
    new_signals = [s for b in new.get('bug_introducing_commits',[]) for s in b.get('commit',{}).get('ai_signals',[])]
    print(f'AI signals: {len(new_signals)}')
    if old['stages'].get('blame_agreement') == 'MISSED_BIC':
        print('Check: was the missed BIC found this time?')
    if old['stages'].get('signal_verification') == 'FALSE_SIGNAL':
        print('Check: are false signals eliminated?')
"
```

3. Compare key metrics:
   - **BIC count**: should decrease (less noise) or stay same (if issue was signal, not blame)
   - **True BIC**: if was `MISSED_BIC`, should now be found
   - **False signals**: if was `FALSE_SIGNAL`, should be gone
   - **Verdict alignment**: should now agree with independent verdict

4. Update the finding in `findings.json` with regression results:
```json
{
  "regression_verified": true,
  "regression_timestamp": "ISO-8601",
  "regression_result": "IMPROVED|NO_CHANGE|REGRESSED",
  "regression_details": "BIC count 20→7, true BIC now found"
}
```

5. If regression fails (no improvement or got worse), flag for investigation and note in improvement_suggestions.

## Integration with /loop

This skill works with `/loop 30m /audit` to continuously audit CVEs. Each run picks the next unaudited CVE, runs the full analysis, saves the finding, and periodically produces pattern analysis reports.
