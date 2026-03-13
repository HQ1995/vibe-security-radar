# Independent CVE Audit

Independently verify a CVE analysis result by reading actual code, diffs, and advisories — without reusing any pipeline code. This catches errors that mechanical git-blame + pattern-matching miss, because it reasons about code semantics.

**Arguments**: `$ARGUMENTS` (a CVE ID, or empty to auto-pick one)

## Why This Matters

The pipeline is mechanical: it runs `git blame`, matches AI signal patterns, and votes. But it can't reason about whether the blamed code actually contains the vulnerable pattern, or whether a squash-decomposed AI signal really means the AI commit introduced the bug. This audit fills that gap and accumulates findings to drive pipeline improvements.

## Phase 0: Select Target

If a CVE ID was provided, use it. Otherwise, use the audit queue script for smart prioritization:

```bash
python3 scripts/audit_queue.py
```

This scores candidates by FP risk signals (tribunal-overturned, squash-signal, noisy-blame, etc.) and recommends the highest-priority target. Use the CVE ID from its "Next:" recommendation.

If the script is unavailable, fall back to this selection logic:

```python
python3 -c "
import json, os; from pathlib import Path

cache = Path.home() / '.cache/cve-analyzer/results'
audit_path = Path.home() / '.cache/cve-analyzer/audit/findings.json'

# Load already-audited CVEs
audited = set()
if audit_path.exists():
    for f in json.loads(audit_path.read_text()):
        audited.add(f.get('cve_id',''))

# Bucket unaudited CVEs by priority
tribunal_confirmed = []  # Priority 1: on website, FP hurts credibility
tribunal_overturned = [] # Priority 2: tribunal said no but LLM said yes — possible FN
unverified = []          # Priority 3: has AI signals, no tribunal yet

for f in sorted(cache.glob('*.json')):
    try: data = json.loads(f.read_text())
    except: continue
    cve_id = data.get('cve_id', f.stem)
    if cve_id in audited: continue
    if data.get('error'): continue

    ai_bics = [b for b in data.get('bug_introducing_commits', [])
               if b.get('commit',{}).get('ai_signals')]
    if not ai_bics: continue

    has_tribunal_confirmed = any(
        (b.get('tribunal_verdict') or {}).get('final_verdict','').upper() == 'CONFIRMED'
        for b in ai_bics)
    has_tribunal_denied = any(
        (b.get('tribunal_verdict') or {}).get('final_verdict','').upper() in ('UNLIKELY','UNRELATED')
        for b in ai_bics)
    has_llm_confirmed = any(
        (b.get('llm_verdict') or {}).get('verdict','').upper() == 'CONFIRMED'
        for b in ai_bics)

    if has_tribunal_confirmed:
        tribunal_confirmed.append(cve_id)
    elif has_tribunal_denied and has_llm_confirmed:
        tribunal_overturned.append(cve_id)
    elif has_llm_confirmed:
        unverified.append(cve_id)

print(f'Unaudited: {len(tribunal_confirmed)} tribunal-confirmed, {len(tribunal_overturned)} overturned, {len(unverified)} unverified')
pick = (tribunal_confirmed or tribunal_overturned or unverified or [None])[0]
if pick: print(f'Selected: {pick}')
else: print('Nothing to audit.')
"
```

If nothing to audit, report that and stop.

## Phase 1: Load Cached Result

Load the cached result from `~/.cache/cve-analyzer/results/<CVE-ID>.json`. Read it and extract:

- `cve_id`, `description`, `severity`, `cwes`
- `fix_commits` — each has `sha`, `repo_url`, `source`
- `bug_introducing_commits` — each has `commit` (with `sha`, `author_name`, `ai_signals`), `blamed_file`, `blame_confidence`, `blame_strategy`, `llm_verdict`, `tribunal_verdict`

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
| Causality verdict | your verdict | LLM verdict | AGREE/DISAGREE |
| | | Tribunal verdict | AGREE/DISAGREE |

For each disagreement, diagnose:
- **Which pipeline phase** went wrong?
- **Is it an algorithm problem** (the pipeline logic is flawed) or a **data problem** (bad input data)?
- **What specific code change** would fix it? (file path + description)

## Phase 7: Save Finding

Save the structured finding to `~/.cache/cve-analyzer/audit/findings.json` (create the file/directory if needed, append to existing array):

```json
{
  "cve_id": "CVE-XXXX-XXXXX",
  "timestamp": "ISO-8601",
  "independent_verdict": "CONFIRMED|UNLIKELY|UNRELATED",
  "confidence": "HIGH|MEDIUM|LOW",
  "fix_commit_valid": true,
  "pipeline_verdict": "CONFIRMED|UNLIKELY|UNRELATED",
  "agreement": true,
  "stages": {
    "fix_validation": "CORRECT|PARTIAL|WRONG",
    "blame_agreement": "SAME|DIFFERENT|EXTRA|MISSING",
    "signal_verification": "REAL_SIGNAL|INHERITED|FALSE_SIGNAL",
    "causality": "CONFIRMED|UNLIKELY|UNRELATED"
  },
  "disagreement_phase": null,
  "root_cause": null,
  "improvement_suggestions": []
}
```

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

# Disagreements by phase
from collections import Counter
phases = Counter(f.get('disagreement_phase') for f in findings if not f.get('agreement'))
print(f'Disagreements by phase: {dict(phases)}')

# Signal type issues
signals = Counter(f['stages'].get('signal_verification') for f in findings)
print(f'Signal verification: {dict(signals)}')

# Blame accuracy
blames = Counter(f['stages'].get('blame_agreement') for f in findings)
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
- **Pipeline verdict**: <verdict> (confidence: <X>)
- **Independent verdict**: <verdict> (confidence: <X>)
- **Agreement**: YES/NO

### Fix Commit Analysis
<what the fix does, is it valid>

### Blame Analysis
<your independent blame vs pipeline's, any discrepancies>

### AI Signal Verification
<are the signals real, inherited, or false>

### Causality Chain
<detailed reasoning about whether the AI code caused the vulnerability>

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
uv run cve-analyzer --no-cache analyze <CVE-ID>
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
