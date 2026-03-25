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

**Do not assume you know the pipeline's data format.** Read the code and data to find out.

### 2a. Understand how the pipeline represents its conclusion

Read the pipeline's data model and scoring logic to understand the current schema:
- `cve-analyzer/src/cve_analyzer/models.py` — data structures (what fields exist, how verdicts/signals are stored)
- `cve-analyzer/src/cve_analyzer/scoring.py` — how confidence is computed, what verdict fields are checked

This tells you which fields carry the pipeline's conclusion and how to interpret them.

### 2b. Read the cached result

```bash
cat ~/.cache/cve-analyzer/results/<CVE-ID>.json | python3 -m json.tool
```

Using your understanding from 2a, extract:
- What origin commits did the pipeline find?
- What AI signals did the pipeline detect, and on which commits?
- What is the pipeline's verdict and confidence?

### 2c. Compare

- **Did the pipeline find the same origin commit you found?** If not, why?
- **Did the pipeline detect AI involvement that you didn't, or vice versa?**
- **Is the pipeline's confidence score appropriate for what you found?**

Classify any discrepancy with a short tag (e.g. `shallow-blame`, `wrong-fix`, `signal-on-fix`, `cosmetic-blame`, `scoring-bug`, `stale-cache`, `correct`). Don't use a fixed taxonomy — describe what actually happened.

## Phase 3: Save Finding & Release

### 3a. Learn the current finding format

Read existing findings to match their format:
```bash
python3 -c "
import json; from pathlib import Path
p = Path.home() / '.cache/cve-analyzer/audit/findings.json'
if p.exists():
    findings = json.loads(p.read_text())
    if findings:
        print(json.dumps(findings[-1], indent=2))
    else:
        print('Empty findings list')
else:
    print('No findings file yet')
"
```

If findings exist, match the existing schema exactly. If no findings exist, use this minimal format:
```json
{
  "cve_id": "<CVE-ID>",
  "verdict": "CONFIRMED|UNLIKELY|UNRELATED|NO_AI|FIX_ONLY",
  "confidence": "HIGH|MEDIUM|LOW",
  "reasoning": "<your independent analysis>",
  "pipeline_agrees": true|false,
  "pipeline_verdict": "<what the pipeline concluded, in its own terms>",
  "notes": "<discrepancy details, root cause if disagreement, null if agreement>",
  "auditor": "audit-agent",
  "timestamp": <unix timestamp>
}
```

### 3b. Save and release

```bash
cd ~/agents/ai-slop/scripts && python3 -c "
from audit_lock import save_finding
import json, sys
save_finding(json.load(sys.stdin))
print('Saved.')
" <<'FINDING'
<your finding JSON here>
FINDING
```

Release claim (always, even on error):
```bash
cd ~/agents/ai-slop/scripts && python3 audit_lock.py release <CVE-ID>
```

Verify release:
```bash
cd ~/agents/ai-slop/scripts && python3 audit_lock.py check <CVE-ID>
```

## Phase 4: Pattern Analysis

Run after every 10th saved finding. Read findings, then compute stats dynamically based on whatever fields exist:

```bash
python3 -c "
import json; from pathlib import Path; from collections import Counter
p = Path.home() / '.cache/cve-analyzer/audit/findings.json'
findings = json.loads(p.read_text()) if p.exists() else []
total = len(findings)
if total % 10 != 0:
    print(f'Total: {total} (next analysis at {total + (10 - total % 10)})')
else:
    print(f'=== Audit Analysis (n={total}) ===')
    # Agreement rate — try common field names, skip entries missing the field
    agree_key = next((k for k in ['pipeline_agrees', 'agreement'] if any(k in f for f in findings)), None)
    if agree_key:
        has_field = [f for f in findings if agree_key in f]
        agree = sum(1 for f in has_field if f[agree_key])
        n = len(has_field)
        print(f'Agreement: {agree}/{n} ({100*agree/n:.0f}%) — {total - n} entries lack field')
    # Verdict distribution
    verdict_key = next((k for k in ['verdict', 'independent_verdict'] if any(k in f for f in findings)), None)
    if verdict_key:
        verdicts = Counter(f.get(verdict_key) for f in findings)
        print(f'Verdicts: {dict(verdicts)}')
    # Confidence distribution
    if any('confidence' in f for f in findings):
        confs = Counter(f.get('confidence') for f in findings)
        print(f'Confidence: {dict(confs)}')
    # Disagreement notes (for manual review)
    disagree = [f for f in findings if not f.get(agree_key, True)] if agree_key else []
    if disagree:
        print(f'Disagreements ({len(disagree)}):')
        for f in disagree[-5:]:
            note = f.get('notes', f.get('root_cause', '?'))
            print(f'  {f.get(\"cve_id\", \"?\")}: {str(note)[:100]}')
"
```
