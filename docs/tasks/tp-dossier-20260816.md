# TP research dossier protocol (2026-08-16)

## Goal

Study each vulnerability completely before any verdict. One vulnerability =
one dossier. No line-overlap shortcuts, no guessing.

## Input

.ai-slop/state/dossier/dossier-<N>.json — rows with case_id, repo,
candidate_sha (optional), fix_sha (optional), public_ids, hint.

## Per vulnerability

1. UNDERSTAND THE VULNERABILITY
   - Fetch the advisory text from OSV (https://api.osv.dev/v1/vulns/<GHSA-id>)
     or local cvelistV5. NEVER use api.github.com - it is rate limited.
   - Write the mechanism in one sentence: source (untrusted input), guard
     (validation/auth), sink (dangerous operation).
   - Note affected and fixed versions.
2. RECONSTRUCT THE TIMELINE
   - introduced_by: find the commit that ADDED the vulnerable mechanism
     (fetch the fix patch, then walk commits touching the same files/lines
     before the fix; verify with the patch that the mechanism lines were
     added there).
   - contributors: other commits that changed the mechanism afterwards.
   - fixed_by: the minimum fix (from the fix patch); state whether the fix
     fully reverses the mechanism.
2b. For commit history walks: git clone --filter=blob:none the repo once, then
   git log -- <file> locally. NEVER use api.github.com repos/commits endpoints.

3. JUDGE AI'S ROLE
   For the introducer commit (and each contributor): author email, commit
   message, trailers, bot/agent markers. Decide: AI introduced / AI
   contributed / AI fixed / AI irrelevant. Marker must sit on the commit
   itself; inherited squash trailers do NOT count.
4. VERDICT
   - B1_AI_FAULT: AI-authored code introduced the mechanism flaw.
   - B2_NOT_AI: introduced by a human, AI not causal.
   - B3_BLOCKED: cannot establish (private history, missing commits).

## Output

.ai-slop/state/dossier/dossier-results-<N>.jsonl — one JSON per case, same
order:

{"case_id","repo","mechanism":"<=1 sentence","source":"...","guard":"...",
 "sink":"...","introduced_by":{"sha","author","date","ai":true|false,
 "marker":"evidence text"},"contributors":[...],"fixed_by":{"sha","complete":true|false},
 "ai_role":"introduced|contributed|fixed|none|unknown",
 "verdict":"B1_AI_FAULT|B2_NOT_AI|B3_BLOCKED",
 "evidence":{"ai_refs":[],"fix_refs":[]},"reasoning":"<=6 lines"}

Never modify tracked files. Reply with output path and verdict counts.

## Acceptance

- Every B1 has introduced_by.sha + marker + line refs.
- Every B2 names the human introducer with evidence.
- Doubt -> B3, never B1/B2.
