# TP mining: rebuild code_evidence (2026-08-15)

## Goal

Build the full code_evidence object for cases that lack one. Everything comes
from the two patches; do not invent anything. Fetch, extract, report.

## Input

.ai-slop/state/evidence-lists/ev-<N>.json — rows with case_id, repo,
candidate_sha, fix_sha, mechanism, references.

## Per case

1. Fetch candidate patch:
   curl -sS -m 60 -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://github.com/<repo>/commit/<candidate_sha>.patch"
2. Fetch fix patch the same way.
3. Split each patch on "diff --git " into per-file hunks. Drop hunks whose
   file matches: package(-lock).json, *.lock, CHANGELOG, README, *.md, docs/,
   LICENSE. Cap total stored size to 45000 chars per side, keep largest first.
4. ai_marker: exact marker line(s) from the candidate commit header/message
   (Co-Authored-By, agent signature, "[AI]", bot/agent author). Empty string
   when none.
5. fix_marker: same for the fix commit.
6. steps: [{"title":"AI change","detail":candidate subject},
   {"title":"Fix","detail":fix subject}].
7. summary: the case mechanism field verbatim (first 160 chars).

## Output

.ai-slop/state/evidence-lists/ev-results-<N>.jsonl — one JSON per case, same
order, with keys:

{"case_id","advisory_url","candidate_url","fix_url",
 "ai_marker","fix_marker","candidate_hunks":[{"annotation":"","code":...}],
 "fix_hunks":[...],"comparison_hunks":[...],
 "candidate_patch_sha256","fix_patch_sha256","steps":[...],"summary"}

- advisory_url: the first github.com/advisories/ reference if present, else "".
- candidate_url/fix_url: https://github.com/<repo>/commit/<sha>.
- sha256: hex digest of the raw patch text as fetched.
- hunks use exactly {"annotation":"","code":"diff --git ..."} shape.

Fetch failures: write the case with empty hunks and a "fetch_error" note in
summary. Never modify tracked files. Reply with the output path and counts.

## Acceptance

- One line per input row, same case_id set, valid JSON.
- Every non-empty hunk starts with "diff --git ".
