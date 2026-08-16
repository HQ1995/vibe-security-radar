# TP mining Lane A: fix recovery for unresolved rows (2026-08-16)

## Goal

For each unresolved advisory row, recover the exact fix commit (and, where
possible, an AI candidate commit). Fail-closed: anything not recovered stays
unrecovered, never guessed.

## Input

.ai-slop/state/laneA/laneA-<N>.json — rows with class_id, public_ids,
reason_code, reason.

## Protocol (per row, budget max 6 network calls)

1. LOCAL FIRST: grep the class_id in
   autoresearch/orchestrator-260810-0613/audit-review/prioritized-ai-edges.jsonl
   (19k rows). If edges exist, take candidate_sha/fix_sha/repository_identity
   from the first RESOLVED edge and skip to step 4.
2. Advisory lookup: curl -sS -m 25 -H "Authorization: Bearer $GITHUB_TOKEN"
   "https://api.osv.dev/v1/vulns/<GHSA-id>". Read fixed version and
   references (fix commit links).
3. Fallbacks: OSV https://api.osv.dev/v1/vulns/<GHSA-or-CVE> ; then NVD
   https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>. Extract
   github.com/<owner>/<repo>/commit/<sha> references.
4. Verify the fix commit exists: curl the .patch URL, expect "From <sha>" in
   the first lines.
5. AI candidate: only when the advisory/mechanism hints AI involvement —
   check the fix commit's parent commits for AI markers (Co-Authored-By,
   "[AI]", agent emails) touching the same files. Bounded: 2 extra calls.

## Output

.ai-slop/state/laneA/laneA-results-<N>.jsonl — one JSON per input row, same
order:

{"class_id","public_ids","repo","fix_sha","candidate_sha",
 "recovered": true|false, "source":"edges|ghsa|osv|nvd|none", "note":"<=80 chars"}

Never modify tracked files. Reply with the output path and recovered counts.

## Acceptance

- One line per input row, class_id set matches exactly.
- recovered=true requires a verified fix sha (patch fetch OK).
