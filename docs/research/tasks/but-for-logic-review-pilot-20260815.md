# but_for logic-review pilot (2026-08-15)

## Objective

For the 10 scoped cases blocked ONLY by "but_for=NARROW", decide by logic
review whether the AI-authored lines, as originally written, constitute the
advisory mechanism flaw. This pilot does not change any ledger verdict; it
produces review rows for the orchestrator and human final review.

## Inputs

- Cases: .ai-slop/state/cohort-v1/but-for-logic-review-20260815-v1/cases.json
- Stored AI hunks: each case's code_evidence.candidate_hunks. Where the
  stored hunks are empty or non-code (e.g. CHANGELOG.md), fetch the candidate
  commit diff instead.
- Fetch raw diffs with GITHUB_TOKEN (already exported):
  https://github.com/<owner>/<repo>/commit/<sha>.patch

## Protocol (per case)

1. AI lines = lines ADDED by the candidate commit (the "+" hunks), not later
   states of the same file.
2. Mechanism = the advisory's source/guard/sink, read from "mechanism" and
   "description".
3. Single question: do the AI-added lines themselves constitute the mechanism
   flaw (missing/wrong guard, wrong sink, unsafe source handling), or does the
   flaw live in lines added/changed later by others, with the AI lines merely
   a benign stage?
4. Verdict:
   - BUT_FOR_PASS_UPGRADE: AI lines themselves are the mechanism flaw.
   - BUT_FOR_NARROW_RETAIN: flaw is elsewhere, or AI lines are not the
     mechanism, or authorship is mixed without AI being the mechanism part.
   - BLOCKED: cannot fetch or verify the evidence.
5. Evidence: exact "file:line" ranges from both the AI (candidate) diff and
   the fix (minimum_fix_set) diff, plus the mechanism element name.

## Output

Write only into .ai-slop/state/cohort-v1/but-for-logic-review-20260815-v1/:

- results.jsonl, one JSON per case:
  {"case_id","verdict","mechanism_element","ai_refs":[],"fix_refs":[],"reasoning":"<=5 lines"}
- summary.md: table, counts per verdict, BLOCKED reasons.

## Acceptance

- Exactly 10 rows, every PASS backed by line-level refs from BOTH diffs.
- Fail-closed: any doubt -> RETAIN or BLOCKED, never upgrade by default.
- Read-only toward tracked files; do not modify research-data.json or any
  tracked path. Report the output directory path when done.
