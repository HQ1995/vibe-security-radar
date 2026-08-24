# Worker spec: final adjudication of the 9 UNKNOWN fp211 ordinals

Owner: this directory only. You are a proposal worker, not the ledger.

## Assigned set (fixed, do not expand)

Ordinals 35, 51, 53, 56, 84, 116, 129, 153, 154 from
autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl.
Do not touch any other row. Do not mine new candidates.

## Inputs (read-only)

- Gates: autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
  (seven-gate definition and the AI_INCOMPLETE_REMEDIATION patch-delta rule).
- Row evidence: the nine rows above (decisive_evidence, counterevidence,
  replay_commands, per-gate status).
- Audit context: autoresearch/orchestrator-260813-fp211-audit/FINAL_REPORT.md.

## Evidence sourcing - NO GitHub API

The GitHub REST/GraphQL API is rate-limited and must not be used. No gh api,
no curl api.github.com. Use, in this order:

1. Existing local clones: search
   /home/hanqing/.cache/ghsa200-worker-clones/*/<owner>__<repo> and run the
   row's replay_commands against the matching clone.
2. Local advisory data: the frozen advisory-database clones under
   /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database,
   commit-af/advisory-database, and fresh-delta20-grok46-low/advisory-database
   (advisories/github-reviewed/2025|2026/*.json), plus the local OSV caches
   .ai-slop/cache/osv-advisory-fix-index-v1/ and
   .ai-slop/cache/osv-advisory-observations-v3/.
3. Git smart-HTTP only for missing objects: shallow, blobless, single-repo
   fetch into work/: git clone --filter=blob:none --no-checkout <https-url>
   work/<owner>__<repo> then git fetch --depth 1 origin <sha> (deepen bounded
   by 2000 commits if the SHA is not advertised). No full clones; host disk
   has about 14G free.

For each ordinal, independently re-derive all seven gates from first-party
evidence (advisory object, commit hunks, release containment), not from the
stored per-gate labels.

Final verdict per row: CONFIRM, NARROW, FALSE_POSITIVE, or UNKNOWN, plus a
confidence and, for FALSE_POSITIVE, the false_positive_class from the audit's
tag vocabulary. UNKNOWN stays UNKNOWN when evidence cannot close a gate;
never convert missing evidence into a negative.

## Outputs (English only)

- result.json: per-ordinal gate matrix + final verdict + counts + a terminal
  flag. Rows that stay UNKNOWN are terminal=false.
- cases.jsonl: one proposal row per ordinal.
- report.md: what closed, what stayed open, per-gate failures, and any
  disagreement with the stored labels.

## Hard constraints

- Never edit anything outside this owned directory. Never touch canonical84,
  fp211-audit, fp211-canonical, web/, scripts/, or other campaigns.
- Never git commit, push, reset, or checkout in this repository or in clones.
- Worker PASS/CONFIRM is a proposal only; the leader independently verifies
  before any integration.
- No credential printing or storage.
