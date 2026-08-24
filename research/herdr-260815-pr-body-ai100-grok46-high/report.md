# PR-body exact-statement routing census

Lane `herdr-260815-pr-body-ai100-grok46-high`. Frozen commit-first pool 5980. Authority is canonical94 HOLD
and seven-gate CONTRACT SHA256 cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3. This packet inspects
introducing PR bodies and repository-owned comments for complete explicit
authorship statements. It does not call a PASS. Worker PASS is a proposal;
this packet emits none.

## Conservation

5980=17+5348+615
615=16+402+122+75+0
exact_statements=75 selected=75 leftover_exact=0 did_not_pad=true
75=0+0+75
PASS=0 packet_delta=0 canonical94_strict_count=94

Remaining 615 identities after subtracting 17 canonical94 overlaps and 5348
already-terminal pool identities. Autonomous registered bot-authored
introducing PRs are the separate bot-author lane (16). Identities without
an introducing PR number on a frozen candidate commit are 402. Identities
with a human introducing PR but no complete unquoted named-tool statement are
122. Exact statements found: 75. Strongest prefix inspected:
75. No padding.

## Method

1. Start from pinned candidate-pool.jsonl (5980 unique GHSA identities).
2. Exclude canonical94 strict released case ids and every explicit terminal
   verdict already present in 260813/260814/260815 packets other than this lane.
3. Recover introducing PR numbers from frozen GN subject-overlap hits and KN
   ranking rows, plus `(#N)` / Merge pull request subjects on local clones.
4. Fetch public PR bodies and issue comments with existing gh auth. Do not
   print or store credentials.
5. Drop PRs whose author login is a registered autonomous AI bot. Drop review
   bots, labels, templates, quoted lines, fenced code, branch names, generic
   AI discussion, and advisory-listed fix PRs that are not on a candidate.
6. Admit only a complete unquoted line that matches a registered explicit
   attribution marker or Generated/Created/Written/Assisted/Implemented with a
   registered named tool.
7. Rank by marker strength, PR body before repository-owned comment, tool,
   pool ordinal, case id. Inspect up to 100. Do not pad.
8. Map closer-deleted hunks onto an atomic (n_parents=1) member of the
   statement PR. Require ancestor topology, but-for blame overlap, full fix
   reversal of those blamed lines, a vulnerable tag containing the member but
   not the closer, a fixed tag containing the closer, and uniqueness versus
   canonical94.
9. ROUTE only when no gate is FAIL and none is UNKNOWN. Never emit PASS.
   source_policy.pr_body_is_production_evidence remains false.

Public primary sources: GitHub-reviewed advisory JSON at
f2c6ab3202aeafb36fbea6e76d892532acfca1a6, local git objects in shared caches, and public GitHub
PR JSON. Matcher contract ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4.

## ROUTE IDs

None. This packet emits ROUTE 0.

## Inspected prefix

Assigned 75. REJECT_ROUTING 0. ROUTE 0. UNKNOWN 75. PASS 0.

All 75 inspected identities have a first-party repository advisory and an exact
unquoted Claude Code footer on a human-authored introducing PR. GitHub-reviewed
JSON and the first-party advisory object name ecosystem patched versions only.
No same-repository fix commit is present, so closer-deleted hunk mapping,
topology, but-for, reversal, and release stay UNKNOWN. ROUTE requires no gate
FAIL and no UNKNOWN. ROUTE 0.

Reject reasons: {"closer_object_missing": 75}.

Mine buckets: {"bot_author_lane": 16, "exact_statement": 75, "no_exact_pr_body_statement": 122, "no_introducing_pr_number": 402}.

Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
