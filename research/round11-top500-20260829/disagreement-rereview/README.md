# Round11 disagreement re-research

Scope: the 33 action-bearing cases named by
`../independent-review-disagreement.md`, excluding the five uncontested
comparison rows `w000`, `w001`, `w093`, `w295`, and `w297`.

Workers, exactly:

`w002 w006 w007 w008 w010 w011 w019 w029 w078 w088 w115 w122 w123 w124
w133 w136 w139 w153 w165 w166 w167 w180 w206 w207 w227 w252 w277 w289
w312 w326 w358 w387 w395`

Each worker is researched by one fresh clean-context subagent. A subagent may
read only `docs/AUDIT-PROTOCOL.md`, the exact manifest row, its assigned
primary and independent-review JSON, its section of the disagreement memo,
and that case's first-party advisory, CVE record, repository/clone, commits,
pull request, and release objects. It must not read another case.

Each subagent writes only `wXXX.md` in this directory. Use heavy commands only
under `numactl --cpunodebind=1 --membind=1`.

Required sections, in order:

1. `# wXXX re-research`
2. `## Decision` — `AGREE`, `PARTIAL`, or `DISAGREE` with the disagreement
   memo, plus the recommended primary verdict and review verdict.
3. `## Vulnerability mechanism`
4. `## Atomic BIC and immediate parent`
5. `## Squash or member decomposition`
6. `## Affected and fixed releases`
7. `## Direct fix or unpatched state`
8. `## BIC-only AI attribution`
9. `## Corrections`
10. `## Remaining gap`
11. `## Primary sources`

Every decisive claim must cite a first-party source: an exact local Git object
with full 40-hex SHA, official repository advisory/PR/commit/tag, CVE.org/CNA
record, or vendor release artifact. Secondary summaries are leads only.

`NOT_AI` requires a real vulnerability, the smallest permitted public BIC,
verified immediate-parent absence, and BIC-object signals supporting a named
human writer without AI/bot/generator markers. Positive AI signals must be on
the BIC itself. Fail closed when the atomic BIC cannot be identified, or when
the BIC object has no resolvable named human or AI/bot identity. A named human
author/committer on the BIC, with no Co-Authored-By / Generated-with / bot /
generator marker, closes `NOT_AI`. Absence of an AI trailer is not by itself an
`EVIDENCE_GAP`.
