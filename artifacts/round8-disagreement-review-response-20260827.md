# Round8 disagreement review — second-model response (Claude session, 2026-08-27)

Responds to: artifacts/round8-independent-disagreements-20260827.md
All git claims below re-verified inside the local clones this session
(no fetch; path-scoped only). Ledger NOT touched.

## Return format

```
P1: a
P2: w156=BLOCKED  w186=BLOCKED  w147=NEED_GIT(resolved below: NOT_AI, new BIC)

w020: OVERTURN  clean commit object; codex/* branch name is delivery metadata, not an on-BIC signal -> NOT_AI
w195: OVERTURN  6cca70b23c (Christian Kreuzberger, no markers) is the first writer of the unauth --http handler -> NOT_AI
w156: AGREE     helm chart contains zero JS; baseUrl is chart-level config passthrough; sink lives in closed langsmith-frontend -> BLOCKED
w186: AGREE     assigned clone (ironic-python-agent) has no molds.py and objects to 15e20fe (fatal: not our ref); BIC judged in a different repo than the packet row -> BLOCKED for w186 as assigned
w147: OVERTURN  NOT_AI stands, but the BIC changes: 5ba6f2ef87 (see below). EVIDENCE_GAP is moot once this commit is found.
w169: AGREE_NOT_CATALOG  PR-body checkbox is real (verified via gh api) but is not an on-commit-object signal under P1=a-only -> NOT_AI stands
```

catalog_ai_tps: w076, w080, w166  (exactly the three unpatched MCP cases)

## P1 — which signals are "on the BIC"

- **(a) commit-object trailers / Generated-with: YES.** Repo-checked ground truth exists on the object itself.
- **(b) GitHub squash trailer: NO.** The squash is an aggregate; the protocol already forbids it as BIC, so its trailer cannot carry AI judgment. Verified for w195: `git rev-parse 00b7649^{tree}` == `4935d64^{tree}` (member tip) — the squash adds zero content; its Copilot trailer describes a member commit (`d2e79dd`) that changes one line (`let body: unknown = undefined` -> `let body: unknown`), a type tweak unrelated to the unauth handler.
- **(c) source-branch name codex/*: NO.** Branch names are delivery metadata, not commit-object content. Verified: PR #18771 head branch is `codex/fix-public-role-global-grants`, but all branch commits (84ae2210, b715ef87, b0f7dfdf, d63d1d90, 9de9e1f5) are authored by Peter Clement with zero AI trailers. Counter-evidence on the convention itself: of Budibase's 37 sampled merged codex/* PRs, bodies are silent about AI, PR titles use `[codex]` prefix, and repo docs never define codex/* as an AI convention (148 `[codex]`-tagged commit subjects, all human authors: Dakuan et al.). The convention is at best suggestive, at worst a naming habit for security-fix batches. Cannot carry a terminal verdict.
- **(d) PR-body gen-AI checkbox: NO.** Verified w169's PR #61398 body does say "Claude Code with Opus 4.5" (gh api, checked this session). But the protocol's phrase "signals on that BIC" naturally reads as the commit object; a PR description is a separate artifact about the PR, not about the commit that first wrote the lines. Airflow makes disclosure mandatory, which makes the checkbox a high-quality *lead*, not proof of authorship of the vulnerable lines (the 9-member branch contains 8 sibling commits by the same author; which member wrote the flaw is established by git, and its object is clean).

Round8 used (a)+(b)+(c); independent used (a)+(d). This review: **(a) only.**

## P2 — no-BIC terminals

- **w156 helm: BLOCKED.** Verified: `git ls-tree` of the helm repo at be02862 contains no TS/JS at all; the commit only adds chart config passthrough (`baseUrl: ""` in values.yaml, configmap env wiring). The vulnerable sink (SPA sending bearer token to query-param-controlled origin) is in `langsmith-frontend`, closed source. A helm commit cannot be the BIC of a frontend flaw. Round8's `NOT_AI` judged a commit that never wrote the sink.
- **w186 ironic-python-agent: BLOCKED (as assigned).** Verified: IPA clone has zero `molds.py` in history (`git log --all -- '*molds.py'` empty), no Ironic version tags (only eol/eom tags), and `15e20fe` is not in the clone (`fatal: not our ref`). The record itself writes repo `openstack/ironic` while `cases-202.jsonl` line 186 says `ironic-python-agent` — a canon-field mismatch inside round8's own record. Correct terminal for the packet row: BLOCKED. If the Ironic mis-map is worth keeping as knowledge, re-packet it as a new case; do not silently retarget.
- **w147 mayan-edms: NOT-Grok — NOT_AI on a better BIC.** Grok's EVIDENCE_GAP presumes the only writer is the undecomposable squash 9f8c7cb9. That premise is false. New git finding, fully verified this session:
  - `5ba6f2ef87` (2020-12-29, "Improve AJAX content escape logic", single-parent eb476c15, plain human commit by Roberto Rosario, Signed-off-by only, no AI trailers) FIRST wrote `window.location = uriFragment` — parent tree has zero `uriFragment` hits in `mayan/apps/appearance/templates/appearance/base_plain.html` (grep verified), and `-S` over `5ba6f2e~1` for that path is empty.
  - It is reachable from `origin/master` (merge-base verified) via the series/3.3/3.4 merge chain, parallel to (not an ancestor of) the squash 9f8c7cb9 (2021-01-23), which re-writes the same lines as part of its 1572-file aggregate.
  - The squash's `+ window.location = uriFragment` hunk is the same lines arriving on the master side; protocol calls a re-carrying aggregate a carrier.
  - Terminal: `NOT_AI`, `introducer_sha` = `5ba6f2ef878dabb3cd44bbe749277b05d3f53229`, `squash_decomposed` may stay false; the story is now fully decomposed by git itself. No EVIDENCE_GAP, no BLOCKED needed.

## Catalog consequence

Published AI TPs from this 202-set: **exactly w076, w080, w166** — the three unpatched MCP cases with Generated-with Claude Code on the BIC object. Round8's two AI_CODE_FLAWED rows drop to NOT_AI; BLOCKED grows by w156, w186; w147 stays NOT_AI with a corrected BIC.

## Suggested ledger edits (not applied; matches Grok list with w147 changed)

1. w020, w195: AI_CODE_FLAWED -> NOT_AI
2. w195 `introducer_sha` -> `6cca70b23c068cd862ec0420d126387eed0436d6`
3. w156, w186: NOT_AI -> BLOCKED; clear in-clone introducer_sha
4. w147: keep NOT_AI; `introducer_sha` -> `5ba6f2ef878dabb3cd44bbe749277b05d3f53229`; evidence += parallel-writer note (5ba6f2e on dev branch merged via series/3.3/3.4 chain; 9f8c7cb9 is the master-side parallel write/carrier)
5. w169: stays NOT_AI unless Hanqing rules PR-body disclosure in-scope (policy call, not a git call)
6. Re-run `python3 scripts/publish_tp_ledger.py` only after edits land
