# Round8 independent disagreements — review brief

Date: 2026-08-27
Audience: a second model, judging independently. Do not rubber-stamp
round8 or this brief. Re-trace git if you disagree.

This file is the disagreement set only. Full 202-case landing notes live in
`artifacts/round8-independent-double-confirm-20260826.md`. The ledger
(`artifacts/funnel-account-20260817.jsonl`) has **not** been rewritten.

## Your job

For each numbered case below, return `AGREE` / `OVERTURN` / `NEED_GIT`
against `docs/AUDIT-PROTOCOL.md`. Then answer the two policy questions.

Do **not** spend budget on SHA-hygiene rows (squash recorded as BIC while
verdict stays `NOT_AI`). Those are listed in the double-confirm report
under “Record defects that do not flip the verdict”. They are out of
scope unless you find one that should flip a verdict.

## Protocol (the whole rule)

From `docs/AUDIT-PROTOCOL.md`:

> Vulnerability first, AI second. … The BIC is the smallest commit that
> first wrote the vulnerable lines — a move, refactor, revert, or squash
> aggregate is not a BIC. Judge the AI role from signals **on that BIC
> only**.

Ledger terminals in `docs/DATA-SCHEMA.md`: `AI_ROOT_CAUSE` |
`AI_CODE_FLAWED` | `NOT_AI` | `BLOCKED`. TP classes are the first two.
This brief also uses `EVIDENCE_GAP` for one undecomposed squash (not a
schema terminal; say whether you would map it to `BLOCKED` instead).

Catalog implication if this brief stands: public AI TPs from this 202-set
are **exactly three unpatched MCP cases**. Round8’s two `AI_CODE_FLAWED`
rows drop out.

## Not in dispute (do not reopen unless you have new evidence)

| Worker | Repo | Round8 | Independent | Why they match |
|---|---|---|---|---|
| w076 | anubissbe/projecthub-mcp | AI_ROOT_CAUSE | AI_ROOT_CAUSE | BIC `31dd902d1234046c7145d4b693d93b5003d4bf64` first wrote `fetch(webhook.url)`; Claude Code trailer on that commit; still at HEAD |
| w080 | hulupeep/mcp-ui-probe | AI_ROOT_CAUSE | AI_ROOT_CAUSE | BIC `ada347ec04db0f15d2477ef8dc4904f71d072465` added unsanitized `journeyId` path join; Claude Code trailer; unpatched |
| w166 | astralisone/rive-mcp-server-core | AI_ROOT_CAUSE | AI_ROOT_CAUSE | BIC `db1d0cc4cd52589116360428b7504fd0ca748b3e` (= HEAD) unsanitized `libraryId` path; Claude Code trailer; unpatched |
| w087 | anthropics/claude-code | BLOCKED | BLOCKED | `CoworkVMService` not in the public repo |
| w189 | guardrails-ai/guardrails | BLOCKED | BLOCKED | PyPI `0.10.1` never appears in git tags / `pyproject.toml` history |

## Headline

| Verdict | Round8 | Independent catalog stance |
|---|---|---|
| AI_ROOT_CAUSE | 3 | **3** (w076, w080, w166). w169 is policy-open, not catalog |
| AI_CODE_FLAWED | 2 | **0** |
| BLOCKED | 2 | **4** (add w156, w186) |
| EVIDENCE_GAP | 0 | **1** (w147) |
| NOT_AI | 195 | **194** catalog |

Packet identity: `.ai-slop/state/research-queue/round8/cases-202.jsonl`
line *i* = worker `w{i:03d}`. Round8 claimed fields:
`artifacts/round8-independent-review-index-20260826.json`.

---

## 1. w020 budibase/budibase — `AI_CODE_FLAWED` → `NOT_AI`

- Advisory: GHSA-j9fc-w3mr-x6mv
- class_id: `alias-2b40c4ee123d2f0e6d472ed8`
- Round8 BIC = independent BIC: `84ae2210cfe16896997db6ab8295afab91e1f392`
- Fix: `453391d3245dd04cc386ccd6959d38ccf30db9a8`

**Bug.** Public role-assign endpoints authorize with a flag-level
allowlist (`validateGlobalRoleUpdate` checks `admin` / similar) while
`assign()` already forwarded `appBuilder` / `role` since 2023. Incomplete
allowlist is the flaw.

**Round8 AI story.** Raw commit has no trailer. Round8 still called
`AI_CODE_FLAWED` because PR #18771 was merged from branch
`codex/fix-public-role-global-grants` (Budibase `codex/*` convention).

**Independent.** Author Peter Clement, empty trailers, no `Generated with`.
Protocol: AI is judged from signals **on the BIC**, not delivery-branch
naming. Same off-commit class as w169.

**Question.** Does a `codex/*` source-branch name, with a clean commit
object, count as an on-BIC AI signal?

Independent answer: **no** → `NOT_AI`.

---

## 2. w195 dynatrace-oss/dynatrace-mcp — `AI_CODE_FLAWED` → `NOT_AI`

- Advisory: GHSA-p7w7-4929-vpj5
- class_id: `alias-f6fc802d874a73bfd4258bf2`
- Round8 recorded BIC: `00b7649a78aba78c578af4e128b38f7bae18a059`
  (GitHub squash of PR #107; Copilot trailer on the squash)
- Round8 `decomposed_shas`:
  `6cca70b23c068cd862ec0420d126387eed0436d6`,
  `d2e79dd7b49facab72b8752f8da96c780d1e9806`,
  `10ccab5e344abcbe8301a165cc85f34ce5e96536`,
  `4935d6467b1b341cb8c4faf17db1e9ff5c4561ab`
- Independent BIC: `6cca70b23c068cd862ec0420d126387eed0436d6`
  (Christian Kreuzberger, **no** AI marker)
- Copilot member `d2e79dd7…`: `let body: unknown = undefined` →
  `let body: unknown` (type tweak, not the unauth HTTP handler)
- Fix `8f129724…` has Claude trailer; correctly demoted (fix, not BIC)

**Bug.** `--http` serves JSON-RPC on `StreamableHTTPServerTransport`
with no auth.

**Question.** Is the squash with Copilot trailer the BIC, or the earlier
human first-writer of the unauthenticated handler?

Independent answer: first-writer `6cca70b23c…` → `NOT_AI`. Round8
violated “squash aggregate is not a BIC” and then judged AI on the
squash trailer.

---

## 3. w156 langchain-ai/helm — `NOT_AI` → `BLOCKED`

- Advisory: CVE-2026-25750
- class_id: `alias-c14b6c3da2e57758f21352b4`
- Assigned clone (`cases-202.jsonl`): `langchain-ai/helm`
- Round8 BIC: `be0286219fa52b2e5ac40eb4e6f5135461543046` (helm commit)
- Round8 fix: `6b9c7ef62b11562328ec4d996be6e1887d888dde`
  (`langsmith-0.12.33` chart/image retag only)

**Bug.** LangSmith Studio SPA trusts query-param `baseUrl` and sends
bearer token / user / workspace to that origin.

**Independent.** Helm clone is yaml/tpl/nginx. It does not parse
`baseUrl`. `langsmith-frontend` source is closed (`langchain-ai/langsmith`
404s). Chart retag is not a first-writer. No public BIC → cannot judge
AI → **`BLOCKED`**, not `NOT_AI` on a helm commit that never wrote the
sink.

**Question.** May you land `NOT_AI` when the assigned repo does not
contain the vulnerable lines?

Independent answer: **no**.

---

## 4. w186 packet IPA / recorded Ironic — `NOT_AI` → `BLOCKED`

- Advisory: CVE-2026-42997 / GHSA-54w4-233h-x86g / OSSA-2026-010
- class_id: `alias-e674a98ac232317d8ce19044`
- **Assigned clone** (`cases-202.jsonl`):
  `github.com/openstack/ironic-python-agent`
- **Round8 review-index repo field**: `openstack/ironic`
- Round8 BIC: `15e20fe293ee1b86fd2eade35e3b5bc1556931ba`
  (Aija Jauntēva, 2020-12-30, `ironic/common/molds.py` — pre-AI era)
- Round8 fix: `c1c9930fbea8dd5c067466371dcce02b8e8e9b36` (Ironic)

**Bug.** Ironic conductor `molds.py` forwards Keystone / Basic
credentials to a user-controlled clean/deploy URL.

**Independent.** IPA clone has no `molds.py`, no Ironic tags
(26.1.6 / 29.0.5 / 32.0.1 / 35.0.1). GHSA lists package
`ironic-python-agent` with Ironic version ranges. Nearby IPA auth attach
(`a132e167…`, OCI image download) is a different sink.

Two stacked defects:

1. Package mis-map (IPA vs Ironic).
2. Round8 judged Ironic `15e20fe…` as `NOT_AI` while the packet pointed
   at IPA. That SHA is not in the assigned clone, so it is not a
   protocol BIC for this case.

**Question.** For this *packet row*, is the correct terminal `BLOCKED`
(no in-clone BIC) even if Ironic `15e20fe…` would be a clean human
first-writer on a *different* repo?

Independent answer: **yes, BLOCKED** for w186 as assigned. Optionally
re-packet Ironic later; do not silently retarget.

---

## 5. w147 mayan-edms/mayan-edms — `NOT_AI` → `EVIDENCE_GAP`

- Advisory: CVE-2025-14691 / GHSA-774q-r975-vqwp
- class_id: `alias-ba551f3edea728db7f93b5fb`
- Round8 BIC = recorded SHA: `9f8c7cb9d5a9b40fcd5cad6ba39524cf89079578`
- Fix: `94032fbe553e97b33e4e9b9e731b4fc45f9d9f91` (4.10.2)

**Bug.** Auth templates extend `base_plain.html`. Pre-fix 4.10.1 does
`window.location = url` from `window.location.hash` with no
scheme/origin check (`javascript:` / `data:` / cross-origin).

**Independent git (path-scoped, no fetch).**

- `2a61328e` (2018) first wrote `window.location = currentHash.substring(1)`.
- `b78089cc` closed that with `.pathname` (does not honor `javascript:`).
- `9f8c7cb9` subject is `Merge remote-tracking branch origin/series/3.5`
  but it is a **one-parent** object (parent `80666a56`), 1572 files,
  +28331/−22862. It reopens `window.location = uri.fragment()`.
- series/3.5 member SHAs are not in this clone (refs: master,
  origin/master, origin/gh-pages, v0.5, v1.0). Squash not decomposed.
- Later `789ac150` is URI.js → native `URL` (carrier). `7b435369` is a
  rename (not BIC).

Round8 judged `NOT_AI` from Rosario trailers on the squash. Protocol:
squash aggregate is not a BIC; AI is not judged from it.

**Question.** With an undecomposable squash that reopened the sink, is
the terminal `EVIDENCE_GAP` / `BLOCKED`, or may you still call `NOT_AI`
from the squash author?

Independent answer: **EVIDENCE_GAP** (schema mapping: `BLOCKED` is
acceptable if you refuse a fifth status; `NOT_AI` is not).

---

## 6. w169 apache/airflow — policy-open (not a catalog TP)

- Advisory: CVE-2026-41014 / GHSA-x2x7-p37c-43cr
- class_id: `alias-cc0a7d1088e230cb79591781`
- BIC SHA **matches** round8: `525dc133593bba14ad64a736ebe334930eab76cc`
  (PR #61398 member; GitHub squash `e0e4ab451ce0` is not BIC)
- Fix: `e36d10a5196d100adb3829219dc91be72d6a7fc9` (Claude on the **fix**,
  demoted by both sides)

**Bug.** UI `partitioned_dag_runs` list used only
`requires_access_asset`; an Asset:read user could enumerate Dag run
state they were not authorized to read. File first added in `525dc133…`
with asset-only `Depends`. Parent `3d5761d0…` has no such route.
Sibling routes already used `requires_access_dag` /
`ReadableDagsFilterDep`.

**AI evidence split.**

| Channel | Signal |
|---|---|
| Commit object `525dc133…` | guan404ming, **empty trailers**, no Generated-with |
| PR #61398 body | Airflow required checkbox: “Was generative AI tooling used to co-author this PR? **Yes — Claude Code with Opus 4.5**” |

Round8: no on-commit marker → `NOT_AI`.
Independent worker: PR-body disclosure is Airflow’s required authorship
channel covering that BIC → recorded `AI_ROOT_CAUSE`.
Independent **catalog stance**: **not a TP** until you decide whether
PR-body disclosure is a signal “on the BIC”. Same class as w020
(off-commit signal).

**Question.** Does required PR-description gen-AI disclosure count as an
on-BIC AI signal when the commit object is clean?

This brief does **not** promote w169 to the catalog. If you say yes,
it would be a fourth `AI_ROOT_CAUSE`. If you say no, round8 `NOT_AI`
stands (and w020 stays `NOT_AI` for the same reason).

---

## Policy questions (answer these even if you skip git)

**P1. On-BIC only.** Which of these, if any, are signals “on the BIC”?

- a. `Co-Authored-By` / `Generated with` on the commit object
- b. GitHub squash trailer on the merge, members clean (w195 round8)
- c. Source branch name `codex/*` (w020)
- d. PR body / contributing-docs checkbox (w169)

Independent catalog uses **(a) only**. Round8 used (a)+(b)+(c). Worker
on w169 used (a)+(d).

**P2. No-BIC terminals.** When the vulnerable lines are not in the
assigned clone, or the only candidate is an undecomposed squash:

- helm / closed SPA (w156) → ?
- IPA vs Ironic mis-map (w186) → ?
- mayan series/3.5 squash (w147) → ?

Independent: `BLOCKED`, `BLOCKED`, `EVIDENCE_GAP`. Round8: all three
`NOT_AI` (w156/w186/w147).

---

## Suggested ledger edits (not applied)

Do not write the ledger unless Hanqing asks. If these disagreements
stand:

1. w020, w195: `AI_CODE_FLAWED` → `NOT_AI`
2. w195 `introducer_sha` → `6cca70b23c068cd862ec0420d126387eed0436d6`
3. w156, w186: `NOT_AI` → `BLOCKED`; clear in-clone `introducer_sha`
4. w147: `NOT_AI` → `BLOCKED` or keep a documented `EVIDENCE_GAP`
5. w169: leave `NOT_AI` (or flip to `AI_ROOT_CAUSE` only after P1.d)
6. Then `python3 scripts/publish_tp_ledger.py` if any TP status flipped

---

## Reviewer return format

One block, no ledger writes:

```
P1: a / b / c / d   (list which count)
P2: w156=…  w186=…  w147=…

w020: AGREE|OVERTURN|NEED_GIT  reason
w195: …
w156: …
w186: …
w147: …
w169: AGREE_NOT_CATALOG | PROMOTE_AI_ROOT_CAUSE | OVERTURN_OTHER  reason

catalog_ai_tps: list of workers you would publish
```

If you `NEED_GIT`, name the clone path and the commands. Do not `git
fetch`. Huge clones: path-scoped `git log -L` / `-S` only; no
repo-wide `git grep --all`; no `git blame -C`.
