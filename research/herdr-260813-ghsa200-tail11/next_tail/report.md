# Follow-up: b5d749dd..a42c436 (not the tail11 denominator)

Status: **COMPLETE**. Proposed seven-gate `PASS` admissions: **0**.

This directory is a **separate** audit of official github-reviewed identities added between parent newer HEAD `b5d749dd70bad2ed373a2524f3fdb34044512ea9` and observed later HEAD `a42c436870111aa3f221257c9d56126a93173ccc`. That later commit was recorded on the parent lane only as `next_tail_head`. It is **not** inside the parent +11/0/2 freeze, not in parent `cases.jsonl`, and not a source head for parent `freeze.json`.

Derived delta for this follow-up range only: reviewed JSON 34,388 -> 34,389. Name-status: **A 1 / D 0 / M 0**. Conservation: 34,388 + 1 - 0 = 34,389. The added identity is `GHSA-P28V-F755-9QRG`.

The advisory-database clone HEAD equals `a42c436`. Freeze commands use `git ls-tree` / `git diff` at the two bound SHAs. No checkout, reset, or clean.

## Verdict

`GHSA-P28V-F755-9QRG` / `CVE-2026-73654` on `triggerdotdev/trigger.dev`: **REJECT**.

Identity closes (first-party published repo advisory). The introducing hunk does not.

Mechanism: `PUT /api/v1/runs/:runId/metadata` passes attacker-controlled `operation.key` into `new JSONHeroPath(operation.key).set(...)` in `packages/core/src/v3/runMetadata/operations.ts` with no prototype-pollution guard.

- Intro squash `34f8bd588e6f1a3edcf3aac3c773d3a0e35af4bf` (Eric Allam, 2025-01-08, PR #1563) first adds that file on default-branch history. Parent is `4243cb24` (`Release 3.3.8`). cve-analyzer `detect_ai_signals` is empty on the squash and on all 13 PR members.
- Atomic add of `operations.ts` among members is `cf80a02d23d99b0f4eebe4ac5eb42059f34b2b3d` (`Implement run metadata updates from ancestor tasks`). Unmarked.
- CodeRabbit is PR-body HTML plus squash bullet `Couple of fixes from CodeRabbit`. Review branding, not an introducing hunk marker.
- Closer squash `6997aeb05e27d2db47f9eda01fdc8a17c81a1ae0` (`fix: security release 2026-07-08`, PR #4316, Chris Arderne) is an ancestor of tag `v4.5.6` and is not an ancestor of `v4.5.5`. Tag `v4.5.5` still lacks `isSafeMetadataKey`; tag `v4.5.6` adds it before `JSONHeroPath.set`.
- Proto-pollution PR-branch member `0c2d9ce22a1af5e2ae8d1809cba38051b4acfb1a` is **not** an ancestor of the squash or of `v4.5.6`. Do not transfer that SHA onto the released closer. Its message mentions `respond to devin comments`; `detect_ai_signals` is still empty (no `devin[bot]` / `@devin.ai` trailer).
- Claude Opus trailers exist on **other** #4316 members (helm secrets, CLI auth, schedule/env-var scoping, Electric SQLi). Those are sibling fixes, not this sink.

Package tag `@trigger.dev/core@3.3.8` does **not** contain `operations.ts`. First containing package tag is `@trigger.dev/core@3.3.9`. Official OSV `introduced` `3.3.8` / first-party `>= v3.3.8` is therefore early. First-party patched `>= 4.5.6` vs last vulnerable `<= 4.5.5` is consistent with git on `v4.5.5` / `v4.5.6` and is not a same-version contradiction.

Absent from the 212 leader-declared IDs and aliases. Worker PASS is a proposal; this follow-up proposes none.

## Gates

| Gate | Status |
|------|--------|
| identity_gate | PASS |
| ai_hunk_gate | REJECT |
| topology_gate | PASS |
| but_for_gate | REJECT |
| fix_reversal_gate | PASS |
| release_gate | PASS |
| uniqueness_gate | PASS |

## Bound vs parent

Parent source heads remain `6e8a7ca9` and `b5d749dd`. This follow-up does not rewrite parent `freeze.json`, parent `cases.jsonl`, or parent added-ID manifests.

## Contract revision (cbd04ef2)

This follow-up binds to leader `CONTRACT.md` sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.

`GHSA-P28V-F755-9QRG` is not an incomplete-remediation row. Patch-delta is not applied. Direct/contributor but-for is unchanged: the introducing `JSONHeroPath.set` hunk is unmarked Eric Allam.
