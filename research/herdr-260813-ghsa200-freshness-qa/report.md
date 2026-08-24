# GHSA 200 source-freshness QA

**Status: `COVERAGE_ESTABLISHED`.** Official first-party coverage through **2026-08-13** is established from `github/advisory-database`. This is source-completeness QA only. No causal `PASS` or `NARROW` verdict is issued.

## Source freeze

| Item | Value |
|------|--------|
| Official repository | https://github.com/github/advisory-database.git |
| Worker clone | `/tmp/ghsa200-worker-clones/freshness-qa/advisory-database` |
| Frozen local HEAD (2026-07-23) | `39d8887723797efc1804585dd06585c9fd751226` at 2026-07-23T12:34:36+00:00 (`Advisory Database Sync`) |
| Current official HEAD | `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86` at 2026-08-13T18:29:41+00:00 (`Publish Advisories`) |
| Commit range | `39d8887723797efc1804585dd06585c9fd751226..6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86` |
| Commits in range | 715 |
| First committer-date after frozen | `6302e2a02c5ffb4e498b9a183e06b139a1bef05a` 2026-07-23T14:00:57+00:00 |
| First reverse-topo commit in range | `898c88da9bc5cf6ca5b351bdd80dc1191bf95647` 2026-06-19T16:20:08-05:00 (reachable from current, not from frozen HEAD) |
| API | Not used. Enumeration is `git ls-tree` plus a sparse worktree of `advisories/github-reviewed`. Pagination/cursor conservation is not applicable. |

The pre-existing cache clone at `~/.cache/cve-analyzer/advisory-database` was used only as a Git object reference. Its HEAD remains `39d8887723797efc1804585dd06585c9fd751226`. This worker did not reset, clean, or commit that cache.

A full worktree checkout failed on `/tmp` disk space because `advisories/unreviewed` is large. Coverage was recovered by cone sparse-checkout of `advisories/github-reviewed` only. Unreviewed identity counts come from `git ls-tree` at each revision and do not require blob checkout.

## File and identity conservation

GitHub-reviewed JSON files:

- Frozen: **33,646** unique GHSA path IDs
- Current: **34,377** unique GHSA path IDs
- Range: **731** added, **0** deleted, **148** modified, **0** renamed
- Frozen + added − deleted = 34,377 (path count conserved)
- Unique IDs: 33,646 retained + 731 added − 0 removed = 34,377 (identity conserved)
- Duplicate path IDs: 0. Paths without a GHSA filename: 0.

Unreviewed JSON files (tree names only):

- Frozen: **317,316**
- Current: **323,274**

No raw advisory pages are stored in the repository. SHA-256 manifests of identity lists live under `manifests/`.

## Published and withdrawn treatment

Rule: a reviewed advisory is **withdrawn** if the official JSON `withdrawn` field is a non-empty timestamp. Otherwise it is **published/active**. Withdrawn IDs stay in the full reviewed identity set and are excluded from the active published denominator.

At current HEAD, every reviewed JSON file has a `published` timestamp (0 missing). The `withdrawn` key is present on 909 files, matching the withdrawn count.

- Current reviewed unique: **34,377**
- Withdrawn: **909**
- Active published: **33,468**
- 909 + 33,468 = 34,377

## Leader declared-ID compare

Leader baseline declared identities are the 212 unique `case_id` values in `autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl` (SHA-256 `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`), matching `baseline.json` `ghsa_cases: 212`.

Compare is identity-list only:

| Routing | Count |
|---------|------:|
| `IDENTITY_PRESENT` (in frozen and current reviewed) | 110 |
| `IDENTITY_PRESENT_WINDOW_NEW` (absent from frozen reviewed, present in current reviewed) | 25 |
| `IDENTITY_ABSENT_FROM_REVIEWED` (absent from current github-reviewed) | 77 |
| `IDENTITY_WITHDRAWN` | 0 |
| **Total declared** | **212** |

110 + 25 = 135 declared IDs are in the current official reviewed set. 102 declared IDs were absent from the 2026-07-23 freeze; 25 of those appear in the 2026-07-23..2026-08-13 window; 77 remain absent from github-reviewed at current HEAD. No declared ID disappeared from reviewed during the window. None of the 212 declared IDs is withdrawn in the current reviewed JSON. None of the 77 current-absent declared IDs is present in the unreviewed tree as a substitute official reviewed object.

Absence from github-reviewed is an identity-coverage fact, not a causal rejection. Presence is not a causal admission.

The window also added **731** novel reviewed GHSA IDs that are not in the leader declared list. Those IDs are listed in `manifests/github_reviewed_window_added_ids.txt` and are not routed as causal cases.

## Fail-closed check

Current official HEAD committer date is 2026-08-13. The current reviewed worktree unique ID set equals `git ls-tree` at that HEAD. JSON parse errors: 0. Path and identity conservation hold. Status is therefore `COVERAGE_ESTABLISHED`, not `COVERAGE_FAILED`.
