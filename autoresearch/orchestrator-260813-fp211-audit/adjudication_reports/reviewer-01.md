# Third-party conflict adjudication — reviewer 01

Assigned packets: `conflict_inputs/reviewer-01.jsonl` (8 rows).
Owned outputs: `adjudications/reviewer-01.jsonl`, `adjudication_reports/reviewer-01.md`.
Raw evidence: `/tmp/fp211-adjudicate-01`. No first/second-pass files, canonical ledger, builders, or code were edited. No commit.

**Finalization:** discovery stopped. All eight assigned 26-field rows are written from collected evidence. No remaining gate was left contradictory or blocked; none was forced to CONFIRM. `ai_hunk_gate` UNKNOWN is preserved on ordinal 68.

Reviewer identity: third_reviewer=1 on every packet. First/second pairs are (2,5), (3,6), (5,2), (6,3). Reviewer 01 is excluded from the first two on all eight rows.

Inspection was independent: first-party GHSA/CVE objects, then git parent/candidate/fix/tag evidence. First/second-pass rows were routing only, not votes.

## Coverage and verdicts

Ordinals, sorted: **48, 68, 85, 90, 100, 160, 193, 203**.

| Verdict | n | ordinals |
|---------|---|----------|
| CONFIRM | 1 | 160 |
| NARROW | 2 | 85, 100 |
| FALSE_POSITIVE | 5 | 48, 68, 90, 193, 203 |
| UNKNOWN | 0 | — |
| BLOCKED | 0 | — |

Only 160 is CONFIRM/HIGH. Contract still requires a rebuilt HOLD ledger before it is a counted case.

## Changed-field resolutions

Decided from primary evidence, not majority.

| Ord | Changed fields | This review | vs first | vs second |
|-----|----------------|-------------|----------|-----------|
| 48 | verdict, confidence, release_gate, causal_class, false_positive_class | FALSE_POSITIVE / HIGH / release FAIL / UNRELEASED_COMMIT_ONLY | first UNKNOWN | agrees second on verdict |
| 68 | ai_hunk_gate | UNKNOWN | first NARROW | agrees second |
| 85 | release_gate | PASS | first UNKNOWN | agrees second |
| 90 | release_gate | FAIL | first UNKNOWN | agrees second |
| 100 | release_gate | PASS | first UNKNOWN | agrees second |
| 160 | verdict, confidence, release_gate | CONFIRM / HIGH / release PASS | first NARROW / MEDIUM | agrees second |
| 193 | verdict, but_for, fix_reversal, causal_class, false_positive_class | FALSE_POSITIVE / but_for FAIL | first NARROW | agrees second |
| 203 | verdict, but_for, fix_reversal, causal_class, false_positive_class | FALSE_POSITIVE / but_for FAIL | first NARROW | agrees second |

## FALSE_POSITIVE counterexamples

**48 / GHSA-9W78 / CVE-2026-2376 — `unreleased_commit_only`.** Unreviewed global GHSA aliases the Red Hat CVE (repo GHSA 404). Claude members persist unvalidated `external_registry_url` and use `requests.Session()` default redirects. Independent clone has 179 tags. Every tag containing carrier `92b6f472` (`v3.17.0`–`v3.18.0`) already has `validate_external_registry_url` (3.17 backport `729cfdfb` / 3.18 merge `33908b87`). `v3.16.5` lacks origin. Listed closers `9afe28a5`/`5ad2b732` are not ancestors of those tags. No git tag has origin without repair → release FAIL for a STRICT_RELEASED row.

**68 / GHSA-4VFF / CVE-2026-34149 — `identity_mismatch`.** Repo advisory/NVD name unescaped credentials and Mongo collection names in `DatabaseBackupJob`. Parent already interpolates `mongodump --excludeCollection`; `update_backup` already writes `databases_to_backup`. Conductor `473c3227` only adds POST `create_backup`; subject is `Changes auto-committed by Conductor` with no AI trailer. Claude is on fix `99043600`. Same candidate/carrier as ordinal 35 (`duplicate_of` `strict-200-v3:alias-69c709472a21c9ed2b2637a2`). Identity FAIL + uniqueness FAIL. `ai_hunk_gate` UNKNOWN (Conductor is not hunk-level AI proof).

**90 / GHSA-VCHH / CVE-2026-50569 — `not_origin_of_named_mechanism`.** Parent `HTTPTriggerSpec.Validate()` never checks `RelativeURL`/`Prefix`; webhook `Validate()` only calls `new.Validate()`. Fix `0deed6bf` says those fields were never checked and treats webhook-removal as context. `v1.24.0` (affected) has the webhook file and neither member nor carrier nor fix. `v1.25.0` has carrier and fix together. But-for FAIL, fix-reversal FAIL, release FAIL.

**193 / GHSA-8V95 — `preexisting_incomplete_predicate`.** Repo GHSA range starts `2026.1.20`. Parent of `1c85eff9` already has `if (authz.callerDeviceId && !authz.isAdminCaller)` on `device.pair.approve` and lacks `requestsNonOperatorDeviceRole`. The [AI] commit nests extra role checks inside that leak. Fix `517ce3df` drops the `callerDeviceId` conjunct the candidate did not introduce. `v2026.1.20` lacks the candidate. Removing the AI commit does not remove the non-device bypass.

**203 / GHSA-HJR6 — `unattempted_env_family`.** Repo GHSA (global 404). Codex PR `#63277`; member `3affd5e8` has no trailer and is not an ancestor of carrier `2d126fc6`. TCLLIBPATH is on the member then dropped on the carrier. BASHOPTS/KSH_ENV/FPATH never appear on parent/member/carrier. `v2026.6.1` has the carrier without those keys. Later `9f413acc` (in `v2026.6.6`) is not reversal of a shipped attempt. Distinct GHSAs from E01/E03/E04 keep uniqueness PASS.

## NARROW (real AI surface, scope shrinks)

**85 / GHSA-RXXP / CVE-2026-32049.** Claude sticker path is a new `fetchRemoteMedia` site that omits `maxBytes` (parent `resolveMedia` already did the same). Advisory is multi-channel byte-cap. Fix `73d93dee` is multi-purpose. Distinct from ordinal 9 (token-in-URL, same SHA). Release PASS: `v2026.2.21` / npm `2026.2.21-2` have candidate without fix; `v2026.2.22` has the fix.

**100 / GHSA-C4M7 / CVE-2026-47211.** Claude adds `OUROBOROS_CLI_PATH`; parent has none. Advisory is untrusted project `.env` RCE; this row is a new execution-affecting selector, not origin of dotenv loading. Squash member is not an ancestor of carrier `4aaf9147`. Release PASS: `v0.38.2` carrier without fix; `v0.39.0` has `4e70b760`.

## CONFIRM

**160 / GHSA-7P8R / CVE-2026-18446.** Reviewed GHSA names literal-`//` authority plus `\\` `/\\` `\\/` introducers; 4.x patched 4.1.2. Single-parent Claude commit `0542a216` adds `AUTHORITY_PREFIX /^(?:...:)?\/\/` and rejects `\\` inside a matched authority; parent is the v4.1.0 bump. Follow-on `f3c6c905` closes remaining introducers on the same parser. Local/npm `v4.1.1` (`f3e437f7`) contains candidate not fix; `v4.1.2` (`c30764cc`) parent is the fix SHA.

## Identity keep/remove

No public-ID splits. Keep/remove equals the manifest set on every row. Unreviewed GHSA-9w78 and repo-only GHSA-8v95/hjr6/4vff stay explicit in keep, with identity NARROW or FAIL as above. GHSA+CVE formal aliases keep both IDs.

## Limitations

- Red Hat Quay / mirror-registry RPMs for CVE-2026-2376 were not unpacked. Git tags still show origin and repair together; RH “Fix deferred” is not a git-tag that contains origin without repair.
- Global GHSA 404 for 4vff/8v95/hjr6; identity used repo advisories.
- Squash members `3affd5e8` and `bbd94a73` were fetched via PR/commit refs, not default clone tips.
- Quay clone was copied then independently `git fetch --tags` (179 tags). Other assigned repos were fresh clones or already-fetched local clones with tag fetch.

## Reusable experience

1. Fetch tags before leaving `release_gate` UNKNOWN. Zero tags in a cache clone is not missing artifacts.
2. Require a published tree with origin *and* without the repair, not ancestry of a listed fix SHA (equivalent backport/merge can ship under a different SHA).
3. Parent-predicate check before calling an [AI] commit incomplete remediation: nested checks inside a pre-existing leak are old-bug-preserving.
4. A squash-member denylist key that is dropped on the carrier is not a released attempt of that env family.
5. Conductor / PR-level Codex / carrier `[AI]` subjects are not relevant-hunk AI proof.

## Replay (non-exhaustive)

See each JSONL row `replay_commands`. Clones under `/tmp/fp211-adjudicate-01/clones/{quay,coolify,openclaw,fission,ouroboros,fast-uri}`. Advisories under `/tmp/fp211-adjudicate-01/advisories/`.
