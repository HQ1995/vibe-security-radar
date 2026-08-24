# Correction audit: ordinal 211 GHSA-JV46-XFWM-36J7 release containment

**Status: `REDTEAM_COMPLETE`.** Verdict: **KEEP** (proposal only).  
Owned directory: `autoresearch/herdr-260813-ghsa200-red-upgrade-b-ord211-release/`.  
Prior `red-upgrade-b-direct` artifacts were not modified. Clone: `/home/hanqing/.cache/ghsa200-worker-clones/red-upgrade-b-ord211-release/clones/szTheory__relyra`.

Release rule used: a case admits if at least one real released version inside the first-party affected range contains the AI candidate without the same-scope fix, and a real first patched release contains that fix. Every textual version named in the advisory range need not have existed.

This row is `AI_DIRECT_ROOT`. The current contract's incomplete-remediation patch-delta clause does not apply to it and does not change `release_gate`.

## Verdict

All seven gates close at the SignatureValue candidate-arm scope. Hex/git `1.1.0` is a real affected release in `>= 1.0.0, < 1.2.0`. Missing `1.0.0` is a source caveat only.

| Gate | Result |
|------|--------|
| identity | PASS |
| ai_hunk | PASS |
| topology | PASS |
| but_for | PASS |
| fix_reversal | PASS |
| release | PASS |
| uniqueness | PASS |

## Identity

Reviewed first-party GHSA-jv46-xfwm-36j7 / CVE-2026-49454. Repo advisory published, not withdrawn. Names `szTheory/relyra`, Hex `relyra`, and SAML `SignatureValue` not cryptographically verified. Structured range `>= 1.0.0, < 1.2.0`, patched `1.2.0`. Named fixes: `2e456897` (candidate-arm crypto) and `8910200` (metadata pin).

## AI hunk and topology

Atomic `2aeba972` (parent `88d43db0`) trailer `Made-with: Cursor` creates `lib/relyra/security/signature.ex`. Parent lacks that file. `verified_signed_node` returns `{:ok, %SignedNode{}}` for a single candidate with no `:public_key.verify`. `git blame -L 167,175 v1.1.0` still attributes that arm to `2aeba972`. Not a squash or merge. Authorship is not transferred.

Later non-crypto helpers change the file blob (`b23d4d61` at the candidate vs `023e3069` at `v1.0`/`v1.1.0`). The success arm is unchanged.

## But-for and fix reversal

Parent has no `signature.ex`. Removing `2aeba972` eliminates the structure-only success arm. Fix `2e456897` inserts `cryptographically_verify` (`:public_key.verify` of canonical SignedInfo plus digest recompute) before building `%SignedNode{}`. `v1.2.0` blame of `cryptographically_verify` (line 205) is `2e456897`.

`8910200` is advisory-named but out of this scope: it edits `lib/relyra/metadata/{auto_refresh,import,trust_anchor}.ex` only. It does not reverse the candidate-arm SignatureValue gap. Minimum fix set is `2e456897` only. The Claude trailer on `2e456897` marks the reversal, not the origin.

## Release

| Artifact | Real? | Candidate `2aeba972` | Fix `2e456897` | In `>=1.0.0,<1.2.0`? |
|----------|-------|----------------------|----------------|----------------------|
| Hex/git 1.1.0 | Yes. Hex inserted 2026-05-08T16:21:03Z checksum `75887931…dca165`. Git `v1.1.0` = `e6d62e1d`, mix `@version "1.1.0"`. GitHub Release `v1.1.0` 2026-05-08T16:18:27Z. | Ancestor. Success-arm blame `2aeba972`. `public_key.verify` count 0. | Not an ancestor. | Yes. |
| Hex/git 1.2.0 | Yes. Hex inserted 2026-05-25T05:37:46Z checksum `aa496984…5da5d4e`. Git `v1.2.0` = `09bd6472`, mix `@version "1.2.0"`. | Ancestor (still). | Ancestor. Blame of `cryptographically_verify` is `2e456897`. | No (patched). |
| Hex/git 1.0.0 | No. Hex HTTP 404. No GitHub Release. Git tag `v1.0` is mix `0.1.0`. | Caveat only. | Caveat only. | N/A. |

`1.1.0` satisfies the containment rule: a real in-range vulnerable release holds the AI hunk without the fix; `1.2.0` is the first patched release and holds the same-scope fix.

## Uniqueness

The 212-case public ledger has one relyra row: ordinal 211, this GHSA, mechanism `relyra-xmldsig-structure-only-success-arm`. Not a duplicate of another counted mechanism.

## Sources

Relyra HEAD `ebee8b38825dcd2002f2b8aa0f8f89b38f63fc1e` (2026-06-14T19:00:27-04:00).

## Contract binding

Leader `CONTRACT.md` sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3` (freshness correction from stale `2dcf018d…`). Hypothesis input `herdr-260813-ghsa200-upgrade-b/cases.jsonl` sha256 `50493a20909eef41ac835042207a6e5b32fcd82f8c9486185de2e3e62d5cd84f` is unchanged. Ordinal 211 is `AI_DIRECT_ROOT`, so the incomplete-remediation patch-delta clause does not apply and does not change the release verdict. KEEP remains a proposal. Artifact hashes are in `result.json`.
