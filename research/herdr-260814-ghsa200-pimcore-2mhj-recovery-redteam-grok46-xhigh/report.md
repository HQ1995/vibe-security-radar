# GHSA-2MHJ-FHVG-V428 red-team recovery -- PASS proposal (HOLD)

Independent hostile review of exactly one first-party advisory, GHSA-2MHJ-FHVG-V428 in pimcore/pimcore. The batch27 row is a hypothesis, not evidence. Source worker verdicts and prose were not trusted. PASS is a proposal, never leader admission. Publication stays HOLD. Canonical81 is not rebuilt. Greater-than-200 stays unsupported.

Reviewed: 1. Unreviewed: 0. PASS proposal: 1. NARROW: 0. REJECT: 0. BLOCKED: 0.

## Verdict

**PASS** `AI_INCOMPLETE_REMEDIATION` for `GHSA-2MHJ-FHVG-V428` (alias `CVE-2026-55072`). All seven contract gates plus `remediation_patch_delta_gate` are PASS at this scope. Countable remains false until the leader admits the row.

## Hostile attacks and results

1. **Wrong parent in the batch27 hypothesis.** selected-30 listed parent `f7565e26`. Independent `git rev-parse dbe1d131^` and the GitHub commit `parents` array are `4b85df494e87b4fbb9c6e8b4c303cb193b1e317e`. `f7565e26` is the first parent of closer `33a0e188`, not of the candidate. Topology uses the independently verified parent.

2. **Is `dbe1d131` an explicit security attempt on this identifier boundary?** Yes. It is single-parent. Subject: `[Security]: Enhance Class Definition security (#19145)`. Body: Copilot agent session URLs and `Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>`. First-parent `ClassDefinition.php` only inserts a leading `^` on the name and id `preg_match` lines. Parent `4b85df49` has `/[a-zA-Z]\w+/` and `/[a-zA-Z0-9]([a-zA-Z0-9_]+)?/` with no start or end anchor. That is a guard rewrite, not a later review of a human patch.

3. **Does the GHSA name this residual?** Yes. Global GHSA type `reviewed`, `withdrawn_at` null, `source_code_location` `https://github.com/pimcore/pimcore`, Packagist `pimcore/pimcore`. Repo advisory state `published`. Summary: missing end anchor `$` after incomplete fix `dbe1d131e4` which added `^` but omitted `$`. Alias `CVE-2026-55072`. Distinct from other pimcore GHSAs (customer-list SQLi, custom-report column SQL, WebDAV MOVE).

4. **Patch-delta, not rollback-to-parent.** Independent regex eval of UID `1 UNION SELECT password FROM users-- `: parent ALLOWS, AI pattern ALLOWS, closer `/^[a-zA-Z0-9][a-zA-Z0-9_]*$/` BLOCKS. Closer `33a0e188` is single-parent of `f7565e26`. First-parent amends the same two patterns to `/^[a-zA-Z]\w+$/` and `/^[a-zA-Z0-9][a-zA-Z0-9_]*$/`. Blame of those lines at `v2026.1.4` / `v12.3.8` is `dbe1d131`. Blame at `v2026.1.5` / `v12.3.9` is `33a0e188`. `dbe1d131` is an ancestor of `33a0e188`. Rollback of the AI commit would reopen the broader unanchored parent hole; that is not a failure for this class. `Block.php` blob `bb2537d5` is unchanged by the AI commit and is extra quoting in the closer. The GHSA-named residual of the AI regex is the omitted `$`, not an untouched sibling regex.

5. **Release containment is not commit-only.** The commit-oz clone has zero tags, which is why batch27 stayed BLOCKED. This packet cloned an owned cache and fetched public tags. GitHub git-ref objects, GitHub Releases (not draft, not prerelease), and Packagist `source.reference` all peel to the same SHAs:
   - first vulnerable public artifacts containing the AI rem and not the closer: `v2026.1.4` (`0565917f`, published 2026-05-27, classdef blob `b954e136` equals the AI blob) and `v12.3.8` (`f025d3c7`, same blob);
   - first fixed public artifacts containing the closer: `v2026.1.5` (`fbf5ab61`, published 2026-06-09, classdef blob `cce70e10` equals the closer blob) and `v12.3.9` (`355ac351`, same blob).
   Tags `v2026.1.0` through `v2026.1.3` and `v12.3.7` do not contain `dbe1d131` and still have the parent unanchored regex. GHSA `introduced: 2026.1.0` is not used as origin.

6. **Uniqueness.** Absent from canonical81 strict (81), fp211 public cases, fp211 canonical ledger, and publication adjudications. Prior packets: commitfirst-oz UNKNOWN, current-delta unmatched, fresh-nz REJECT (origin-lane delegation), batch27 BLOCKED (no tags). Those are uncounted. Shared closer SHA is not duplication.

## Gates

| Gate | Result |
|---|---|
| identity_gate | PASS |
| ai_hunk_gate | PASS |
| topology_gate | PASS (single-parent candidate and closer; independently verified parent `4b85df49`; AI ancestor of closer and of `v2026.1.4` / `v12.3.8`) |
| but_for_gate | PASS under patch-delta (incomplete remediation) |
| fix_reversal_gate | PASS |
| release_gate | PASS (public tags + GitHub Releases + Packagist source.reference, not commit-only) |
| uniqueness_gate | PASS |
| remediation_patch_delta_gate | PASS |

## Hold

This packet does not admit the case and does not change the canonical count. The leader must re-verify before any ledger rebuild. Publication and the greater-than-200 claim remain HOLD.
