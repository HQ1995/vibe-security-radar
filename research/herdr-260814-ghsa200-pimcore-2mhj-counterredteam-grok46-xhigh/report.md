# GHSA-2MHJ-FHVG-V428 counter-redteam -- REJECT

Independent hostile review of exactly one hypothesized `AI_INCOMPLETE_REMEDIATION` admission for `pimcore/pimcore`. Recovery-packet prose was not trusted. Conflicting `fresh-nz` and `batch27` rows were read only as hypotheses. Verdict is REJECT. Countable remains false. Publication and more-than-200 remain HOLD. canonical81 is not rebuilt.

Reviewed: 1. Unreviewed: 0. KEEP proposal: 0. REJECT: 1.

## Verdict

**REJECT.** Fatal counterexample: the GHSA-named residual is a ClassDefinition UID/name regex with a leading `^` and no trailing `$`. That hunk is authored by unmarked human PR 19145 member `e96631216bb439896cc5979ed9f2850eaf28d2f4`, not by Copilot. Squash `dbe1d131e49421eee5a427f1ae0dec5735639ff3` carries a Copilot trailer from later members that never touch `ClassDefinition.php`. That is authorship transfer. User policy for incomplete remediation is not met because the AI commit did not explicitly attempt this same boundary.

Independently resolved parent of the hypothesized candidate: `4b85df494e87b4fbb9c6e8b4c303cb193b1e317e`. Minimum fix `33a0e1887e1e31b4283b016ac5440c35ea5697b4` does add the missing end anchor and ships in public tags `v12.3.9` / `v2026.1.5`. Those facts do not convert the human regex rewrite into an AI hunk.

## Hostile attacks

1. **Older hole, GHSA path not a residual of the attempted boundary.** Does not kill. Parent `4b85df49` and tags `v12.3.7` / `v2026.1.3` already had unanchored `preg_match` guards (`blob b09f5e65`). The hypothesized attempt added only `^`. The first-party GHSA names the omitted `$` as the residual of `dbe1d131e4`. That residual-of-attempt story would survive if the hunk were AI-authored.

2. **Regex hunk is human, or only carried by an AI-marked merge.** Fatal. PR 19145 (base `12.3`, merge commit `dbe1d131`) has seven members. The first three are unmarked human `draft` commits by Ji Jia Jia / `kingjia90`. Only the first, `e9663121`, diffs `models/DataObject/ClassDefinition.php`, adding `^` to both patterns. `ClassDefinition.php` blob `b954e136` is identical from that member through the squash. The four `copilot-swe-agent[bot]` members edit `ClassDefinition/Dao.php` or `LocateFileTrait.php` only. Git blame at `v12.3.8` of the two regex lines is the squash SHA because GitHub squash collapsed members. Contract `ai_hunk_gate` and `topology_gate` fail.

3. **Parent already had equivalent validation, so but-for fails.** Parent did not have `^`. `but_for_gate` still FAIL under a Copilot-only counterfactual: reverting Copilot Dao/LocateFile edits leaves blob `b954e136` and the missing `$` in place.

4. **`33a0e188` is not the atomic same-mechanism fix or does not descend.** Does not kill. Candidate is an ancestor of the fix (7 commits). Fix-parent `ClassDefinition.php` blob equals the squash blob. The fix adds `$` / rewrites the id pattern to `^[a-zA-Z0-9][a-zA-Z0-9_]*$`. GHSA references this commit. Extra `Block.php` quoting is a sibling sink the regex attempt never touched; it does not stop the regex amendment. PR 19177 member `ae7b6958` (human) authors the `$`; later Copilot Autofix only tweaks the id class. `fix_reversal_gate` PASS. `remediation_patch_delta_gate` FAIL because the AI-authored change is not that regex boundary.

5. **Cited tags are wrong branch, lack candidate, already contain fix, are drafts, or sit outside GHSA ranges.** Does not kill containment. Lightweight tags `v12.3.8` (`f025d3c7`) and `v2026.1.4` (`0565917f`) are public GitHub Releases (`draft=false`, `prerelease=false`). Packagist `pimcore/pimcore` `source.reference` equals those peels. Both contain candidate, exclude fix, and have regex blob `b954e136`. First fixed tags `v12.3.9` (`355ac351`) and `v2026.1.5` (`fbf5ab61`) contain the fix blob `cce70e10`. `v12.3.8` is an ancestor of `v2026.1.4` (2026.1.4 second parent is 12.3.8). `v2026.1.5` second parent is `v12.3.9`. Repo advisory lists only `<= 2026.1.4` / `2026.1.5`; global GHSA also lists `< 12.3.9` / `12.3.9`. Citing `v2026.1.0` as first vulnerable for this residual would be false: `v2026.1.0`..`v2026.1.3` lack the candidate and still have parent blob `b09f5e65`. `release_gate` PASS for public containment of the incomplete regex; that does not admit AI causality.

6. **Earlier packet already counts this GHSA/mechanism.** Does not kill. Absent from canonical81 (81 ids), fp211 public cases, fp211 ledger, publication adjudications, and final mechanisms. `fresh-nz` REJECT treated Copilot closer `33a0e188` as origin and delegated the residual. `batch27` BLOCKED because its clone had zero tags. Neither is an admission.

7. **First-party GHSA identity, package, or repository mapping is wrong.** Does not kill. Global GHSA `type=reviewed`, `withdrawn_at=null`, `source_code_location=https://github.com/pimcore/pimcore`, composer package `pimcore/pimcore`, alias `CVE-2026-55072`. Repo advisory `state=published`, same `ghsa_id`. `identity_gate` PASS.

## Gates

| Gate | Result |
|---|---|
| identity_gate | PASS |
| ai_hunk_gate | FAIL |
| topology_gate | FAIL |
| but_for_gate | FAIL |
| fix_reversal_gate | PASS |
| release_gate | PASS |
| uniqueness_gate | PASS |
| remediation_patch_delta_gate | FAIL |

## Ancestry (proved, not counted)

First public tags containing the incomplete regex blob and excluding the fix: `v12.3.8` then, via merge, `v2026.1.4`. First public tags containing the fix blob: `v12.3.9` then, via merge, `v2026.1.5`.

## Hold

This packet does not admit the case and does not change the canonical count. canonical81 remains 81. The leader must not treat worker or red-team REJECT as a ledger rebuild.
