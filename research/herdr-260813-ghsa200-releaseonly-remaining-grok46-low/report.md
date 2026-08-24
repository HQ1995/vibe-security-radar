# Remaining high-signal release-only gaps

Verdict first: **0 PASS**. Five first-party GHSA identities remain after mechanical exclusion of nearclosed12, B3, and strict72. All five stay **NARROW**. Worker PASS is a proposal and this packet emits none. Publication remains **HOLD**. Causal admission is false. The 72-case strict-released lower bound is not rebuilt. This packet does not support a more-than-200 claim.

## Scope

Source pool: fp211 ordinals 20, 132, 136, 152, 155, 157, 169, 170, 186, 192, 195, 197, 211 (13 identities).

Mechanically excluded before review:

- nearclosed12 identities already reviewed in `autoresearch/herdr-260813-ghsa200-nearclosed-upgrades-grok46-high`: ordinals 170, 186, 192, 195, 197 (`GHSA-V396-V7Q4-X2QJ`, `GHSA-F2FQ-4RMP-9X8C`, `GHSA-2X93-H3HG-2XFP`, `GHSA-9C3V-684M-579C`, `GHSA-WP73-F3GG-W4VR`). Expected overlap 169/170/186/192/195/197: 169 is not in that packet.
- B3: ordinal 169 `GHSA-F38V-77QJ-H4JQ`.
- strict72 counted identities: ordinals 20 and 211 (`GHSA-XW8C-RRVX-F7XQ`, `GHSA-JV46-XFWM-36J7`).

Assigned remaining unique identities: **132, 136, 152, 155, 157**. Conservation: assigned = reviewed + unreviewed = 5 + 0 = 5. Count unit is first-party GHSA once. CVE aliases are not counting units. Scope was not broadened.

## Conservation

| Verdict | Count |
|---|---|
| PASS | 0 |
| NARROW | 5 |
| UNKNOWN | 0 |
| REJECT | 0 |
| BLOCKED | 0 |

## Why zero PASS

Admission requires a real vulnerable released tag or package that contains the counted commit's own AI marker and first-parent hunk (or that commit's own blob), plus a fixed release that contains the same-invariant reversal. A commit-only window or a guessed version remains NARROW. Member authorship is never transferred onto a carrier. All seven contract gates must be the string `PASS`. Prefer no PASS over weak evidence.

## Per-case

**GHSA-M63V-2G9W-2W6V** (132, fission/fission). Reviewed first-party GHSA. Claude member `2db76f65` is not a tag ancestor. Carrier `e484df84` and fix `695d3e97` both first appear in `v1.24.0`. `podspec_safety.go` blobs are three-way unequal (member `af473d26`, carrier `330fccee`, tag/fix `1d7219e7`). `v1.23.0` lacks the file. No released residual of the AI PodSpec denylist without `ValidateContainerSafety`. Topology, release, and patch-delta NARROW. Distinct from `GHSA-QF5V`.

**GHSA-P5RM-JG5C-8C77** (136, microsoft/kiota). Reviewed first-party GHSA. Copilot member `f51f4971` is not an ancestor of `v1.33.0` or `v1.34.0`. File blob of the member equals the squash carrier `782a03f5`; that still does not put the member on a tag. `v1.33.0` blob `1391bf0c` is the older raw-string validator. `v1.34.0` blob equals fix `430008e9`. No tag contains the incomplete decode without the NUL/homoglyph closure. Do not transfer member authorship. Topology, release, and patch-delta NARROW.

**GHSA-X2W7-XR2G-QHJR** (152, ArnasDon/wacrm). Global GHSA is unreviewed with empty `vulnerabilities` and a 404 repository advisory (same identity bar as `GHSA-4FXP`). Claude `4afa9bea` is marked and atomic. Local and origin tag counts are 0. Private `package.json` `0.1.0` is not a published artifact. Advisory names `73041bf`, which is not the counted SHA. Identity and release NARROW. A commit-only version remains NARROW.

**GHSA-X8QQ-M4QC-RPJ5** (155, Roskus/prospero-flow-crm). Global GHSA is unreviewed with empty `vulnerabilities` and a 404 repository advisory. Claude `56ea64c8` / `86f40651` introduce `find($id)` Order/OrderItem controllers. `v4.6.0` lacks `OrderReadController.php`. `v5.5.3` contains origins and fix `9a859c4`; the released file blob equals the fix (`d2e097de`), not origin (`c3082407`). Version bumps `4.18.0` / `4.21.0` in commit messages are not tags. Identity and release NARROW.

**GHSA-G8MR-85JM-7XHM** (157, vitest-dev/vitest). Reviewed first-party GHSA. Codex `af88b1f5` is atomic and an ancestor of `v3.2.5`. Fix `385a1aef` is the candidate's child. `v3.2.4` contains neither; `rpc.ts` `7619c5f0` is not the candidate blob. `v3.2.5` `rpc.ts` equals the fix. No tag contains the allowWrite backport without gating `cdp`. Release and patch-delta NARROW. Topology PASS does not promote the row.

## Uniqueness

None of the five ids is in strict72, nearclosed12, or B3. Shared fission/kiota/vitest SHAs with other GHSA identities are different invariants and are not merged. CVE aliases are stored and not counted.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. Integration and publication stay HOLD.

Status is **TERMINAL**. Expansion stopped. No further candidates in the assigned remaining set.
