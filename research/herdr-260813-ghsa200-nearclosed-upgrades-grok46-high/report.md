# Near-closed fp211 upgrades (topology / release only)

Verdict first: **0 PASS**. Twelve first-party GHSA identities were deep-reviewed. Ten stay **NARROW** and two stay **UNKNOWN**. Worker PASS is a proposal and this packet emits none. Publication remains **HOLD**. Causal admission is false. The 48-case strict-released lower bound is not rebuilt.

## Scope

Assigned set: existing fp211 NARROW/UNKNOWN GHSA identities whose fp211 (or later independent) gate vector already has `identity_gate`, `ai_hunk_gate`, `but_for_gate` or patch-delta, and `fix_reversal_gate` equal to `PASS`, and whose remaining misses are only `topology_gate` and/or `release_gate`.

Excluded before ranking:

- frozen strict 48
- netred 21 KEEP
- Actual and Gogs accepted red-team KEEP (`GHSA-7GH7-258J-4MPQ`, `GHSA-6P9M-Q3JP-47H4`)
- pending B3 three (`GHSA-G3XQ-3GMV-QQ8G`, `GHSA-F38V-77QJ-H4JQ`, `GHSA-PV2J-RGHR-V5R9`)

Universe after exclude: 77 fp211 NARROW/UNKNOWN identities. Near-closed after exclude: 11 fp211 rows plus 1 later-packet identity close (`GHSA-G353-MGV3-8PCJ`, identity closed by narrow-recovery-b while topology remains). Deep-reviewed: **12** (cap 30). Unreviewed in this lane: **0**. Count unit is first-party GHSA once. CVE aliases are not counting units.

## Conservation

assigned = reviewed + unreviewed = 12 + 0 = 12.

| Verdict | Count |
|---|---|
| PASS | 0 |
| NARROW | 10 |
| UNKNOWN | 2 |
| REJECT | 0 |
| BLOCKED | 0 |

## Why zero PASS

Recovery required exact Git tag or package-artifact ancestry or blob identity of the **counted commit's own** AI marker and first-parent hunk. Member authorship was never transferred onto a carrier. All seven contract gates must be the string `PASS`. Prefer no PASS over weak evidence.

Three rows that fp211 treated as near-closed on release only (`GHSA-V396-V7Q4-X2QJ`, `GHSA-2X93-H3HG-2XFP`, `GHSA-9C3V-684M-579C`) were already NARROW'd on `but_for_gate` / patch-delta by terminal incomplete-remediation red-team and independent patch-delta review. This packet preserves those NARROW verdicts and does not reopen the superseded upgrade-b PASS.

## Per-case

### UNKNOWN (2)

**GHSA-8G98-M4J9-QWW5** (56, tailot/taylored). Jules `c139c021` is the origin. npm versions dict still has only `8.2.4`. Time keys `7.0.5` / `7.0.7` / `7.0.8` have no tarballs. Sole git tag `8.2.4` already contains the fix `57b76343`. Packument time keys are not artifacts.

**GHSA-VH5J-5FHQ-9XWG** (84, tailot/taylored). Incomplete remediation of token replay. Advisory names `8.1.2` / `8.1.3`, which remain time keys without tarballs. Same SHA `57b76343` is the 8G98 fix and the VH5J candidate (opposite role, uniqueness PASS). Do not infer PASS from later `8.2.4`.

### NARROW (10)

**GHSA-CW23-QWR7-C655** (107, nearai/ironclaw). Unreviewed global GHSA with empty `vulnerabilities` (identity NARROW). Member `b20880c1` is Claude-marked and not a tag ancestor. `shell.rs` blobs are three-way unequal (member `4798d0c3`, carrier `fa92cb37`, `ironclaw-v0.29.1` `8f574e90`). Parent of carrier already had `NEVER_AUTO_APPROVE`. Do not transfer member authorship.

**GHSA-WJHR-76VG-2HVC** (108, cyberjunky/python-garminconnect). Reviewed GHSA. Claude `21aea2d` is not an ancestor of `0.3.4` / `0.3.5`. Human `e36613f3` has the same origin blob and is the tag ancestor, with no AI marker. Fix `77a3837` blob-equals `0.3.5` without being a git ancestor. Listed carrier `f74174a` is the fix merge. Topology and release stay NARROW.

**GHSA-G353-MGV3-8PCJ** (124, openclaw/openclaw). Identity PASS on the reviewed first-party object. Member `b0c67ea0` is not a tag ancestor. `channel.ts` blobs are three-way unequal. Parent of squash `5c2cb6c5` already had `verificationToken`. Shared SHA with `GHSA-Q447` is a different invariant (uniqueness PASS).

**GHSA-5WP8-Q9MX-8JX8** (126, qhkm/zeptoclaw). Allowlist member `3c4368da` is not a tag ancestor. Squash `1712deb` has its own Claude marker and first-parent introduces `allowlist.is_empty`, but it is multi-purpose (sandbox runtimes) and blob-unequal to `v0.6.1`. GHSA also names command/argument/wildcard bypasses. Patch-delta NARROW. No member-to-carrier transfer.

**GHSA-X34R-63HX-W57F** (156, langroid/langroid). Copilot member `b1c45e3f` is not an ancestor of `0.59.31`. Mixed squash quotes Copilot and Claude. Released `table_chat_agent.py` blob already equals the fix, not the origin. Copilot did not author `_literal_ok`.

**GHSA-V396-V7Q4-X2QJ** (170, GitPython). Terminal incomplete-rem red-team: AI shlex switch still uses `startswith`; `-uVALUE` is already blocked. Later human `14219588` writes the exact matcher that misses joined shorts. `but_for_gate` NARROW.

**GHSA-F2FQ-4RMP-9X8C** (186, ChurchCRM/CRM). Identity via published repository advisory (global `/advisories` 404). Claude member `cbea916e` is not a tag ancestor. Carrier `1bfc187a` is unmarked. Advisory lists `7.5.1` only; carrier first appears in `7.3.1`.

**GHSA-2X93-H3HG-2XFP** (192, openclaw/openclaw). Terminal incomplete-rem red-team: parent snapshot routes already existed. Current-tab validation is a sibling surface. `but_for_gate` NARROW.

**GHSA-9C3V-684M-579C** (195, openclaw/openclaw). Terminal incomplete-rem red-team: candidate scrubbed streamable HTTP; GHSA names SSE. Sibling-transport completion is not but-for.

**GHSA-WP73-F3GG-W4VR** (197, openclaw/openclaw). Repo advisory names ClickClack `toolsAllow`. Candidate did not edit ClickClack files. Unattempted sibling provider. `but_for_gate` and `release_gate` NARROW.

## Uniqueness

None of the twelve ids is in the frozen 48, netred 21 KEEP, Actual/Gogs KEEP, or B3 three. Shared SHAs documented above are not treated as duplication. CVE aliases are listed on rows and are not counted.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. Integration and publication stay HOLD.

Status is **TERMINAL**. Expansion stopped. No further candidates. The bounded set is the twelve reviewed rows above: zero PASS proposals, ten NARROW, two UNKNOWN.
