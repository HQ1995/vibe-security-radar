# Legacy near4b NARROW upgrade

Verdict first: **0 KEEP**. Assigned **4**, reviewed **4**, unreviewed **0**. Equation **4=4+0**. All four rows are **REJECT** at HIGH confidence. Packet delta **0**. Canonical84 stays **84**. Publication and more-than-200 remain **HOLD**. Worker KEEP is a proposal only and is not issued.

Unclosed identity stays **UNKNOWN** on every row: unreviewed GHSA plus repo-advisory 404 is missing first-party evidence, not a closed FAIL. Empty affected ranges, aliases, and shared SHAs were routing only. Git-closed FAIL gates stay FAIL.

Selection is exactly the four legacy NARROW cases from `autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh/result.json` with two non-PASS gates: ordinal 5 GHSA-FWPR-59HH-GR98, ordinal 61 GHSA-3636-3MQQ-Q7X9, ordinal 86 GHSA-7X5Q-8F6H-RJRC, and ordinal 107 GHSA-CW23-QWR7-C655. Routing labels were not trusted.

## Sources

- Narrow-recovery-a result sha256 `fac9ebdc4d4eace59c13f4eb56e35439f4caae90023aedbf3a9afda293915bea`
- Narrow-recovery-a cases sha256 `023e5703b63cbf7f700ee6cb89041ee1824929eae17d43aec140945f0e59ebd9`
- Canonical84 ledger sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06` (counted overlap 0/4)
- CONTRACT sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- Advisory JSON copied under `work/pages/`
- Mysti/MISP/conductor replayed from read-only cache clones
- Ironclaw cloned under `work/clones/ironclaw` then removed

## Independent replay

| Ord | ID | Routing non-PASS | This review | UNKNOWN | FAIL |
|----:|----|------------------|-------------|---------|------|
| 5 | GHSA-FWPR-59HH-GR98 | identity, release | REJECT | identity | release |
| 61 | GHSA-3636-3MQQ-Q7X9 | identity, release | REJECT | identity | fix_reversal, release |
| 86 | GHSA-7X5Q-8F6H-RJRC | identity, fix_reversal | REJECT | identity | fix_reversal |
| 107 | GHSA-CW23-QWR7-C655 | identity, topology | REJECT | identity | topology, but_for |

### Ordinal 5 GHSA-FWPR-59HH-GR98 REJECT

Identity UNKNOWN. Unreviewed GHSA; repo advisory 404. Not converted to FAIL.

AI hunk PASS on `bce0d2ba` (Claude Opus 4.6) adding `initProjectMemory` literal-path 12-hex key. Topology PASS: candidate equals peeled `v0.4.0`. But-for PASS. Fix reversal PASS on commit `6d709229`. Release FAIL: live tags remain `v0.3.1` and `v0.4.0`; no tag contains `6d709229`. Uniqueness PASS.

### Ordinal 61 GHSA-3636-3MQQ-Q7X9 REJECT

Identity UNKNOWN. Unreviewed GHSA; repo advisory 404.

AI hunk PASS on `47bf71cc` (Claude Opus 4.7) adding `Galaxy.find` with only `Galaxy.enabled=true`. Topology PASS: ancestor of carrier `709087cc` and `v2.5.37`. But-for PASS.

Fix reversal FAIL: named closer `d3adfe1a` embeds PHP `'Galaxy.distribution' > 0` in CakePHP conditions. `8aa2bb6d` later uses `Galaxy->buildConditions`. Release FAIL: `v2.5.39` contains `d3adfe1a` and not `8aa2bb6d`. Uniqueness PASS.

### Ordinal 86 GHSA-7X5Q-8F6H-RJRC REJECT

Identity UNKNOWN. Unreviewed GHSA; repo advisory 404.

AI hunk PASS on `840ec19c` (Claude): Nashorn `--no-java` to GraalJS `HostAccess.ALL`. Topology PASS: member ancestor of carrier and `v3.21.21`; blob `1a5feb7d` equal. But-for PASS for the JS evaluator.

Fix reversal FAIL: hop1 and `v3.30.1` still use `HostAccess.ALL`; hop2 `c691e35e` / `v3.30.2` sets `js.load` false and still keeps `HostAccess.ALL`. Release PASS for containment of origin in `v3.21.21` and hop2 in `v3.30.2`. Uniqueness PASS.

### Ordinal 107 GHSA-CW23-QWR7-C655 REJECT

Identity UNKNOWN. Unreviewed object; repo advisory 404.

AI hunk PASS on member `b20880c1` (Claude Sonnet 4.6): High `contains()` moved inside `split(['|','&',';'])`, omitting newline. Topology FAIL: member is not an ancestor of `ironclaw-v0.29.1` or squash `b58b4215`; blobs differ (`4798d0c3` / `fa92cb37` / `8f574e90`). But-for FAIL for the assigned member. Fix reversal PASS on merge `a1d7c3ba` in `ironclaw-v1.0.0`. Release PASS on crate tags for the squash line, not the assigned member. Uniqueness PASS.

## Conservation and claim boundary

Assigned 4 = reviewed 4 + unreviewed 0. KEEP 0. REJECT 4. Canonical ledger not edited. Owned clone and raw HTML/diff cache removed. No greater-than-200 claim.

Replay commands are in `cases.jsonl` and `replay.txt`.
