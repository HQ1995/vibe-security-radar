# Wave3 unknown-2 closure: GHSA-4RMQ-MC2C-R495 and GHSA-X2HW-PX52-WP4M

**REJECT both.** KEEP proposal 0. Packet delta 0. Current leader-accepted count remains 84.

Owner: `autoresearch/herdr-260814-p12-unknown2-grok46-high/`. Assigned exactly the two unresolved wave3 rows: p1 `GHSA-4RMQ-MC2C-R495` and p2 `GHSA-X2HW-PX52-WP4M`. Independent first-party advisory objects and Git history, including owned PR-ref fetches. Generic Copilot trailers on many-author squashes were not treated as hunk authorship. KEEP requires all seven gates PASS at high confidence. Both rows fail `ai_hunk_gate`, `topology_gate`, and `but_for_gate`. This packet does not admit either row, does not edit L0 `canonical84`, and does not support a greater-than-200 claim.

Conservation: assigned=2, reviewed=2, unreviewed=0.

## GHSA-4RMQ-MC2C-R495 -- REJECT

Minimal counterexample: unmarked member `f0f7d0d7448945f0384a6e0884090994ae0ad04d` (RafilxTenfen, no AI trailer) changes `AfterBtcDelegationUnbonded` from `!fpSecuresBabylon || !isFpInActiveSet` to `!fpSecuresBabylon || !isFpActiveInPrevSet || !isFpActiveInCurrSet`. That current-set conjunct is the phantom-stake hole: same-block unbond plus FP deactivation skips the ActiveSatoshis subtraction.

PR #1731 squash `a7c9a2828f213e8157ba60501dfcc0e43233f77e` lands the same predicate with no Copilot trailer. File blob `4fe8df8e` equals follow-up `933b6b2e` (comment typo only) and original feature squash `77c301cc` (#1707). Backport #1755 member `dfd35065` drops `fpSecuresBabylon` but keeps `|| !isFpActiveInCurrSet`. GitHub squash `2bd9585607bd7b1c0905d21b92bcdb6d4c03bf36` (parent `4bfae6d85240af95e4ab37d64c12f331e3c2f91a`) is the v4 carrier. Members `f0f7d0d7` and `a7c9a282` are not ancestors of `2bd95856`. The Copilot trailer on `2bd95856`/`77c301cc` is the same generic coauthor list as earlier squash `8076968b` (#1683), which used a different `fpBbnPrevStatus` predicate.

Minimum fix `e65c3a55a398a403103f1b089cf76f0d4befc7a0` (#1890) changes the early return to `!isFpActiveInPrevSet`. That is mechanism reversal, not origin. Tags: `v4.0.0`/`v4.1.0` blob `c8e6db4a` still has the current-set conjunct; `v4.2.0` equals the fix and blob `2243b3ef` does not.

## GHSA-X2HW-PX52-WP4M -- REJECT

Minimal counterexample: unmarked member `7e886f151f4e6a9427f2a9858c9b047f1dcfe689` (Siddharth Suresh, no AI trailer) first adds `soroban-sdk/src/crypto/bn254.rs`. `From<U256> for Fr` is `Self(value)` with no modulo-`r` reduction. `from_u256`/`from_bytes` call `.into()`. `PartialEq` compares raw `U256`. PR #1615 squash `3cf10a984dba03f68b4f2ed653b715063e983bba` (Jay Geng; coauthors Siddharth and Leigh) lands that file with no Copilot trailer.

Later #1667 members `#1630` and `#1645` keep `Self(value)`. Final blob `142655a1` equals PR #1667 head, squash `ecad5addcae1dfc3b9bd9865ea5977aef5f16843` (parent `a60b7e8f8464e6bd6ffea4a5d7b9843a76deeb71`), and tag `v25.0.0`. Members `7e886f15` and `3cf10a98` are not ancestors of `ecad5add`. The Copilot trailer on the 183-file squash sits among seven human coauthors plus `github-actions[bot]` and does not map to the Fr constructors.

Parent `a60b7e8f` already implements BLS12-381 `Fr From<U256>` as `Self(value)`. Removing the candidate does not eliminate the advisory's BLS equality hole. Minimum fix `082424b30bf22ea7fb8c79f16ccd135e0ae9f3db` (#1750) routes construction through `rem_euclid(r)`. Tag `v25.3.0` contains that reduced blob `09f50852`. Containment is not a save.

## Gates

KEEP requires all seven gates PASS.

1. `identity_gate`: PASS both. GitHub-reviewed first-party objects, not withdrawn. Babylon names `github.com/babylonlabs-io/babylon/v4` fixed at 4.2.0. Soroban names `soroban-sdk` with alias CVE-2026-32322 and fix commit `082424b3`.
2. `ai_hunk_gate`: FAIL both. Atomic unmarked humans authored the relevant hunks. Generic Copilot on the carriers is not member-to-hunk proof.
3. `topology_gate`: FAIL both. Candidate parents are resolved (`4bfae6d8`, `a60b7e8f`). Squash members that authored the hunks are not ancestors of the landing squashes. Counting the Copilot trailer as origin is authorship transfer.
4. `but_for_gate`: FAIL both. Removing the Copilot trailer, or treating the carrier as AI-authored, leaves the human-authored predicate / unreduced `Fr` constructors. For Soroban, parent already has the same BLS12-381 hole.
5. `fix_reversal_gate`: PASS as mechanism check, not a save. `e65c3a55` drops the current-set conjunct. `082424b3` reduces `Fr` modulo `r`.
6. `release_gate`: PASS as artifact containment, not a save. Babylon `v4.0.0`/`v4.1.0` vs `v4.2.0`. Soroban `v25.0.0` vs `v25.3.0`.
7. `uniqueness_gate`: PASS, not a save. Both identities are absent from L0 `canonical84`.

`remediation_patch_delta_gate` is NOT_APPLICABLE.

## Replay commands and hashes

Replay (creates owned clones under `work/clones/`, fetches PR refs, checks parents/blobs/markers):

```
zsh autoresearch/herdr-260814-p12-unknown2-grok46-high/replay.zsh
```

Expected last line:

```
REPLAY_OK reviewed=2 KEEP_proposal=0 REJECT=2 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=84
```

Manual anchors after replay:

```
git --no-optional-locks -C work/clones/babylon log -1 --format='%P' 2bd9585607bd7b1c0905d21b92bcdb6d4c03bf36
git --no-optional-locks -C work/clones/babylon rev-parse f0f7d0d7448945f0384a6e0884090994ae0ad04d:x/costaking/keeper/hooks_finality.go
git --no-optional-locks -C work/clones/soroban log -1 --format='%P' ecad5addcae1dfc3b9bd9865ea5977aef5f16843
git --no-optional-locks -C work/clones/soroban rev-parse 7e886f151f4e6a9427f2a9858c9b047f1dcfe689:soroban-sdk/src/crypto/bn254.rs
```

Input SHA-256:

| Path | SHA-256 |
| --- | --- |
| `autoresearch/orchestrator-260814-w3-sol-p1/result.json` | `0ac57a79984c896e0455287ee014d75452a3d605fd073195ff09b7bcd840745f` |
| `autoresearch/orchestrator-260814-w3-sol-p1/cases.jsonl` | `f271da3dd1843bf095e2befa31f5b7b1f33f266991539f7a4089b88dd584012a` |
| `autoresearch/orchestrator-260814-w3-sol-p2/result.json` | `90f9fe8e82a1b72136593edbdbc437c01f141267f6fd12955eca785f764e1cd4` |
| `autoresearch/orchestrator-260814-w3-sol-p2/cases.jsonl` | `0aa2834777e9c4628c1ae601c685b5685c6fc7f1ba8b162d0fe695b72d177213` |
| `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-1.jsonl` | `cb782f031b5a707bfb8d7b63cc1710f6ad0341096cf37bc76ed6b0031ad0be42` |
| `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-2.jsonl` | `27b72afa0995d061aa0e489a3342281a8135657a8ff9cb7170724aac25278d46` |
| `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md` | `94ba89b0ec0bb6703e7c5fbc33e5b35eb313ca243ec18add357f51685dcc06d1` |
| `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md` | `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3` |
| `docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md` | `70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f` |
| `autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl` | `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06` |
| `work/pages/advisory-database/GHSA-4rmq-mc2c-r495.json` | `3cfe28f97cd6620f8adb04e0043478f8d410b0b4eea7f2450bf76ffec73dc876` |
| `work/pages/advisory-database/GHSA-x2hw-px52-wp4m.json` | `8e3536e385b21590ba21afe55ddf57aa8b3c49500275e95048b8b738748b308c` |

`docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md` prints a different canonical84 hash than the recomputed ledger file. This packet uses the recomputed file hash and does not edit either frozen file.

## Claim boundary

Worker REJECT is not admission. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. L0 remains 84, status HOLD. Publication and more-than-200 stay unsupported.
