# Independent red-team of 22 ACCEPT net-new GHSA hypotheses

**Verdict first: 21 KEEP proposals, 1 NARROW, 0 REJECT, 0 UNKNOWN, 0 BLOCKED.**

Review only. Not leader admission. Publication HOLD. `causal_admission` is false. Does not rebuild the 48-case lower bound and does not support a >200 claim.

## 7C3W downgrade (preserved)

**GHSA-7C3W-FXGH-FRC7** is **NARROW** on `but_for_gate`. Other six gates PASS. Countable: false.

Published repo GHSA confirmed PoC is parent `get_pipeline_job_output` interpolating unencoded `job_id` into `/jobs/${jobId}/trace`. Claude `c156ac76` copies that interpolation onto `/artifacts` tools. New route of an old invariant; ACCEPT upgrade refused.

## Gate vectors

All 21 KEEP rows have identity / ai_hunk / topology / but_for / fix_reversal / release / uniqueness = PASS.

7C3W: identity PASS, ai_hunk PASS, topology PASS, **but_for NARROW**, fix_reversal PASS, release PASS, uniqueness PASS.

## Edge rewrites (10, unresolved 0)

8JPQ, FMFG, J4XF, MF5G, PWF7, R48C, RG8M, RQP8, W28W, WV46. KEEP only on the counted SHA’s own first-parent diff plus that SHA’s own AI marker. No member-to-carrier authorship transfer.

G39V and PF93 are absent from fp211 (novel). Hostile ACCEPT members were non-ancestors; counted AI-marked squashes.

## Bound inputs

| Artifact | sha256 |
|---|---|
| CONTRACT.md | `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3` |
| baseline.json | `d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132` |
| final-review result.json | `4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528` |
| cases.jsonl (22 compact rows) | `d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889` |

Replay: `bash autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/replay.txt`
