# Leader reconciliation - 2026-08-14 scale-up close-out

Truth layers: docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md is the single-source map.
L0 canonical84 ledger.jsonl sha256 a9b23a7ca39104f851b684a4089fa58f43887bb379895b68f6306c47d969ec06
re-checked after all lanes finished: unchanged.

## Lanes

- g4-unknown9 (grok-4.6 high): 9/9 assigned ordinals re-reviewed, verdicts
  9x UNKNOWN, 0 countable, terminal=false. No evidence invented; GitHub API
  unused. Replay blocker: coolify blob fetch failed, kept as UNKNOWN not FAIL.
  Finding: ordinal 116 stored topology/fix_reversal/release PASS reopened to
  UNKNOWN (sibling first-parent vs tag-blob mismatch could not be replayed).
  Zero proposals, so no integration.
- g4-sample12 (grok-4.6 high): blind 12-row re-review of counted strict rows.
  Verdicts 10 CONFIRM, 1 NARROW, 1 UNKNOWN, 0 FALSE_POSITIVE; 10/12 agree with
  counted-strict status. Disagreements: coolify GHSA-X9QH-W4C4-54F9 identity
  unrecoverable from local sources (infra gap); openclaw GHSA-VJ3G-5PX3-GR46
  NARROW vs counted strict (candidate a604df8c vs carrier 2267d58a authorship
  transfer dispute). No FP found in the sample.
- sol-closure (gpt-5.6-sol max): fp_taxonomy.md (54 FP rows classified, counts
  leader-verified against experience.json), estimate BLOCKED (missing n1 and m
  lane capture sets; formula and unblock inputs documented), closure.md claim
  boundary: 84 strict HOLD, greater-than-200 unsupported.

## Integration decision

No countable proposals from any lane. canonical84 stays 84/HOLD; publication
stays HOLD; no commits made. Next optional steps (require user sign-off):
leader replay of the two IAA disagreements, and a fresh canonical snapshot
only if a future packet yields countable rows.

## Measured spend (partial)

g4-unknown9 reached at least 11.2M input / 112K output tokens (observed
mid-run); g4-sample12 and sol-closure totals not extracted from pane UI.

