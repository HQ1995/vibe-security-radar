# Unified fail-closed verifier - report

Date: 2026-08-13
Lane: `autoresearch/herdr-260813-ghsa200-unified-verifier/`
Role: fail-closed acceptance gate. This lane never promotes a case, never edits
canonical/publication files, and never counts anything. It only proves HOLD
until every acceptance condition is satisfied.

## Verdict

`status=HOLD`, `integration_ready=false`, `publication_ready=false`. The
verifier fails closed with **30 blockers**. The 200-case claim is not
integration-ready.

## Blockers (enumerated, not waited on)

| class | count | detail |
|---|---:|---|
| nonterminal lane | 4 | `fresh_am`, `fresh_nz`, `remediation`, `upgrade_b` still ACTIVE |
| unresolved UNKNOWN | 5 | upgrade-a worker rows still UNKNOWN |
| unresolved BLOCKED | 20 | upgrade-a worker rows still BLOCKED (routed, not yet resolved) |
| patch-delta gap | 1 | `GHSA-VH5J-5FHQ-9XWG` (ordinal 84) is `AI_INCOMPLETE_REMEDIATION` but lacks `remediation_patch_delta_gate=PASS` |

The `gap` inventory lane and the four `upgrade_a` terminal review layers
(worker -> red-team -> ordinal-20 composite -> third review) pass their checks:
all four third-review ACCEPT rows carry all seven PASS gates; ordinal 93 is
correctly normalized to `AI_NEW_SURFACE_CONTRIBUTOR` with a `scope_statement`;
the stale proposer SHA is accepted only because the third review declares an
explicit `superseded_edge` binding the corrected final hypothesis.

## Fail-closed conditions implemented

1. missing/nonterminal lane
2. PASS/ACCEPT/CONFIRM/KEEP row lacking any of the seven PASS gates
3. contributor class lacking `scope_statement`
4. `AI_INCOMPLETE_REMEDIATION` lacking `remediation_patch_delta_gate=PASS`
5. proposal lacking independent terminal review
6. review hypothesis SHA mismatch/stale unless `superseded_edge` binds the
   corrected final hypothesis
7. conflicting review verdicts for one case
8. duplicate case / public-ID / mechanism overlap
9. unresolved UNKNOWN/BLOCKED row
10. source/assignment conservation failure

Each is a deterministic pure function in `verifier.py`, covered by
`test_verifier.py` (12 tests: all ten fail-closed cases plus the explicit
superseded-edge positive control and a HOLD-output integration check).

## Inputs

The verifier reads only the leader `CONTRACT.md` (sha256
`cbd04ef2...90ed3`), `baseline.json` (sha256 `b1cfc5c0...7493`), and the input
paths declared in `manifest.json`. It performs no arbitrary schema exploration.
