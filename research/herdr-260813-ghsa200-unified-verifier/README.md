# Unified fail-closed verifier

Deterministic, stdlib-only acceptance gate for the GHSA-200 causal-case
pipeline. It never promotes a case and never edits canonical/publication files;
it only proves HOLD until every acceptance condition is satisfied.

## Files

- `manifest.json` - declarative manifest. Pins the leader contract/baseline
  hashes and declares each lane's terminal state and input paths. Lanes that
  are unsupported or still active are marked nonterminal (`ACTIVE`), and the
  verifier fails closed on them.
- `verifier.py` - the verifier. Reads only the manifest, the pinned contract and
  baseline, and the manifest-declared input paths. Emits `result.json` with
  `status=HOLD`, `integration_ready=false`, `publication_ready=false`, and the
  enumerated blockers.
- `test_verifier.py` - unittest covering the ten fail-closed conditions plus the
  explicit superseded-edge positive control.
- `result.json` - terminal output (HOLD + blockers).
- `report.md` - verdict-first evidence summary.
- `replay.txt` - commands to reproduce.

## Fail-closed conditions

1. missing or nonterminal lane
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

## Run

```
python3 -m unittest test_verifier -v
python3 verifier.py --manifest manifest.json --root <repo-root> --output result.json
```

## Manifest contract

`manifest.json` is declarative. Each lane declares `state` (`TERMINAL` or
`ACTIVE`) and, for terminal lanes, an `inputs` list of `{path, role}` entries.
The verifier reads no path that is not declared in the manifest.
