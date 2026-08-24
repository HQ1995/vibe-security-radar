# Capture-recapture prevalence estimate

## Result

`BLOCKED`. The frozen artifacts do not preserve two complete, comparable final-inclusion capture sets, so neither a Lincoln-Petersen estimate nor its Chapman-corrected form can be reported without inventing inputs.

The target counting unit is one deduplicated CVE/GHSA alias class satisfying the public AI-attribution and case-level causal inclusion contract, over the frozen window from 2025-05-01 through 2026-08-09. Sources: [goal_contract.json](../orchestrator-260809-1127/goal_contract.json) and [official census summary.json](../orchestrator-260809-0539/current-official-census/summary.json).

## Recoverable inputs

| Symbol | Candidate capture lane | Value | Frozen evidence |
|---|---|---:|---|
| `n1` | `advisory_to_repository_history` | `BLOCKED` | [screening-ledger.json](../orchestrator-260809-1127/screening-ledger.json) records the lane's routing/history result but no deduplicated final-inclusion alias set or count. |
| `n2` | `public_web_and_literature_snowballing` | 1 | [web-literature-adjudications.json](../orchestrator-260809-1127/web-literature-adjudications.json) contains exactly one inclusion, alias class `alias-60e4ba8e4edaa0300d797af5`. |
| `m` | Intersection of the two final-inclusion sets | `BLOCKED` | The lane-1 member set is absent, so the overlap with the one-member lane-2 set cannot be computed. |

Exactly two counts are missing: `n1`, the number of finally included alias classes captured by the advisory-to-repository-history lane, and `m`, the number of included alias classes captured by both lanes. `n2` is not missing.

The aggregate strict corpus cannot substitute for `n1` because [corpus.json](../orchestrator-260809-1127/corpus.json) is not discovery-lane labeled. The official-term artifact's 289 source-hit rows also cannot substitute for a capture count because they are routing hits rather than causally admitted alias classes; see [official-ai-term-hits.json](../orchestrator-260809-1127/official-ai-term-hits.json) and [deepseek-official-term-screen.json](../orchestrator-260809-1127/deepseek-official-term-screen.json).

## Formula

For two complete capture sets with sizes `n1` and `n2` and overlap `m`:

```text
Lincoln-Petersen: N_hat_LP = (n1 * n2) / m
Chapman:          N_hat_Chapman = (((n1 + 1) * (n2 + 1)) / (m + 1)) - 1
```

To unblock the calculation, freeze the complete deduplicated alias-class membership set `A` for `advisory_to_repository_history`, derive `n1 = |A|`, compute `m = |A intersect B|` against the already frozen web/literature set `B`, and document why the two capture mechanisms can be treated as sufficiently independent. Until then, the estimate remains `BLOCKED`.
