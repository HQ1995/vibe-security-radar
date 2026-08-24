# Closure and claim boundary

## Final boundary

The frozen canonical artifact is a `HOLD` snapshot containing 84 distinct strict released first-party GHSA identities. It explicitly sets causal admission, publication admission, integration readiness, and publication readiness to false. It does not support a greater-than-200 claim. Source: [canonical84 summary.json](../orchestrator-260814-ghsa200-canonical84/summary.json).

The source audit conserves 211 mechanism hypotheses and 212 public GHSA cases. Of those cases, 149 are causal-valid at either strict or narrowed scope, while 9 remain `UNKNOWN` and are excluded from the valid count. The unresolved ordinals are 35, 51, 53, 56, 84, 116, 129, 153, and 154. Sources: [FINAL_REPORT.md](../orchestrator-260813-fp211-audit/FINAL_REPORT.md), [audit summary.json](../orchestrator-260813-fp211-audit/summary.json), and [final_mechanisms.jsonl](../orchestrator-260813-fp211-audit/final_mechanisms.jsonl).

Two reconciliation obligations remain pending. The nine-`UNKNOWN` proposal lane has no terminal review artifact, and any worker verdict would still require independent leader verification under its [assignment](../herdr-260814-final-unknown9-grok46-high/SPEC.md). The blind 12-row inter-annotator-agreement sample likewise has no result artifact beyond its [assignment](../herdr-260814-sample12-iaa-grok46-high/SPEC.md). Neither pending lane may silently change the canonical count. The capture-recapture prevalence estimate is separately `BLOCKED` because comparable per-lane capture counts and overlap are not frozen; see [estimate.md](estimate.md).

## Publication-ready statement

In the frozen study window, the canonical HOLD snapshot supports a provisional strict lower bound of 84 distinct first-party GHSA cases with released AI-contributed vulnerability mechanisms; it does not support a claim of more than 200 cases or an estimate of global prevalence. The broader source audit evaluated 211 mechanism hypotheses mapping to 212 public cases, found 149 causally valid at strict or explicitly narrowed scopes, and left 9 unresolved. Because the canonical snapshot is not publication-admitted and the unresolved-case and blind inter-annotator-agreement lanes still require leader reconciliation, 84 must be reported as a provisional frozen-ledger boundary rather than a final population total.

## Follow-up study measurements

- Signal-level precision and recall for each AI-attribution signal, measured against a manually adjudicated sample that includes both positive and negative controls.
- Inter-rater reliability at both gate and final-verdict levels, with a frozen blind sample, adjudication protocol, agreement statistic, and uncertainty interval.
- Sampling-based prevalence from a probability sample of the eligible alias-class frame, with inclusion weights and confidence intervals; capture-recapture should be attempted only after complete independent lane membership sets are frozen.
