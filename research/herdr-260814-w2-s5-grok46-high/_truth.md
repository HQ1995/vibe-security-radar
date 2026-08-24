# Research truth layers - single-source rule

Date: 2026-08-14. This file is the leader's anti-mixing map. Exactly one
layer may be quoted as the current claim; every other layer must be labeled
with its own name when cited.

## L0 - Frozen ground truth (the only claim source)

- autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl
  - ledger.jsonl sha256: a9b23a7ca39104f851b684a4089fa58f43887bb379895b68f6306c47d969ec06
  - 84 strict released first-party GHSA identities; status HOLD;
    causal/publication/integration admission all false; greater-than-200
    unsupported.
  - Rule: this ledger is immutable. New admissions require a NEW canonical
    directory built by a deterministic builder plus an independent leader
    replay of every appended row. Workers never edit it.

## L1 - Source layer (input, never a standalone claim)

- autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl (211 hypotheses)
- autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl (212 cases)
- autoresearch/orchestrator-260813-fp211-audit/experience.json (54 FP class census)
- 65 CONFIRM / 84 NARROW / 54 FALSE_POSITIVE / 9 UNKNOWN; 149 causal-valid.

## L2 - Presentation layer (display contract, not data)

- web/data/index.json: 36 published case pages, generation 6bb26cae...,
  generated 2026-08-09, coverage through 2026-03-31.
- web/src/lib/research-status.ts: strictReleasedGhsa=84, status HOLD,
  publicationReady=false.
- The 36-page catalog and the 84-strict ledger are different denominators;
  never merge their counts.

## L3 - Worker proposals (never truth until leader replay)

- autoresearch/herdr-260814-final-unknown9-grok46-high/ (9 UNKNOWN ordinals)
- autoresearch/herdr-260814-sample12-iaa-grok46-high/ (12-row blind re-review)
- autoresearch/orchestrator-260814-closure-sol/ (taxonomy + estimate + closure)
- Worker PASS/CONFIRM is a proposal. Agreement with L0 is measured, not assumed.

## Stale / superseded (never cite as current)

- SOK 40 alias classes (2026-08-09 freeze), strict-200 identifier closure,
  canonical71/72/73/78/81/82, and all herdr-260812/260813 campaign dirs.
- These are historical checkpoints. Only canonical84 (L0) is current.

## Quarantine

- autoresearch/.leader-quarantine-260814/ holds four stray root-level temp
  artifacts moved out of the way on 2026-08-14 (three ANC hash files and
  .tmp_compute_output.py). Nothing frozen was deleted.
