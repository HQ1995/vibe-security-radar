# CVE-2026-45582 ledger patch notes

Status: draft for leader review only. The patch has not been applied to Neon, the recovery export, or the site.

## Basis

- Current Neon row: `alias-ad08edcf98825ffa3306395b`, revision `1`, read with `python3 scripts/ledger_store.py get alias-ad08edcf98825ffa3306395b`.
- Independent conclusion: `research/provisional-closure-20260831/not-ai-second-review.md`, section “CVE-2026-45582 — DISAGREE”.
- Human original: `5960d2826eb23e87ed142b3a88cf5d8ac0eddc42`, direct parent `78abda601ab0c34fb60cb760ed18a2fa5ae3c232`. The commit creates `src/telemetry/workflow-sanitizer.ts`; its commit object identifies author/committer `czlonkowski` and contains no AI marker.
- AI security attempt: `597bd290b69459c3b84bbd7cffc5e51c4aa0f28b`, direct parent `99c5907b71a6c3228d345a2f0879cd893f30cd7e`. Its commit object contains repeated `Generated with Claude Code` and Claude coauthor markers; its sanitizer delta preserves context in URL-shaped fields.
- Final closure: `6cf6fef653fcd6d598f2f356aac4754931c7329f`, which fully redacts URL-like fields. Git tags bound the narrow AI-created behavior to `v2.22.17` through `v2.51.2`, with `v2.51.3` fixed.

## Patch intent

The top-level publication fields replace the false `47510ef6…` candidate with the exact `597bd290… -> 6cf6fef…` incomplete-remediation edge, set an empty carrier set, record all seven gates as `PASS`, and add the complete `ir_chain` required by `docs/DATA-SCHEMA.md`. The draft also removes the stale `blocked535` payload and companion verdict, adds a corrected `causal_research` envelope for re-derivation, then sets `ledger_best` to the existing closed-state value `CAUSAL_CHAIN_CLOSED`.

`assessment_ids` is intentionally empty because the independent Markdown review is not a registered Neon assessment.

## Leader review points

- `CAUSAL_CHAIN_CLOSED` is supported by existing ledger precedent and by `scripts/select_round7_pool.py`; no new state value was introduced.
- `gates_source` is `provisional-closure-20260831/not-ai-second-review`; change it only if the final transaction uses a different canonical source label.
