# Research data contract

Machine-readable sources for the AI-vulnerability catalog. Every file below
is git-tracked and reproducible from the listed inputs. A future model can
scan this directory (or `web/src/generated/research-data.json` alone) and
get the full evidence chain per case without guessing field semantics.

## Layers

| Layer | File | Rows | Role |
|---|---|---|---|
| Working ledger | `artifacts/funnel-account-*.jsonl` | 23,861 | Every candidate case ever considered; status state machine |
| Published catalog | `web/src/generated/research-data.json` | 195 | Confirmed TPs, fully structured evidence chains |
| Chain index | `research/orchestrator-260814-irchains-sol/ir-chains.jsonl` | 51 | Incomplete-remediation causal chains with `evidence_paths` |

## Ledger row (`artifacts/funnel-account-*.jsonl`)

One JSON object per line, keyed by `class_id` (alias of a deduped advisory
cluster). Writer: leader only, via `scripts/merge_funnel_lane.py`.

- `class_id` — stable cluster key (`alias-<40hex>`)
- `status` — state machine: `UNANALYZED` → `PARTIALLY_ANALYZED` →
  terminal `AI_ROOT_CAUSE` | `AI_CODE_FLAWED` | `NOT_AI` | `BLOCKED`
- `dossier_best` / `ledger_best` — final verdict payloads (may be null for
  older terminal rows; process fields below then carry the evidence)
- `repo`, `advisories` — repository identity, advisory count
- Process fields (`notai_*`, `blocked*`, `causal_research`, ...) — lane
  working records; naming is free-form, treat as evidence notes

TP classes: `AI_ROOT_CAUSE`, `AI_CODE_FLAWED`. Closed: `NOT_AI`, `BLOCKED`.

## Published case (`web/src/generated/research-data.json` → `cases[]`)

Regenerate with `python3 scripts/publish_tp_ledger.py` (see
`docs/AGENT-OWNERSHIP.md` for the single-writer contract).

Identity:

- `case_id` — public ID (GHSA/CVE); `aliases` — all known IDs
- `class_id` — ledger cluster key; `repository` + `repository_metadata`

Path (the case's causal journey):

- `contribution_class` — one of `AI_DIRECT_ROOT` (108), `AI_NEW_SURFACE_CONTRIBUTOR` (31),
  `AI_INCOMPLETE_REMEDIATION` (31), `AI_CODE_FLAWED` (23), `AI_CAUSAL_CONTRIBUTOR` (2)
- `candidate_set` — AI-authored commits that introduced/exposed the flaw
- `carrier_set` — commits that carried the flawed code across merges
- `minimum_fix_set` — the security fix commits that close the path
- `mechanism` + `mechanism_key` — vulnerable mechanism description
- `scope_statement` — what the case claims and does not claim
- `cause_category`, `cwes`, `severity`, `tier`, `gates`

Causal chain (`ir_chain`, present for all 31 `AI_INCOMPLETE_REMEDIATION`,
absent for other classes — they need no remediation chain):

- `original_advisory_ids`, `original_sha`, `original_author_kind/name`
- `original_mechanism`, `original_sink`
- `attempted_remediation` — the incomplete fix (candidate shas)
- `residual_bypass` — how the path stayed open
- `final_closure` — the fix that closed it

Code evidence (`code_evidence`, present for all 195):

- `candidate_url`, `fix_url`, `advisory_url` — primary sources
- `candidate_patch_sha256` — content hash of the AI change
- `candidate_hunks`, `fix_hunks`, `comparison_hunks` — line-level diffs
- `ai_marker`, `fix_marker` — authorship signals on each side

Publication: `published_at`, `fixed_release`, `vulnerable_release`,
`ai_provenance`, `fix_authorship`, `research_status`, `ledger_status`.

## Incremental scanning

- New TPs: rows in the ledger whose `status` flips to `AI_ROOT_CAUSE` /
  `AI_CODE_FLAWED`; each release batch appends to `research-data.json`
  (see `snapshot.case_count` / `snapshot.generated_at`).
- Full chains: `ir-chains.jsonl` rows carry `evidence_paths` pointing into
  `research/orchestrator-*/` lane artifacts for deep verification.
- Inputs that rebuild the catalog (all git-tracked): ledger, ir-chains,
  `research/.../ghsa200-canvas/sweep/*.json` (first-party dates,
  enrichment fixes, code evidence), `scripts/generated-code-evidence.json`,
  `scripts/*adjudications*.json`, `scripts/tp_publication_overrides.json`.
