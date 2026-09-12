# Data contract

Neon is canonical; `artifacts/funnel-account-*.jsonl` is its deterministic recovery
export, not a publish input. The [publisher](../scripts/publish_tp_ledger.py)
reads case rows from Neon `ledger_rows` (`--from-export` reads the jsonl
backup). Reader-facing values that have no column in `ledger_rows` (curated
summaries, severity, release ranges, advisory dates, backfilled code evidence)
live in committed files under `scripts/`, never in the previous publish output.
`finalize` exports after its transaction succeeds. Writes follow
[AGENTS.md](../AGENTS.md).

Field definitions: [Ledger SQL](../scripts/ledger_schema.sql) and
[published types](../web/src/lib/research-data.ts).

The public site is a concise projection, without internal workflow dashboards.
The ledger retains full assessments, evidence and history; published types do not
define the research evidence standard.

## Ledger

- `class_id` is the immutable advisory-cluster key; retain all `advisory_ids`.
- `status`: `UNANALYZED`, `PARTIALLY_ANALYZED`, or terminal `AI_ROOT_CAUSE`,
  `AI_CODE_FLAWED`, `NOT_AI`, `BLOCKED`, `FALSE_POSITIVE`.
  `EVIDENCE_GAP` is an audit verdict, not a ledger status.
- `finalize` requires `expected_revision` and supporting `assessment_ids`.
  New terminal updates require nonempty `row.causal_research` with `verdict`
  matching `row.status`: the leader's accepted synthesis. Assessments and full row
  versions, including supporting assessment IDs, are append-only.
- Publisher/envelope use `row.causal_research` whenever the key exists; null, empty
  or malformed values do not fall back to older assessments. Only rows without
  the key retain legacy lookup. Canonical publication fields override synthesis
  fallbacks, including explicit nulls/empty sets.

## Audit records

One JSON record per case, kept in the batch's research directory; the accepted
synthesis lands in the ledger row's `causal_research` in the same shape. Required
fields beyond the verdict and its prose: `advisory_disposition`, `introducer_sha`,
`landing_commit`, `bic_granularity`, `decomposed_shas`, `decomposition_probe`,
`ai_on_bic` (JSON boolean, or absent when not established), `ai_marker`,
`fix_ai_marker`, `remaining_gap`, `flip_condition` (what evidence would change the
verdict) and `ai_admissibility` whenever AI evidence sits outside the BIC object.

    python3 scripts/audit_record_gates.py --strict research/<batch>/<case>.json
    python3 scripts/compare_slots.py --a research/<batch>/review --b research/<batch>/verify

Verdict rule, by the change that carries the defect:

- `AI_ROOT_CAUSE` — the vulnerable behavior first enters the tree in an AI-attributed change.
- `AI_CODE_FLAWED` — the origin is human (or non-AI) and the AI-attributed change is itself
  the flawed code: AI-written logic, or an incomplete remediation or hardening that leaves
  the defect or creates the exposure the advisory describes.
- `AI_CAUSAL_CONTRIBUTOR` — an AI-attributed change adds the causal exposure path of a
  human-origin defect, without being that origin or its repair.
- `NOT_AI` — no AI attribution on the object that carries the defect.
- `FALSE_POSITIVE` — the advisory is rejected, withdrawn or a duplicate.
- `EVIDENCE_GAP` / `BLOCKED` — open: the decisive fact, or the upstream answer, is missing.

Introduction, new exposure and incomplete remediation are the three accepted reasons a case
may be a TP; none of them requires AI to have written the original defect.

## Published cases

- Only `AI_ROOT_CAUSE` / `AI_CODE_FLAWED` rows are TPs. Public `case_id` uses
  GHSA/CVE IDs; preserve aliases. `published_at` comes from first-party advisory
  metadata, never the introducer's date.
- `candidate_set` identifies causal AI changes; `carrier_set` identifies merges
  carrying them; `minimum_fix_set` identifies the direct security fixes.
- Unpatched cases require `unpatched.confirmed=true`, `reason` and
  `potential_fix.approach`/`rationale`; reference commit/URL may be null.
  Keep `fix_sha`/`direct_fix_sha` null, `minimum_fix_set` empty, and omit fixed
  release/fix evidence. Candidate evidence is still required.
- `ir_chain` is mandatory for `AI_INCOMPLETE_REMEDIATION` and absent otherwise:
  original defect/author, `attempted_remediation`, `residual_bypass`, `final_closure`.
  Its candidate/fix SHA sets must match the case. Missing `original_sha` requires
  `unresolved_reason` and `original_author_kind=UNKNOWN`; final closure may be
  absent only for a substantiated unpatched case.
- Curated `code_evidence` belongs on the canonical row. Hunk roles `candidate`
  and `fix` identify source commits; `before_after` identifies a composed comparison.
  Unavailable code needs `unavailable_reason`. Case-level prose is not a hunk annotation.
  `annotation_mode="hunk_specific"` requires distinct annotations and matching
  `required_anchors` for the displayed roles.
- Reader copy is finished prose. A `description`, `mechanism` or evidence
  `summary` must end a sentence; a value that stops mid-word means a writer sliced
  the text at a character offset and the tail is lost. Length caps cut at a
  sentence boundary (`site_preflight.clip_sentence`), never at an offset, and
  `site_preflight.py` rejects a payload whose reader copy is a fragment or an
  audit shorthand dump.
- Preserve canonical field values, including explicit nulls/empty sets, over
  legacy display overrides. `publication_status` is `confirmed`, `qualified` or
  `provisional`; incomplete evidence cannot be confirmed and `confirmed` requires
  empty `publication_issues`.
- Read counts from `snapshot`: ledger total = reviewed + in progress + not started;
  case count = confirmed + qualified + provisional.

Checks: [audit records](../scripts/audit_record_gates.py),
[ledger transactions](../scripts/ledger_store.py),
[publication](../scripts/site_preflight.py). Causal judgment follows the
[Audit protocol](AUDIT-PROTOCOL.md).
