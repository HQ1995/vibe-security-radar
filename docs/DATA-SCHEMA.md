# Data contract

Neon is canonical; `artifacts/funnel-account-*.jsonl` is its deterministic recovery
export. The [publisher](../scripts/publish_tp_ledger.py) reads Neon first with
committed-file fallback. Writes follow [AGENTS.md](../AGENTS.md).

Field definitions: [Ledger SQL](../scripts/ledger_schema.sql) and
[published types](../web/src/lib/research-data.ts).

## Ledger

- `class_id` is the immutable advisory-cluster key; retain all `advisory_ids`.
- `status`: `UNANALYZED`, `PARTIALLY_ANALYZED`, or terminal `AI_ROOT_CAUSE`,
  `AI_CODE_FLAWED`, `NOT_AI`, `BLOCKED`, `FALSE_POSITIVE`.
  `EVIDENCE_GAP` is an audit verdict, not a ledger status.
- `finalize` requires `expected_revision` and supporting `assessment_ids`.
  Assessments and version history are append-only.

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
