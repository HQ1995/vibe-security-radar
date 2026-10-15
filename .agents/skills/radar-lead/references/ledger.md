# Ledger and published data

Neon `ledger_rows` is the ground truth. `artifacts/ledger.jsonl` is its export and the
copy that saves Neon traffic:
- `finalize`, `apply` and `intake` refresh it incrementally by `updated_at`;
- `check` and `publish_tp_ledger.py --prefer-export` ask Neon only for a digest and read
  the export when it matches;
- the site build, duplicate checks and incremental reconciliation read it;
- `bootstrap` restores an empty database from it.

Never hand-edit it. `ledger_store.py export-history` writes a full local backup of the
history tables to `.ai-slop/ledger-history` (untracked); take one before a large migration.
Reader-facing values without a ledger column (curated summaries, severity, release ranges,
advisory dates, code evidence) live in committed files under `scripts/`. `scripts/advisory-months.json`
dates each row of the original universe for the monthly research-coverage strip; rows admitted later
are dated by their own `source_intake` records. Operational order
and recovery follow the [release reference](release.md).

Field definitions: [Ledger SQL](../../../../scripts/ledger_schema.sql) and
[published types](../../../../web/src/lib/research-data.ts).

The public site is a concise projection, without internal workflow dashboards.
The ledger retains full assessments, evidence and history; published types do not
define the research evidence standard.

## Ledger rows

A row holds only the fields below; earlier fields remain in `ledger_versions`.

| Group | Fields |
| --- | --- |
| Identity | `class_id`, `status`, `advisory_ids`, `advisory_aliases`, `advisory_identity`, `advisories`, `advisory_ids_source`, `source_intake`, `repo`, `duplicate_of_class_id` |
| Conclusion | `causal_research` |
| Publication | `site_scope`, `site_tier`, `site_publication`, `code_evidence`, `candidate_set`, `minimum_fix_set`, `carrier_set`, `candidate_sources`, `candidate_fix_edges`, `ir_chain`, `gates`, `gates_source`, `fixed_release`, `vulnerable_release`, `unpatched`, `mechanism`, `description`, `cwes`, `references`, `severity`, `fix_authorship` |

- `class_id` is the immutable advisory-cluster key. `advisory_ids` only grow; a write that
  removes one is rejected.
- `status`: `UNANALYZED`, `PARTIALLY_ANALYZED`, or terminal `AI_ROOT_CAUSE`,
  `AI_CODE_FLAWED`, `NOT_AI`, `BLOCKED`, `FALSE_POSITIVE`.
  `EVIDENCE_GAP` is an audit verdict; it lands as `BLOCKED`.
- `causal_research` is the one accepted record, and every reader uses only it. Its
  `verdict` matches `status` (`EVIDENCE_GAP` on a `BLOCKED` row); null, empty or malformed
  values are errors, never a fallback. A record with `legacy_projection` was copied
  unchanged from an older field on 2026-10-15 without new research; it has no
  `protocol_version`, so case selection treats it as an older-standard conclusion.
- `duplicate_of_class_id` names the canonical row of the same vulnerability: a CVE assigned
  to a maintainer advisory, its unreviewed mirror, or a withdrawn duplicate advisory. The
  canonical row carries the union of advisory IDs and the strongest research. The publisher
  and case selection skip duplicate rows. A duplicate keeps a conflicting conclusion only as
  the opposing argument for re-research.
- `repo` is the advisory-side repository namespace: the repository the keyed advisory
  designates in its `linked_repos` / `vendor_products`, resolved against object content when
  the advisory leaves it implicit, never an advisory database. It is not necessarily where
  the row's own objects resolve - `alias-4caa00e9` (CVE-2026-1739) has advisory, product and
  repair objects in `free5gc/pcf` while its introducer resolves only in `free5gc/free5gc`.
- `finalize` lands research: `expected_revision`, supporting `assessment_ids` and a
  terminal `causal_research`. `apply` lands maintenance (identity repairs, migrations) with
  an actor and description; it checks revisions, attaches assessments when given, and both
  paths run the envelope gate. Assessments and row versions are append-only.

## Published cases

- Only `AI_ROOT_CAUSE` / `AI_CODE_FLAWED` rows without `duplicate_of_class_id` are TPs.
  The public `case_id` is the maintainer advisory; mirrors, CVEs and withdrawn duplicates
  are aliases, and a renamed page keeps a redirect in `web/public/_redirects`.
  `published_at` is the maintainer advisory's first-party date, never a mirror's or the
  introducer's.
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
  display overrides. `publication_status` is `confirmed`, `qualified` or
  `provisional`; incomplete evidence cannot be confirmed and `confirmed` requires
  empty `publication_issues`.
- Read counts from `snapshot`: ledger total = reviewed + in progress + not started;
  case count = confirmed + qualified + provisional.

Checks: [audit records](../../../../scripts/audit_record_gates.py),
[ledger transactions](../../../../scripts/ledger_store.py),
[publication](../../../../scripts/site_preflight.py). Causal judgment follows the
[Audit protocol](../../radar-audit/references/protocol.md).
