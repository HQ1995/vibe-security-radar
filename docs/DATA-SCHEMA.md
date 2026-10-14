# Data contract

Neon is canonical; `artifacts/funnel-account-*.jsonl` is its deterministic recovery
export, not a publish input. The [publisher](../scripts/publish_tp_ledger.py)
reads case rows from Neon `ledger_rows` (`--from-export` reads the jsonl
backup). Reader-facing values that have no column in `ledger_rows` (curated
summaries, severity, release ranges, advisory dates, backfilled code evidence)
live in committed files under `scripts/`, never in the previous publish output.
`finalize` exports after its transaction succeeds. Operational order and recovery
follow the [case lifecycle runbook](RELEASE-RUNBOOK.md).

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
- `repo` is the advisory-side repository namespace: the repository the keyed advisory
  designates in its `linked_repos` / `vendor_products`, resolved against object content when the
  advisory leaves it implicit. It is not the repository the case was assigned under, and not
  necessarily the repository where the row's own objects resolve - `alias-4caa00e9` (CVE-2026-1739) has
  advisory, affected product and repair objects in `free5gc/pcf` while its introducer resolves only in
  `free5gc/free5gc`. Batch assembly rewrites the cell from the manifest, so a lane's case file keeps
  the value it was worked under while the accepted record and the Neon `ledger_rows` column take the
  manifest value. Changing a cell after a freeze moves the accepted digest and needs the delivery
  gate re-run.
- `finalize` requires `expected_revision` and supporting `assessment_ids`.
  New terminal updates require nonempty `row.causal_research` with `verdict`
  matching `row.status`: the leader's accepted synthesis. Assessments and full row
  versions, including supporting assessment IDs, are append-only.
- Publisher/envelope use `row.causal_research` whenever the key exists; null, empty
  or malformed values do not fall back to older assessments. Only rows without
  the key retain legacy lookup. Canonical publication fields override synthesis
  fallbacks, including explicit nulls/empty sets.

## Audit records

Current research contract: `2026-09-27.3` (see AUDIT-PROTOCOL). The base record
format originated in `2026-09-19.1`; the research-work sidecar was added in
`2026-09-25.1`. These dates do not migrate older frozen batches. Reject duplicate
JSON keys, including nested ones; later values must never silently replace evidence.

One JSON record per case, kept in the batch's research directory; the accepted
synthesis lands in the ledger row's `causal_research` in the same shape. Required
fields beyond the verdict and its prose: `advisory_disposition`,
`advisory_aliases`, `introducer_sha`, `landing_commit`, `bic_granularity`,
`decomposed_shas`, `decomposition_probe`, `ai_on_bic` (JSON boolean, or absent
when not established), `ai_marker`, `fix_ai_marker`, `fix_granularity`,
`remaining_gap`, `flip_condition` (what evidence would change the verdict),
`identity_class` and `disclosure_convention` for a `NOT_AI` verdict,
`false_positive_ground` for a `FALSE_POSITIVE`, `residual_triage` when a
residual cue was adjudicated as a version range, and `ai_admissibility`
whenever AI evidence sits outside the BIC object.

    python3 scripts/audit_record_gates.py --strict research/<batch>/<case>.json
    python3 scripts/audit_record_gates.py --strict --repo <clone_dir> research/<batch>/<case>.json
    python3 scripts/compare_slots.py --lane auditor1=<cases1> --lane auditor2=<cases2> --lane auditor3=<cases3>

How the causal fields read:

- `EVIDENCE_GAP` / `BLOCKED` may carry an explicit `bic_granularity: null`
  with `introducer_sha: null`, or `fix_granularity: null` with no claimed fix or
  repair SHAs. Both require a substantive `remaining_gap` and `flip_condition`.
  Missing fields and invented enum values are not substitutes. These nulls describe
  unknown evidence; they neither admit a closed verdict nor prove an unpatched state.
- For an affirmatively supported `FALSE_POSITIVE`, use explicit nulls for
  `introducer_sha`, `bic_granularity`, `fix_sha` and `fix_granularity`.
  Here null means not applicable to the refuted/excluded allegation, not unfinished
  research. Do not claim a landing, decomposed members or repair SHAs, and omit
  `ai_on_bic`. Retain any inspected objects and markers in evidence without
  inventing vulnerability roles; use UNKNOWN for unassessed causal markers.
  A top-level PRESENT `ai_marker` or `fix_ai_marker` cannot bind to these null
  causal roles and is rejected; preserve its object, quote and scope in evidence.
  Keep the keyed official advisory, its matching alias state, affirmative
  `false_positive_ground` evidence and `flip_condition`. Missing evidence alone
  cannot use this exception or `NO_FIX_OBJECT`.
- `advisory_disposition` is the state of the advisory the case is keyed to (the
  first `advisory_ids` entry). `advisory_aliases` includes that keyed advisory
  and every consulted advisory established to concern this case, using entries
  with `id` and `state`. Keep the keyed entry as `UNKNOWN` when no matching
  source establishes its lifecycle; this entry does not assert a successful
  consultation. A dead
  alias next to a live keyed advisory stays visible with its own state. Preserve
  unlinked consultations and endpoint/body identity mismatches in evidence;
  neither a returned list item nor a shared repository establishes an alias.
  The state vocabulary is fixed: `ACTIVE`, `WITHDRAWN`, `REJECTED`,
  `DUPLICATE`, `UNKNOWN`. Normalize lifecycle evidence using the captured
  official source format, not a universal requirement for a literal `state` field.
  For GitHub REST global advisories (`/advisories/{ghsa_id}`, or the matching
  item of `/advisories`), require the matching `ghsa_id`, a valid non-null
  `published_at`, and a present `withdrawn_at`: explicit null maps to `ACTIVE`,
  a valid withdrawal timestamp to `WITHDRAWN`. These are date-time fields;
  absent, empty, boolean or malformed values are not substitutes. This format
  has no `state` property; null withdrawal alone does not establish publication.
  Repository advisories (`/repos/{owner}/{repo}/security-advisories/...`) use
  their explicit `state`: `published` maps to `ACTIVE`, `withdrawn` to
  `WITHDRAWN`. `draft`, `triage` and `closed` stay `UNKNOWN` in this vocabulary;
  retain the raw state and do not infer rejection, duplication or withdrawal.
  Repository timestamps permit null; do not impose the global publication
  rule on that format or infer its state from timestamps alone.
  Match the exact advisory identifier and endpoint; a shared CVE, repository
  or reference URL is not sufficient. Do not transfer a GHSA's state to a
  different keyed advisory. Preserve source fields, capture time, identifier
  and receipt/hash in evidence. Local OSV/GraphQL projections returned by a
  helper are not captured REST responses; omitted fields do not become null.
  Missing required evidence, malformed fields or unresolved identity/lifecycle
  conflicts use `UNKNOWN` pending resolution. Honor each format's permitted
  nulls, including global `identifiers` and `references`; null auxiliary fields
  alone do not invalidate otherwise supported lifecycle evidence. Different
  aliases may have different states; compare captures of the same identifier
  with their dates before treating a state change as a contradiction.
  Reviewed versus unreviewed is separate from lifecycle. A failed lookup is
  not an exclusion state, lifecycle does not prove the mechanism, and prose
  such as "open" or "live" is not a schema value.
- `landing_commit` is the merge/squash object that carried the BIC;
  `landing_basis` records how it was located (`PROSE_CARRIER_ON_DEFAULT`,
  `PROSE_CARRIER_NO_CONTENT_MATCH`, `INTRODUCER_ON_DEFAULT`, `NO_LANDING_NAMED`).
  `landing_commit` carries a sha only for a located carrier. When the
  introducer is itself on the default branch and no distinct carrier object
  exists, the basis is `INTRODUCER_ON_DEFAULT` and `landing_commit` stays
  **null**; the strict gate rejects an `ATOMIC` record that sets
  `landing_commit` equal to `introducer_sha`, because that re-asserts a
  landing the granularity denies.
  A `SQUASH_DECOMPOSED` record carries either the carrier or `landing_note`
  saying why none is resolvable, plus what a member-table read showed when the
  carrier is asserted rather than content-matched.
- `decomposition_probe` records the one bounded fetch run for an
  `AGGREGATE_MEMBERS_UNREACHABLE` BIC and what it returned; naming the
  unreachable object there and in `remaining_gap`, with `flip_condition` saying
  what would resolve it, is where that search ends.
- `fix_granularity`: `ATOMIC` (the fix object is the repair),
  `CARRIER_BUNDLE` (carrier-shaped; `atomic_repair_sha` names the repair,
  `fix_shas` the other landings of the same repair), `UNRESOLVED` (a fix object
  exists but cannot be read), or `NO_FIX_OBJECT` (the record substantiates an
  unpatched state, so no fix object is there to decompose).
- `residual_triage`: `{"decision": "NOT-RESIDUAL", "basis": "..."}` when the
  record's own evidence names a residual surface as a version range below the
  fix, or when the cue phrase is quoted carrier text (a commit subject or an
  evidence label), rather than an open surface. The basis says which sentence
  that is and why it closed; the strict gate's residual cue stops firing on that
  case.
- `fix_ai_marker.state` is `PRESENT` for an accepted AI marker (agent/bot
  author, AI co-author trailer, disclosure naming a tool), `ANNOTATION_ONLY`
  for a trailer with no AI in it, or `ABSENT`/`UNKNOWN`. A fix-side marker is
  informational: `PRESENT` off the BIC object requires the `ai_admissibility`
  sentence saying what it is and is not evidence of.
- For a PRESENT `ai_marker` or `fix_ai_marker`, record `sha`, `quote` (the exact
  identity/trailer/disclosure text), and `source` (`commit` or `first_party`).
  The local Git check accepts legacy `value` as the quote and defaults an omitted
  source to `commit`. A BIC marker's SHA must equal `introducer_sha`; a fix marker's
  SHA must name `fix_sha`, `direct_fix_sha`, `atomic_repair_sha` or a `fix_shas` member.
  A `first_party` marker also needs `url`, a retained source snapshot, and
  `ai_admissibility` binding the disclosure to the causal change. The Git check only
  checks the shape of this web evidence; the reducer must verify the saved source.
  Quoting a commit proves what it says, not the scope or causal relevance of AI use.
- `false_positive_ground`: `ADVISORY_REJECTED_ALIAS` requires the keyed advisory's
  disposition to be REJECTED, WITHDRAWN or DUPLICATE; `ADVISORY_MISATTRIBUTED` needs
  primary evidence of a wrong-product/source binding; `MECHANISM_REFUTED` needs
  affirmative evidence against the asserted vulnerable behavior. The legacy value
  `EVIDENCE_INSUFFICIENT` remains readable in historical records with that last
  meaning, but the current strict gate rejects it: new records use
  `MECHANISM_REFUTED`. Missing evidence or an unfinished probe is EVIDENCE_GAP,
  never a false-positive ground. Ordinary CVE/GHSA aliases are not rejected duplicates.
- Every TP row binds its AI evidence to the BIC itself (`ai_on_bic` true and
  `ai_marker PRESENT` with `sha` equal to `introducer_sha`). For `AI_ROOT_CAUSE`
  the BIC is the change that first introduces the vulnerable behavior; for
  `AI_CODE_FLAWED` and `AI_CAUSAL_CONTRIBUTOR` the BIC is the AI-attributed flawed
  or exposing change itself, and the earlier human origin is recorded in
  `flaw_origin` (its sha and what it established), not as `introducer_sha`.
  `candidate_set` lists the other objects considered; it never carries the row's
  attribution, and a marker there cannot stand in for one on the BIC.
  Rows landed before contract `2026-09-19.1` may still carry the older
  origin-as-BIC shape; the gate reads them as legacy, not as the convention.
- `identity_class` (`human`, `human-gh-noreply`, `named-no-email`,
  `ai_coder_bot`, `placeholder`, `object-missing`, `no-object`) and
  `disclosure_convention` (`CONVENTION_NOT_OBSERVED`,
  `CONVENTION_PRESENT_UNUSED`, `POLICY_MENTIONS_AI`, `NO_DATE`) are the two
  observations the `NOT_AI` threshold rests on besides the absent marker.
  These are the accepted spellings; the gate also reads the same classes in
  upper case with underscores. Only `human` and `human-gh-noreply` meet the
  named-identity threshold; a display name with no address or account binding
  (`named-no-email`) and every remaining class are step-4 `EVIDENCE_GAP`,
  not a `NOT_AI` verdict.

Verdict rule, by the change that carries the defect:

- `AI_ROOT_CAUSE` — the vulnerable behavior first enters the tree in an AI-attributed change.
- `AI_CODE_FLAWED` — the origin is human (or non-AI) and the AI-attributed change is itself
  the flawed code: AI-written logic, or an incomplete remediation or hardening that leaves
  the defect or creates the exposure the advisory describes. Its BIC is that AI-attributed
  change; the human origin is `flaw_origin`.
- A change is AI-attributed when its own object carries the marker: an agent or bot
  author, an AI co-author trailer, or a first-person disclosure in the message that the
  logic was written or generated with an AI tool (`LLM-assisted` under a human author
  is a marker, so a human-authored commit disclosing AI assistance for the introducing
  change is `AI_ROOT_CAUSE`, not `AI_CODE_FLAWED`). Author identity does not decide
  the class; the marker on the causal object does.
- `AI_CAUSAL_CONTRIBUTOR` — an AI-attributed change adds the causal exposure path of a
  human-origin defect, without being that origin or its repair.
- `NOT_AI` — the causal object has a recovered named human/organization identity,
  no AI marker, and a contemporaneous disclosure-convention check. An absent marker
  alone, an unresolved identity, or a human carrier of unattributed member code is insufficient.
- `FALSE_POSITIVE` — the advisory is rejected, withdrawn or a duplicate, or its
  own basis does not describe vulnerable code (`false_positive_ground`).
- `EVIDENCE_GAP` is the audit verdict for a missing decisive fact or upstream answer; it
lands as terminal `BLOCKED`, whose `remaining_gap` names the one object that would flip
it. Nothing is published from that row until a revision reads the object.

Introduction, new exposure and incomplete remediation are the three accepted reasons a case
may be a TP; none of them requires AI to have written the original defect.

## Reducer decisions (local coordination)

The [Adjudication protocol](ADJUDICATION-PROTOCOL.md) owns acceptance. New assignments
store its immutable decision object in a dedicated `decisions.json`, optionally
under a `reduction` key. Execution and dispatch state stay in the batch index,
which holds a pointer to the decision file. Do not mix `dispatch` or `allocation`
into frozen decisions. Legacy frozen layouts retain their original checks until
explicit migration. Decisions are not ledger or website data.
`auditors` freezes all N independent lane names before dispatch;
the supplied lanes must match that list. Every case binds each named input plus `accepted`.
All digests are SHA-256 of exact file bytes, including whitespace. Paths are relative
to the decision file, or absolute. Retain source copies; a URL alone is not a receipt.
The baseline envelope below uses legacy prose resolutions; newly adopted research-work
contracts extend it as specified in the next section.

```json
{
  "reduction": {
    "reducer": "reducer3",
    "auditors": ["auditor1", "auditor2", "auditor3"],
    "pins": {
      "manifest": {"path": "../batch.txt", "sha256": "<64 hex>"},
      "audit_protocol": {"path": "contract/AUDIT-PROTOCOL.md", "sha256": "<64 hex>"},
      "reducer_protocol": {"path": "contract/ADJUDICATION-PROTOCOL.md", "sha256": "<64 hex>"},
      "schema": {"path": "contract/DATA-SCHEMA.md", "sha256": "<64 hex>"},
      "brief": {"path": "contract/brief.md", "sha256": "<64 hex>"},
      "record_gate": {"path": "contract/audit_record_gates.py", "sha256": "<64 hex>"},
      "comparison": {"path": "contract/compare_slots.py", "sha256": "<64 hex>"},
      "reduction_gate": {"path": "contract/audit_reduction_gate.py", "sha256": "<64 hex>"}
    },
    "cases": {
      "alias-example": {
        "sha256": {"auditor1": "<64 hex>", "auditor2": "<64 hex>", "auditor3": "<64 hex>", "accepted": "<64 hex>"},
        "status": "ACCEPTED",
        "reviewed_dimensions": ["advisory", "mechanism", "bic", "ai", "fix", "versions", "residual"],
        "basis": "State the final causal chain and how counterevidence was resolved.",
        "resolutions": {
          "fix": "State all competing repair claims, the decisive primary observation and the final choice."
        },
        "evidence": [{"path": "evidence/alias-example.txt", "sha256": "<64 hex>"}]
      }
    }
  }
}
```

The `reducer_protocol` pin names the adjudication contract; reducer remains the role name.
`--lane NAME=PATH` is repeatable. Legacy `--a`/`--b` commands name lanes `a` and `b`.
This is a shape example, not an acceptable prewritten decision. Every differing dimension
across the auditor records and final synthesis needs its own nonempty resolution.
Generic `evidence` and `reasoning` differences belong to the `mechanism` review dimension;
this requires an explanation of differing observations, not automatic contradiction.
TP cases also need `bic`, `ai` and `fix` resolutions even when lanes agree; review signals require
`residual`, and invalid input records require `input_quality`. The reducer explains
whether each flag is substantive. Receipt files contain observations, commands/URLs,
repository/object, time and exit results; each reasoning claim points to the relevant
part. `reviewed_dimensions` records coverage, not evidence of correctness.

`BLOCKED` requires `next_question` and prevents an all-accepted gate result. Confirmed
unpatched research can be `ACCEPTED` with its qualified repair conclusion. Record
execution and publication status separately. Additional `pins` entries bind staging
payloads, reports and other deliverables. Preserve the full accepted research when
projecting it into the ledger; the gate does not test that projection or live revisions.

For frozen gate code, keep `audit_record_gates.py`, `compare_slots.py` and
`audit_reduction_gate.py` together and invoke that copy. The gate checks the hashes of
the code actually used. Historical batches retain their original contract; adoption of
this format must be explicit, not a retroactive claim that old runs followed it.

### Research-work contract

New batches adopting the current contract retain the sidecar introduced in
`2026-09-25.1`: set `reduction.research_contract` to
`causal-work-v1` and freeze the gate invocation with `--research-contract causal-work-v1`.
The option rejects an omitted or different declaration; older frozen batches retain
their existing contract. This is local coordination data, never ledger or site data.

Each decision has a `research` object with `advisory`, `mechanism`, `bic`, `ai`, `fix`
and `versions` entries. Auditors keep the same object in their owned research sidecar,
linked from the sealed report; adjudicators write their own synthesis in the decision.
The existing `basis`, `residual` resolution and per-dimension `missing_fact` describe
the remaining uncertainty. A single entry has this shape (not a prewritten finding):

```json
{
  "evidence_grade": "QUALIFIED_BOUNDARY",
  "work_state": "UNFINISHED",
  "finding": "State the supported causal conclusion, conditions and counterevidence.",
  "evidence": [{"path": "evidence/source.txt", "sha256": "<64 hex>"}],
  "missing_fact": "State the decisive fact still unknown.",
  "next_permitted_route": "original-member",
  "routes": [{
    "id": "original-member",
    "question": "Which parent/child change first introduced the relevant behavior?",
    "source": "upstream repository history",
    "evidence_type": "parent/child source comparison",
    "status": "PENDING"
  }]
}
```

`evidence_grade` is `BOUND`, `QUALIFIED_BOUNDARY` or `UNRESOLVED`. It describes the
supported conclusion, independently of work remaining. `BOUND` need not assert a
vulnerability or an existing fix: an affirmative refutation or the keyed advisory's
documented exclusion of further work can support a scoped conclusion. State that scope;
do not invent code findings for a rejected advisory or extend an absence claim.
A `BOUND` finding has no decisive `missing_fact`: represent it with JSON null, not an
empty string. Genuine remaining gaps use the other evidence grades and a named fact.

`work_state` is `UNFINISHED` while an identified, permitted, decisive investigation
remains, regardless of the grade or case verdict. `next_permitted_route` names a
`PENDING` or `FAILED` route. `COMPLETE` requires a null next route and no unfinished
route; a non-BOUND conclusion also needs a nonempty `missing_fact` and route history.
Completion is the researcher's claim about the recorded questions and evidence available
at that point, not proof that every possible source was discovered. Omitted or invalid
research objects are unassessed, never zero outstanding work.

A route is a question plus an authoritative source and evidence type. Alternate URLs
for the same observation are attempts within that route, not extra research coverage.
Choose routes for the facts they can distinguish; after a decisive answer, do not keep
searching merely to fill source categories. If a planned alternative becomes redundant,
explain its disposition in the supported finding and retain the prior plan in the attempt
history. Completed findings can have an empty route list when primary evidence already
binds them. Investigate a qualified boundary wherever a different available observation
could still change its conclusion.

Routes use `PENDING`, `FAILED`, or one of four terminal observations:

| Status | Meaning |
| --- | --- |
| `ANSWERED` | The source answered the specific question; a supported absence is an answer. |
| `UNAVAILABLE` | The specified evidence is unavailable, with its actual access/source result. |
| `EXHAUSTED` | The recorded, bounded source inquiry ended without answering the missing fact. |
| `PROHIBITED` | An applicable instruction prevents this specific inquiry; retain its authority and scope. |

Every non-PENDING route needs `observation` and `evidence` receipts. A crash, timeout,
rate limit or failed write is `FAILED`, not proof of source absence or exhaustion.
Resource and permission limits remain in force; report affected unfinished work and
continue other authorized questions. Receipts must substantiate the claimed outcome.
The gate checks the declared statuses and pinned bytes, not the truth of their interpretation.

Under this contract, each required `resolutions` entry is an object containing `claims`
(a nonempty account for every assigned lane), `observation`, `reasoning`, `conclusion`
and primary `evidence` receipts. Explain the shared premise when reports agree and why
it holds or fails. Changes made only by the adjudicator still need a resolution. Every
supplied resolution is checked, including optional ones. Existing TP and input-quality
obligations remain.

The reduction gate returns `research_work.worklist` from unfinished entries, including
qualified ones, and reports `evidence_boundaries` and `unassessed_cases` separately.
The list concerns declared research only. A zero-length list neither proves discovery
completeness nor changes `BLOCKED`, missing-lane, execution or publication status.
The leader reviews the choice of questions, counterevidence and terminal observations
before accepting the claimed boundary. Never use route counts as a quality score.

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
