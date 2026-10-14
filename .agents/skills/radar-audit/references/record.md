# Audit record

Current research contract: `2026-10-14.1` (see the [audit protocol](protocol.md)). The base record
format originated in `2026-09-19.1`; the research-work sidecar was added in
`2026-09-25.1`; `impact` was added in `2026-10-14.1`. These dates do not migrate
older frozen batches. Every new record declares its `protocol_version`. Reject
duplicate JSON keys, including nested ones; later values must never silently replace
evidence.

One JSON record per case, kept in the batch's research directory; the accepted
synthesis lands in the ledger row's `causal_research` in the same shape. Required
fields beyond the verdict and its prose: `protocol_version`, `impact` (except for a
`FALSE_POSITIVE`), `advisory_disposition`,
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

- `impact` is the step-2 account, three substantive strings: `affected` (component,
  routes and affected revisions/versions), `prerequisites` (who can trigger it: network
  position, authentication, role, configuration or state) and `effect` (what they
  obtain). An unknown part says what is unknown and why. The strict gate requires it
  for records declaring `protocol_version` `2026-10-14.1` or later.
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

