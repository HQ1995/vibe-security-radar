 # Research data contract
 
 Machine-readable sources for the AI-vulnerability catalog. The canonical
 store is Neon Postgres; artifacts/funnel-account-*.jsonl is its deterministic
 GitHub recovery export. Research lane scratch under research/ is LOCAL-ONLY
 (git-ignored, never committed) and is not a data source for publication - the
 publisher reads the Neon ledger (DB-first) and falls back to the committed
 jsonl backup when Neon is unavailable.
 
 ## Layers
 
 | Layer | File / source | Rows | Role |
 |------|----------------|------|------|
 | Working ledger | Neon Postgres; GitHub export `artifacts/funnel-account-*.jsonl` | 29,593 | Canonical store of every candidate case; status state machine |
 | Published catalog | `web/src/generated/research-data.json` | `snapshot.case_count` | Published TPs with confirmed/qualified/provisional status |
 | Chain index | Neon `ledger_display` (`ir_chain` rows) | 51 | Incomplete-remediation causal chains with `evidence_paths` (source now DB-first) |
 | Origin re-review overlay | Neon `ledger_display` (`origin_rerereview` rows) | 4 | Full-history corrections that supersede missing/shallow original-commit fields |
 
 ## Ledger row (`artifacts/funnel-account-*.jsonl`)
 
 One JSON object per line, keyed by `class_id` (alias of a deduped advisory
 cluster). Canonical store is Neon Postgres. The GitHub JSONL is a
 deterministic recovery export written only by the leader via
 `scripts/ledger_store.py export`. Never edit the JSONL directly.
 
 - `class_id` — stable cluster key (`alias-<40hex>`)
 - `status` — state machine: `UNANALYZED` → `PARTIALLY_ANALYZED` →
   terminal `AI_ROOT_CAUSE` | `AI_CODE_FLAWED` | `NOT_AI` | `BLOCKED` |
   `FALSE_POSITIVE`
 - `dossier_best` / `ledger_best` — final verdict payloads (may be null for
   older terminal rows; process fields below then carry the evidence)
 - `repo`, `advisories` — repository identity, advisory count
 - Process fields (`notai_*`, `blocked*`, `causal_research`, ...) — lane
   working records; naming is free-form, treat as evidence notes
 
 TP classes: `AI_ROOT_CAUSE`, `AI_CODE_FLAWED`. Closed: `NOT_AI`, `BLOCKED`,
 `FALSE_POSITIVE`. Rebuild the catalog with
 `python3 scripts/publish_tp_ledger.py` after a successful export.
 
 Unpatched findings carry an explicit `unpatched` record (not an empty `fix_sha`):
 `{"confirmed": true, "reason": <why no fix exists>, "potential_fix": {"approach":
 <concrete remediation>, "rationale": <why it closes the sink>, "reference_commit":
 <upstream fix commit or null>, "reference_url": <issue/PR or null>}}`. `fix_sha`/
 `direct_fix_sha` stay null; the finding closes only when the record supplies both a
 verified no-fix reason and a concrete potential fix.
 
 ## Published case (`web/src/generated/research-data.json` → `cases[]`)
 
 Regenerate with `python3 scripts/publish_tp_ledger.py` (see
 `docs/AGENT-OWNERSHIP.md` for the single-writer contract).
 
 Identity:
 
 - `case_id` — public ID (GHSA/CVE); `aliases` — all known IDs
 - `class_id` — ledger cluster key; `repository` + `repository_metadata`
 
 Path (the case's causal journey):
 
 - `contribution_class` — one of `AI_DIRECT_ROOT`, `AI_NEW_SURFACE_CONTRIBUTOR`,
   `AI_INCOMPLETE_REMEDIATION`, `AI_CODE_FLAWED`, `AI_CAUSAL_CONTRIBUTOR`
   (live counts are in `snapshot`, not this document)
 - `candidate_set` — AI-authored commits that introduced/exposed the flaw
 - `carrier_set` — commits that carried the flawed code across merges
 - `minimum_fix_set` — the security fix commits that close the path; empty when
   `unpatched.confirmed` is true
 - `mechanism` + `mechanism_key` — vulnerable mechanism description
 - `scope_statement` — what the case claims and does not claim
 - `cause_category`, `cwes`, `severity`, `tier`, `gates`
 - `unpatched` — null, or
   `{"confirmed": true, "reason": ..., "potential_fix": {"approach", "rationale",
   "reference_commit", "reference_url"}}` when no upstream fix exists
 
 Causal chain (`ir_chain`, present for every `AI_INCOMPLETE_REMEDIATION` case,
 absent for other classes — they need no remediation chain):
 
 - `original_advisory_ids`, `original_sha`, `original_author_kind/name`
 - `unresolved_reason` — a non-empty reason is required when `original_sha` is
   unavailable; records the exact history/evidence boundary instead of guessing
   an introducer
 - `original_mechanism`, `original_sink`
 - `attempted_remediation` — the incomplete fix (candidate shas)
 - `residual_bypass` — how the path stayed open
 - `final_closure` — the fix that closed it
 
 Code evidence (`code_evidence`, present for published cases):
 
 - `candidate_url`, `fix_url`, `advisory_url` — primary sources
 - `candidate_patch_sha256` — content hash of the AI change
 - `candidate_hunks`, `fix_hunks`, `comparison_hunks` — line-level diffs
 - each hunk's `role` is `candidate` or `fix` when it belongs to that commit;
   `before_after` identifies an editor/publisher-composed before/after comparison
 - hunk `annotation` may be empty; the UI then shows one clearly labeled case-level
   context per role, but must not present it as a hunk-specific causal explanation
 - `unavailable_reason` is required when no code hunk can be published and explains
   the exact public-history boundary to the reader
 - `ai_marker`, `fix_marker` — authorship signals on each side
 - unpatched findings may omit `fix_hunks` / `fix_url`; they still need candidate hunks
 - curated code evidence belongs on the canonical ledger row as `code_evidence`;
   the publisher uses legacy generated/cache evidence only when that field is absent
 - `annotation_mode: "hunk_specific"` opts a canonical record into the strict
   annotation gate: every displayed hunk needs distinct reader prose, and every
   string in `required_anchors.candidate` / `.fix` must occur in that role's hunks
 
 Publication:
 
 - fields present on the canonical ledger row take precedence over legacy site
   overrides and cached generated data, including explicit `null` / empty sets
 - `publication_status` — `confirmed` | `qualified` | `provisional`
 - `publication_issues` — missing-evidence codes; must be empty for `confirmed`
 - `advisory_url` — canonical GHSA or CVE URL
 - `published_at`, `fixed_release`, `vulnerable_release`
 - `ai_provenance`, `fix_authorship`, `research_status`, `ledger_status`
 
 Snapshot census: `ledger_total` = `ledger_reviewed` + `ledger_in_progress` +
 `ledger_not_started`; `case_count` = `confirmed_cases` + `qualified_cases` +
 `provisional_cases`. Incomplete evidence is never labeled `confirmed`.
 
 ## Incremental scanning
 
 - New TPs: rows in the ledger whose `status` flips to `AI_ROOT_CAUSE` /
   `AI_CODE_FLAWED`; each release batch appends to `research-data.json`
   (see `snapshot.case_count` / `snapshot.generated_at`).
 - Full chains: `ir_chain` rows in Neon `ledger_display` carry `evidence_paths`
   pointing into local-only research lane artifacts for deep verification.
 - Inputs that rebuild the catalog: the Neon ledger (DB-first), its committed
   jsonl backup, `scripts/generated-code-evidence.json`, `scripts/*adjudications*.json`,
   `scripts/tp_publication_overrides.json`.
