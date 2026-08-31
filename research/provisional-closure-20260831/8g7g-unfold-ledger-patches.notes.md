# GHSA-8G7G / GHSA-56C3 atomic ledger patch notes

Status: draft for leader review. The patch has **not** been applied to Neon,
the recovery export, the publisher, or the generated site.

## Live optimistic-lock basis

Both complete rows were read from live Neon with `scripts/ledger_store.py get`
immediately before the JSONL was created and again during validation:

| Class | Expected revision | Live change set | Preserved `advisory_ids` |
|---|---:|---|---|
| `alias-c5a7e76e9787edf4ea076555` | `1` | `bootstrap-df09d361-e566-4dc5-908a-db1b682c2e8a` | `["CVE-2026-42449","GHSA-56c3-vfp2-5qqj"]` |
| `alias-f8d8e53edbeacc7b689a133b` | `1` | `bootstrap-df09d361-e566-4dc5-908a-db1b682c2e8a` | `["GHSA-8g7g-hmwm-6rv2"]` |

`scripts/ledger_store.py apply` locks and validates every JSONL row within one
database transaction. Keeping these two rows in one patch file therefore gives
the required atomic un-fold: a revision conflict or validation failure on either
row aborts the transaction. Do not split or partially apply this file.

## Row intent

### c5a7 -> GHSA-56C3 / CVE-2026-42449

- Restores canonical identity `GHSA-56C3-VFP2-5QQJ`, contribution class
  `AI_INCOMPLETE_REMEDIATION`, candidate `d9d847f230923d96e0857ccecf3a4dedcc9b0096`,
  empty carrier set, and closing fix
  `9639f757853149f0cb16663cc8b6b6468f27a25f`.
- Removes the live row's mixed three-advisory `squash_audit`, its associated
  verdict/decomposition flags, and the ambiguous legacy atomic-BIC flag. No
  GHSA-8G7G path-interpolation evidence remains on this row.
- Adds the resolved remediation chain from original GHSA-4GGG/CVE-2026-39974
  AI commit `424f8ae1ff1b840a2646b84d594e4f6057128dff`, through the IPv4-only
  attempted remediation, to the IPv6-complete final fix.
- Sets `ledger_best=CAUSAL_CHAIN_CLOSED` and stores canonical code evidence on
  the row itself: one candidate hunk and one fix hunk from
  `src/utils/ssrf-protection.ts`, distinct reader annotations, exact commit
  URLs, selected-hunk hashes, and candidate/fix patch-file witnesses. The
  publisher therefore cannot fall back to the old GHSA-8G7G cache for this row.
- The seven top-level `PASS` gates come from
  `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:505`, whose
  case identity, candidate, empty carrier set, fix, and contribution class all
  match this restored row. They are not inherited from GHSA-8G7G.

### f8d8 -> GHSA-8G7G

- Restores publication of canonical identity `GHSA-8G7G-HMWM-6RV2` as
  `AI_DIRECT_ROOT`, candidate `74f05e937fa7d94babe3507510caa17ce17a698c`,
  empty carrier set, and direct fix
  `1cfe9c6bddb4b1634e6e23323c18ea35fd196999`.
- Replaces the false `folded_into` / `kept_class_id` publication binding. The
  claim is restricted to advisory issue (1), raw n8n API path segments; the
  redirect-SSRF and telemetry siblings remain excluded.
- Sets `ledger_best=AI_ROOT_CAUSE` and stores canonical code evidence on the
  row itself: two candidate hunks showing raw workflow/execution/credential
  interpolation and two fix hunks showing caller replacement plus the bounded
  encoding helper. Each hunk has a distinct annotation, and both roles carry
  exact commit URLs, selected-hunk hashes, and patch-file witnesses.
- The seven top-level `PASS` gates come from the independent check at
  `research/provisional-closure-20260831/final-gap-8g7g.md:53-71`.

`assessment_ids` is empty on both lines because the Markdown re-audit and the
historical JSONL evidence are not registered Neon assessments.

## Publication boundary

This file is an atomic **ledger-only** patch. Publication must remain on HOLD
until the leader also moves the 74f05e93/1cfe9c6b override from c5a7 to f8d8,
removes that stale override from c5a7, rebuilds the catalog, and verifies
exactly one case for each GHSA with no cross-aliasing. Canonical evidence is
already complete in these two DB rows; publisher, web, and database changes
remain intentionally outside this artifact.

## Validation

- Physical JSONL: 2 lines, 2 unique class IDs, 22,818 bytes.
- SHA-256: `3981903e3feec0faeedf55787a7f9a8ad3678e5252520f547d1e6467c8349dd4`.
- Every physical line passed `json.loads` and has exactly
  `{expected_revision,row,assessment_ids}`.
- Both expected revisions and both advisory-ID arrays matched fresh live
  `ledger_store.py get` results.
- Both full rows passed `ledger_store.validate_update()` against their live
  predecessors.
- Publisher identity collection resolves only 56C3/CVE-2026-42449 for c5a7
  and only 8G7G for f8d8; contribution classes resolve respectively to
  `AI_INCOMPLETE_REMEDIATION` and `AI_DIRECT_ROOT`.
- The c5a7 remediation chain passed `site_preflight.ir_chain_errors()` with no
  errors.
- All six selected hunks were checked as ordered subsequences of their exact
  local Git commit patches. Both patch-file witness sets were checked against
  `git diff-tree`; all four stored hunk hashes were recomputed successfully.
- All displayed annotations pass the site's public-prose check, required
  anchors are present, and both rows have empty publisher
  `publication_issues` under their canonical evidence.
- No apply/finalize command, database mutation, publisher run, generated-data
  write, or commit was performed.
