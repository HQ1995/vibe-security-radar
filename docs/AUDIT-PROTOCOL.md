# Audit protocol — how a case gets judged

The standing rules for judging whether a vulnerability is AI-introduced.
These are the rules the pipeline enforces (see code pointers) plus the
judgement standards learned from the round-6 fine-grained BIC review.
Anyone (human, lane agent, long-running scanner) who judges a case must
follow this file. The data shapes are in `docs/DATA-SCHEMA.md`; file
ownership is in `docs/AGENT-OWNERSHIP.md`.

## 1. Order of work: vulnerability first, AI second

Never skip to attribution. For every candidate:

1. **Understand the vulnerability**: advisory identity (GHSA/CVE), the
   exact mechanism, the trigger path, the vulnerable code location, the
   fixed behavior. If the mechanism cannot be stated concretely, the case
   is not ready to judge — backfill `flaw_origin`/`bug_semantics` first.
2. **Find the minimal BIC**: the *smallest* commit that first wrote the
   vulnerable lines (see §3).
3. **Judge the AI role on that BIC** (see §2).
4. **Close the fix side**: the fix commit(s), or an explicit `unpatched`
   note with the advisory's status.

## 2. Contribution classes

| Class | Meaning | Requirement |
|---|---|---|
| `AI_DIRECT_ROOT` | AI-written code introduced the vulnerability; AI is the root cause | The vulnerable lines' first writer carries an AI signal (see §4) |
| `AI_INCOMPLETE_REMEDIATION` | AI wrote an incomplete fix that left the path open | Full `ir_chain`: original introducer → attempted remediation → residual bypass → final closure |
| `AI_NEW_SURFACE_CONTRIBUTOR` | AI added a new attack surface (new feature/route) that enabled the flaw | AI wrote the surface; the flaw mechanism lives on it |
| `AI_CODE_FLAWED` | AI wrote vulnerable code but is not the sole root cause | Pre-existing human enabler, or AI participation below line level (review-only), or human completed the exploit path |
| `NOT_AI` | No AI role | Evidence of human authorship on the vulnerable lines |

Deciding factors, in order: `site_scope` override → `AI_CODE_FLAWED`
status → `flaw_origin` text signals ("incomplete|missed|bypass
remained|residual" → incomplete-remediation class; "surface|reachable|
prerequisite" → new-surface class) → `AI_DIRECT_ROOT` default.

## 3. Minimal BIC

- A squash/merge/bundle commit is **not** a BIC. Decompose it to the
  PR constituents and pick the commit that first wrote the vulnerable
  lines. Record the decomposition in `decomposed_shas`.
- Verify first-writer: parent lacks the behavior (`git ls-tree`/`grep`),
  or `pickaxe`/`-S` shows no earlier writer.
- Blame to line level where possible.
- If the upstream history was force-pushed/rewritten and the commit is
  unrecoverable, state that in `remaining_gap`; do not substitute a
  different commit.

## 4. AI signal hierarchy (weakest → strongest)

1. Informal text signatures (`Made-with: Cursor`, `Generated with
   Claude Code` banner) — treat as signals only per the pipeline's
   pattern list; disclose the weakness in `remaining_gap`.
2. Project-level disclosure (README/CLAUDE.md says content was
   AI-written) — attribute at project level, not line level; disclose.
3. `Co-Authored-By: <AI tool>` trailer on the BIC.
4. Author/committer identity is the AI tool itself (e.g.
   `Claude Code Assistant <claude@anthropic.com>`, `kali-builder-agent`,
   a `did:key` non-human identity).

**Critical rule (round-6 lesson)**: a co-author trailer on a *squash*
commit is an aggregate of the whole PR. It does **not** prove the
vulnerable lines are AI-written. The signal must be on the minimal BIC
or on a constituent that touches the vulnerable file. If only the squash
carries the signal and the BIC does not, downgrade to `AI_CODE_FLAWED`
(or lower) and record the finding in `bic_analysis`.

## 5. Required evidence per case

- `verdict`, `reasoning` (why, not just what)
- `flaw_origin` + `bug_semantics`: concrete mechanism, no template words
  (`introduced_with_feature`, `ai`, `introducer` are forbidden)
- `ai_marker`: the actual signal text/location
- `introducer_sha` (minimal BIC), `fix_sha`/`direct_fix_sha` or
  explicit `unpatched`
- `decomposed_shas` when the BIC came from a squash
- `advisory_identity.member_ids`: **mandatory** — never publish an
  `ALIAS-*` case. Dig the real GHSA/CVE via: repo security-advisories,
  OSV commit query (`POST /v1/query {"commit": sha}`), OSV package
  query, NVD keyword search, then web search. Only if every channel
  fails may the case stay unpublished with a note.

## 6. Publication gates (enforced, not aspirational)

`scripts/publish_tp_ledger.py` refuses to publish when any of:

- duplicate official IDs — including **GHSA↔CVE same-entity pairs**
  (`scripts/ghsa-cve-map.json`); dedup must already exist at ledger level
  (`site_publication.publish=false`), not be done at publish time
- `published_at` missing **or not traceable to the advisory date table**
  — never substitute the introducer commit date; resolve the real
  advisory date (web search if the APIs miss it)
- `ir_chain` missing for `AI_INCOMPLETE_REMEDIATION` (or present for
  other classes)
- listing SHA vs evidence commit mismatch
- `code_evidence` (comparison hunks) missing, unless allowlisted for a
  verified fact (e.g. upstream force-pushed the commits)
- `vulnerable_release`/`fixed_release` missing, unless allowlisted for a
  verified fact (advisory publishes no version range)

Allowlist entries must state a concrete verified reason; allowlist-as-
filter is prohibited. `scripts/site_preflight_allowlist.json` and the
web tests mirror each other — keep them in sync.

## 7. Tools

| Step | Tool |
|---|---|
| Merge lane results (dedup gate included) | `scripts/merge_funnel_lane.py` |
| Backfill comparison hunks for unpublished TPs | `scripts/build_missing_code_evidence.py artifacts/funnel-account-*.jsonl` |
| Publish + gates | `scripts/publish_tp_ledger.py` |
| Preflight | `scripts/site_preflight.py` |
| Entity map | `scripts/ghsa-cve-map.json` |
