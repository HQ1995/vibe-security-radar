# GHSA 200+ delta-even batch2

**Status: COMPLETE for the assigned 80 IDs. 0 PASS proposals.**

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.

Worker PASS is a proposal, never admission. This lane proposes no admissions.

### Contract revision (patch-delta)

`AI_INCOMPLETE_REMEDIATION` but-for now uses patch-delta: rollback may reopen a broader old vulnerability. A rem row counts only if an AI security attempt adds or rewrites a boundary, a released residual bypass in that boundary is first-party-advisory covered, and a later same-mechanism closure directly amends it. Unrelated untouched sibling holes do not count. Origin and contributor but-for are unchanged.

This lane has no `AI_INCOMPLETE_REMEDIATION` rows and no rem PASS. Four AI-adjacent hits were screened against patch-delta and fail to qualify (sibling or non-authorship). Their origin/contributor but-for is unchanged. `GHSA-45PQ-889G-FCGH` names incomplete path validation but is human-origin, so origin but-for stays.

Delta-even artifacts were not modified. Sibling fresh/current-delta/remediation conclusions were not read as evidence. New clones live only under `/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2`. Official reviewed JSON was read from the existing delta-even advisory-database; that tree was not moved.

## Assignment freeze

Source: `autoresearch/herdr-260813-ghsa200-delta-even/routing_manifest.jsonl` rows with `final_route=SCREENED_NO_PLAUSIBLE_AI`, sorted by uppercase `ghsa_id`, first 80.

Assertions (all true):

- 80 unique IDs
- all in the even partition
- 0 overlap with the 212 leader declared IDs
- 0 overlap with delta-even deep-reviewed IDs
- all 80 are in the accepted 731-ID window

This batch exists to test the first-pass router's unreferenced-history blind spot: official closer AI scan is not origin proof.

## Terminal outcomes

| Verdict | Count | Meaning |
|---------|------:|---------|
| PASS | 0 | No seven-gate admission |
| REJECT | 46 | Introducing hunk resolved; relevant origin/contribution is human/non-AI |
| UNKNOWN | 16 | History not fully resolved after a first-party closer walk |
| BLOCKED | 18 | No usable official fix SHA in the batch2 clone |
| **Total** | **80** | Exactly 80 terminal seven-gate rows |

## How origin was tested

For each assigned ID:

1. Read the official github-reviewed JSON (identity, aliases, commit refs, affected range).
2. Clone the named repository under the batch2 cache (`--filter=blob:none`; large remaining repos used `--no-checkout`).
3. Walk beyond the official closer: parent-blame of deleted hunks and `git log -S` on distinctive tokens from the fix.
4. Scan candidate origin commits with `cve_analyzer.detect_ai_signals`.

REJECT required a resolved introducing-hunk set with no AI authorship marker. UNKNOWN/BLOCKED were used when that walk failed.

## AI-detector hits (all REJECT after inspection)

**GHSA-434R-7C99-HWF3** (HKUDS/nanobot). Hit is `unknown_ai` on the phrase `LLM-generated` in `5dc96505`, which describes model-produced tool-call URLs. Not a commit trailer. Closer `545294c6` is human.

**GHSA-4CWX-7WF7-3272** (nodejs/undici). Claude trailers on `de01babc` and `e1cc0d43` are later cache-revalidation fixes. Official closer `4fe5bc5f` (Matteo Collina) repairs empty qualified `private`/`no-cache` parsing. Adjacent-file blame, not this mechanism's origin.

**GHSA-55H5-XMCQ-C37V** (py-pdf/pypdf). Claude `4d8ebcec` fixed stale object-stream cache. This advisory's closer `b5fc5aa7` speeds broken-xref recovery. Same `_reader.py`, different mechanism.

**GHSA-6VH2-WG4H-4VWJ** (FlowiseAI/Flowise). Claude `aee37e16` is ambient webhooks. The ungated `...overrideConfig` spread was introduced by Henry Heng / Rafael Reis in 2024-2025 with no AI trailer. Closer `23b997ee` removes that human spread.

## Recovered BLOCKED closer (still not PASS)

**GHSA-55Q2-FJHQ-7XH7** (DOMPurify). Official short SHA was missing on the default branch. PR 1557 merge `2c8ca25e` and the IN_PLACE lineage are Cure53, no AI trailer. REJECT.

**GHSA-43PX-GPWC-Q84V** and **GHSA-6H35-9P2W-3J3R**. PR closers are human `3em0`. Introducing hunks were not isolated. UNKNOWN.

## What this lane will not claim

- It does not admit any new GHSA.
- It does not claim the first-pass router was complete. 16 UNKNOWN and 18 BLOCKED are the measured remainder of that blind spot on this 80-ID slice.
- It does not own later SCREENED_NO_PLAUSIBLE_AI IDs after these 80.

## Artifacts

- `assignment_manifest.json` / `assignment_ids.txt` -- frozen 80
- `result.json`, `cases.jsonl` (80 rows), `report.md`, `replay.txt`, `source_hashes.json`
- `origin_scan.jsonl` -- raw introducing-hunk walk
- `evidence/*.official-github-reviewed.json`
