# Batch 2 unresolved recovery: ranks 25–36

## Outcome

Completed the requested 12-row review without touching ranks 1–24 or ranks below 36. Recommendations are **0 RESOLVED_PASS, 9 RESOLVED_REJECT, 1 STILL_BLOCKED, and 2 STILL_UNKNOWN**. There are no silent drops. No new publication-grade positive case emerged.

## Scope and snapshot boundary

- Task started at 2026-08-12T12:47:44-04:00; terminal time is recorded in `result.json`.
- Sole ledger input: frozen `autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl`.
- Frozen input SHA-256: `5167b86efb2d6e3d218c41da120c7302f99049b9c588e8fd00896051d50355ca`.
- Owned snapshot copy: `snapshot/unresolved-inventory.jsonl`, same hash.
- Exact ranks 25–36 slice: `snapshot/ranks-25-36.jsonl`, 12 rows, SHA-256 `df89caa71095f35f5015cff159591df4ee65d56412895d020daf7fde79886404`.
- Workspace boundary: branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`; NUL-delimited porcelain status hash at start and at 12:57:57 was `96f440a130e4983e79da19d7d15014920ca649544e5c3905c327073d8412df10`.
- Repository object boundaries are in `snapshot/source-snapshot.json`. Shared clones were read-only; missing clones live only under this output directory.
- Primary web sources were read 2026-08-12 12:49–12:59 EDT. Exact GHSA/repository URLs and immutable commit IDs are in the ledger. Page bodies were not treated as frozen byte inputs; commit IDs, tag targets, and the frozen ledger are the reproducible evidence anchors.

## Decision rule

`RESOLVED_PASS` requires one chain with an exact candidate, explicit AI authorship/provenance for that candidate, same security mechanism, first-party advisory identity, exact fix, and a released tag containing the fix. `RESOLVED_REJECT` means the investigated AI candidate(s) are demonstrably post-fix, path-disjoint, mechanism-disjoint, or the exact vulnerable origin predates them. `STILL_UNKNOWN` preserves exact lineages whose AI causality is not proved. `STILL_BLOCKED` preserves rows without a product-owned exact fix/release identity.

Repository topic, product purpose, AI-tool instruction files, ancestry alone, tests, routing matches, and source recovery were not treated as causal proof.

## Recommendation ledger

| Rank | Component / identity | Recommendation | Exact row-level evidence |
|---:|---|---|---|
| 25 | DedeCMS / CVE-2026-19353 | STILL_BLOCKED | GHSA-qg5x-jc32-6g34 is unreviewed with unknown source/fix. The product repo snapshot `cc735a4f` still has `_4_Setup`; its install history ends in 2021 and cannot identify the advisory's 5.7.118 build or released fix. The only advisory repository reference is a researcher-owned issue. |
| 26 | libexpat / CVE-2026-72522 | RESOLVED_REJECT | First-party PR #1296 merged exact fix `8886826d`; tag `R_2_8_3` contains it. The vulnerable `0xF8` mask is present by `d248bbd94` (2019). A Qwen-labeled downstream packaging commit is post-fix and outside upstream lineage. |
| 27 | MaxKB / CVE-2026-42335 | RESOLVED_REJECT | Product advisory GHSA-r8hf-mwwr-hxgc names v2.8.1. Target-path origin `8c3caa27` → fix `c9043db1` → v2.8.1 all pass ancestry checks. No explicit AI attribution occurs on the vulnerable target path. |
| 28 | Absinthe / CVE-2026-43967 | RESOLVED_REJECT | Product advisory identifies introducer `0b46e3b` (2016), exact fix `223600c5`, and 1.10.2. Explicit Claude commits touch subscription, descriptions, or incremental delivery, not `UniqueFragmentNames`. |
| 29 | Caddy Defender / CVE-2026-46415 | RESOLVED_REJECT | Middleware origin `c9e87f89` → fix `5b6e94e4` → v0.10.1. Copilot commits `cb3bed3` and `2888b2b` touch tarpit/Azure range code, not trusted-proxy client IP selection. |
| 30 | qui / CVE-2026-30924 | RESOLVED_REJECT | Credentialed-CORS origin `6c7b2dc0` → fix `424f7a0d` → v1.15.0. Copilot UI-progress and Claude CI-workflow commits do not touch the mechanism. |
| 31 | SentencePiece / CVE-2026-1260 | RESOLVED_REJECT | Target construction traces to `c950219a` (2018); exact fix `d856b67f` passes string lengths to Darts and is contained by v0.2.1. No target-line AI attribution exists. |
| 32 | F5-TTS / CVE-2026-43624 | RESOLVED_REJECT | Finetune handler exists from `8ed1beac` (2024); fix content `25dc4e86`, merge `2f53ded6`, tag 1.1.21. Claude commit `6768b1b` only changes W&B/Hydra training configuration. |
| 33 | Network-AI / GHSA-6x2m-p4xp-wg22 | STILL_UNKNOWN | Same-mechanism origin `709f3d09` → fix `a59c13a1` → v5.12.2 is exact. The mixed origin also updates AI-tool instruction files, but it has no explicit generated-by/model/co-author evidence; tooling adjacency is not causality. |
| 34 | listmonk / CVE-2026-34584 | RESOLVED_REJECT | Product advisory combines multiple permission hotpaths and names fix `347f5976`; v6.1.0 contains it. No explicit AI attribution appears on fixed paths before it. Claude commit `84a9a12` is later and fixes ZIP slip, a different mechanism. |
| 35 | tookie-osint / CVE-2026-42866 | RESOLVED_REJECT | Writer origin `dd17d879` → exact sanitizer fix `38054f97` → v4.1fix. Later `[codex]` commit `67003e7` only changes `brib.py`, after containment. |
| 36 | Network-AI / CVE-2026-46701 | STILL_UNKNOWN | Mechanism roots `8469edbe` (SSE server), `4ebb5050` (wildcard CORS), and `b23aedbe` (empty-default bearer auth) all precede exact fix `dc504811`, contained by v5.4.5. No target-path commit has explicit model/co-author provenance. |

The machine-readable 12-row version, including full hashes and first-party URLs, is `recommendation-ledger.jsonl`.

## Negative and unknown controls

- No row meets the explicit-AI plus same-mechanism requirement; therefore the PASS count is zero rather than inferred from repository AI adjacency.
- Ranks 28–32, 34, and 35 retain explicit AI commits as negative controls instead of silently deleting them; each is later or mechanism/path-disjoint.
- Rank 26 retains the downstream `Generated-By: qwen3.6-35b` packaging event as a negative control because it occurs after upstream containment.
- Ranks 33 and 36 remain UNKNOWN because exact code lineage and release containment do not answer AI authorship.
- Rank 25 remains BLOCKED because neither the unreviewed advisory nor the available product history supplies exact fix and release lineage.
- Unauthenticated GitHub Advisory API calls returned HTTP 403. This was not bypassed with credentials; public first-party advisory/repository pages and Git objects were used instead.
- No builds, tests, PoCs, runtime reproductions, or full-corpus reruns were performed. Their absence does not weaken the narrow ancestry rejection, but runtime exploitability was not revalidated.

## Exact commands and sources

`commands.md` records the exact clone, pickaxe, attribution scan, blame, ancestry, hashing, and validation commands. Every web source is an exact URL in `recommendation-ledger.jsonl`; the principal identities are the product-owned GHSAs for MaxKB, Absinthe, Caddy Defender, qui, both Network-AI rows, listmonk, and tookie-osint; the libexpat PR; and the first-party SentencePiece/F5-TTS commits and releases.

## Claim boundary

This is a recommendation ledger for the frozen unresolved inventory only. It supports rejecting nine candidate classes from an AI-caused-vulnerability publication set, preserving one blocked and two unknown classes, and making **no positive causal claim**. It does not establish vulnerability exploitability independently, author intent, model use where commits lack explicit provenance, or completeness outside ranks 25–36. Exact release ancestry proves containment lineage, not AI causality.
