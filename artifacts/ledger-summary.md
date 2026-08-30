# Vibe Security Radar - canonical research ledger summary

The JSONL ledger is the source of truth. Refreshed 2026-08-26 after appending 5,469 leftover (0%-gate HAS_AI / keep_config) classes as UNANALYZED. Unique confirmed TPs unchanged at 234. Previous refresh: 2026-08-26 leftover intake; before that, window extension (+263 UNANALYZED) and round7 causal wave.

## Canonical status

Counts below treat `site_publication.publish: false` TP rows as folded duplicates, not extra findings.

| Status | Classes | Meaning |
|---|---:|---|
| AI_ROOT_CAUSE | 189 | Unique official IDs where AI code introduced or enabled the vulnerability. |
| AI_CODE_FLAWED | 59 | Unique official IDs where AI-written code was flawed. |
| FOLDED_DUPLICATE_TP | 7 | Extra class rows for the same GHSA as another TP; kept in the book, not extra TPs. |
| NOT_AI | 1172 | AI attribution is resolved as not AI-caused; remediation and history are tracked separately below. |
| PARTIALLY_ANALYZED | 6162 | Some evidence exists, but the complete causal chain is not closed. |
| BLOCKED | 31 | A required implementation, fix, ownership, or history boundary is unavailable. |
| UNANALYZED | 21980 | No individual causal research has been completed. |
| Total | 29593 | One row per class_id. Unique confirmed TPs: 234. |

## Leftover intake as UNANALYZED - 2026-08-26

Live 0% leftover was 28,691 product-source classes. 22,875 were already on the book (`class_id` match). The stable remainder — HAS_AI or keep_config, hash-proven, no advisory-ID collision with an existing row — was appended as UNANALYZED. Existing statuses were not touched. 0% droppable rows were not added.

| Filter | Count | Ledger action |
|---|---:|---|
| Leftover already on the book | 22,875 | Untouched |
| HAS_AI / keep_config, new `class_id`, new IDs | **5,469** (5,032 HAS_AI / 437 keep_config; 1,063 reviewed / 3,031 unreviewed / 1,375 NVD-only) | Appended as UNANALYZED |
| Same advisory already booked under another `class_id` | 90 | Skipped (GHSA twins) |
| Clone/scan failure (unknown) | 257 | Left off the book |
| Unscanned (snapd / wpf / logstash / apm-server / kubesphere) | 9 | Already on the book; still unscanned |

After intake: leftover 28,691; on the book by `class_id` 28,344; off the book 347 (257 unknown + 90 twins). Merge: `scripts/merge_funnel_lane.py` (`created: 5469, updated: 0`). Lane: `artifacts/leftover-unanalyzed-lane-20260826.jsonl`. Report: `artifacts/leftover-unanalyzed-merge-report-20260826.json`. Backup: `artifacts/funnel-account-20260817.jsonl.bak-leftover-unanalyzed-20260826`.

## Advisory identity recovery - 2026-08-26 (from-source rebuild merged + user fill; 24,124/24,124 hash-proven)

The funnel ledger's `advisory_ids` were recovered for every resolvable row from the from-source rebuild in `.ai-slop/state/refresh-20260826/` (125,928 upstream clusters, 110,054 GHSA records, 94,119 NVD records; generator `scripts/recover_advisory_ids_20260826.py`; lane + pins + report in `artifacts/advisory-recover-report-20260826.json`). Merge: `scripts/merge_funnel_lane.py` (`updated: 3004, created: 0`); report: `artifacts/advisory-lane-merge-report-20260826.json`.

- Proof standard: a row is hash-proven iff `sha256(“\n”.join(sorted(census-case members)) + “\n”)[:24] == class_id suffix` (census-case = `GHSA-` + lowercase body, rest UPPERCASE). No inference pins were written; only census-map verbatim, cluster membership, or 96-bit hash matches.
- EVIDENCE_GAP closure: 0 of 202 EVIDENCE_GAP-flagged no-ID rows remain without IDs. This merge pinned 202 (its entire null-source overlap with EVIDENCE_GAP rows); the 5 round7 identity-pinning failures (openclaw qG 1342-pool, mytube 4, fastgpt 23, ech0 22, coolify qJ 41) were already hash-pinned by the window-extend lane (`hash_pin_20260826`) and are hash-proven.
- Result: 21,233 → **24,124** rows carry `advisory_ids`; all 24,124 pass the hash formula (248/248 TP rows). 2,890 previously-empty rows recovered (`hash_pin_aliasset_20260826` 2,503 / `hash_pin_k1_20260826` 383 / `hash_pin_repopool_20260826` 4); 114 pre-ID'd rows re-pinned over values that never hashed (`subset_of_existing` 51 over research_block/repo_cohort_exact/hash_pin_20260826/census_alias_map values, `hash_pin_aliasset_20260826` 54, `hash_pin_k1_20260826` 9); the final 1 row filled by the user (`manual_fill`).
- Former honest-empty row resolved (2026-08-26, user-supplied): `alias-bd1066d6c07a95b9fb97e4a2` (meshtastic/firmware, UNANALYZED, `advisories: 1`) filled as `CVE-2024-47065` with `advisory_aliases` `GHSA-4hjx-54gf-2jh7`, source `hash_pin_k1_20260826`. Verified: `H("CVE-2024-47065\n") == bd1066d6c07a95b9fb97e4a2` (member set is the single CVE, not CVE+GHSA — `H([CVE,GHSA])` does not match, so the fill form is exactly right). External confirmation: GitHub **repository-level** advisory API `repos/meshtastic/firmware/security-advisories` pairs `GHSA-4hjx-54gf-2jh7 ↔ CVE-2024-47065` ("Traceroute_APP responses are not rate-limited", <2.5.1, CVSS 6.5). This is a repo-level advisory from 2024, absent from the global advisory-database clone, OSV, and the NVD 2025/2026 pool — the reason the local exhaustive sweep (GHSA database, NVD feeds, alias sets of all 7 meshtastic CVEs, cohort pools) found no candidate set. A structural gap, not a sweep miss. Diff vs pre-merge backup: only this one row gained 3 fields (additions only); row count, order, and status histogram unchanged.

Backup: `artifacts/funnel-account-20260817.jsonl.bak-advisory-lane-merge-20260826` (pre-merge). Earlier chain: `.bak-advisory-recover-20260826`, `.bak-advisory-correct-20260826`, `.bak-advisory-backfill-20260826`, `.bak-round7-correction2-20260826`.


## Window extension to 2026-08-26

Sources pulled 2026-08-26: GitHub `advisory-database` HEAD `c02e9c72` (commit date 2026-08-26 15:28 UTC), NVD 2025/2026 feeds, GitHub Advisories API `published>=2026-08-17`. Local clones (574) rescanned with Source v3 `author_identity-v3` + `explicit_attribution-v5` (`scripts` output under `.ai-slop/state/refresh-20260826/`).

| Filter | Count | Ledger action |
|---|---:|---|
| GitHub advisories in 2026-08-17 .. 2026-08-26 | 4173 (290 reviewed / 3883 unreviewed) | — |
| NVD 2026 published in window (non-REJECTED) | 3764 | — |
| Alias clusters overlapping an existing class | 67 (42 case-fold only; 25 new GHSA twins) | Identity backfill on the 25; status untouched |
| New github-reviewed + first-party repo, disjoint from the book | **263** | Appended as UNANALYZED |
| Unreviewed / NVD-only with a weak GitHub URL | 4379 | **Not** added (would flood the book; original 23,861 was repo-narrowed reviewed-quality) |
| Local clone AI commits (since 2025-05-01, new matcher) | 126,203 across 475/574 repos | Inventory only, not TPs |
| GPT-display-name + Codex GitHub noreply recoveries | 0 | Matcher v3 still finds none on this clone pool |
| `Made-with: Cursor` exclusive (no other module) | 1,926 commits | Inventory; do not auto-flip NOT_AI/TP |

Of the 263 new UNANALYZED rows, 57 sit in a locally cloned repo that already has AI commits (17 unique repos, including mlflow, vm2, praisonai, mobsf, monai). That is HAS_AI on the repository, not AI-on-BIC. They stay UNANALYZED until a causal wave.

Backup: `artifacts/funnel-account-20260817.jsonl.bak-window-extend-20260826`. Site `coverage_to` / `source_cutoff` moved to 2026-08-26; published TP count unchanged at 234.

## Round7 causal research wave - 2026-08-26 (complete: 200/200)

Round7 is the prioritized wave over the 200 highest-opportunity PARTIALLY_ANALYZED cases (`round7/priority-pool.jsonl`, tier C=90/A=90/D=20), selected from the 6,357-row partial pool. Full causal method per `docs/AUDIT-PROTOCOL.md` on every case: minimal atomic BIC with parent-absence verification, fix identification, AI-role adjudication on the BIC's vulnerable lines only. Full report: `artifacts/round7-verdict-report-20260826.md`.

- Final verdicts: 192 NOT_AI, 3 AI_ROOT_CAUSE, 0 AI_CODE_FLAWED, 5 EVIDENCE_GAP (EVIDENCE_GAP rows stay PARTIALLY_ANALYZED).
- Archive fields: `round7_research`, `round7_verdict`, `round7_research_source` (per row).
- New TPs: openclaw/openclaw GHSA-hhff-fj5f-qg48 (AI_ROOT_CAUSE; BIC b9b47f5002 with Claude Opus 4.6 Co-Authored-By on the vulnerable content_type detection lines). The two other AI attributions were reversed by the correction below.
- EVIDENCE_GAP (5, stay PARTIALLY_ANALYZED): advisory-identity-pinning failures — openclaw 1342-id pool (qG), franklioxygen/mytube 4 candidates, labring/fastgpt 23, lin-snow/ech0 22, coollabsio/coolify 41 (qJ). No-inference rule forbids guessing among candidate advisories.
- Quality control: 12 qZ lines repaired from truncated round6 SHAs to full 40-hex (clone `rev-parse` + `cat-file -e` verified); 4 orphaned-BIC policy rows (BIC unreachable from origin after force-push/rebase; `introducer_parent=null` + `remaining_gap`, verdicts stand on recorded evidence); 2 root-commit BICs; 12 squash-decomposed. Final reconciliation: 200/200 pool coverage, 0 duplicate class_ids, all 18 keys, all SHAs 40-hex, `direct_fix_sha == fix_sha` everywhere.
- Ledger: `update_ledger_round7_20260825.py` → `archived=200, tp_duplicate_gate=pass`; `detect_duplicate_tps` clean post-write; no case_id clash among the 3 new TPs. Unique confirmed TPs at wave close: 232 → 235; after the correction below: 235 → 233; after correction round 2: 233 → **234**.
- Correction (2026-08-26, external cross-check, Grok): two AI attributions pointed at non-BIC commits and were re-adjudicated NOT_AI via `scripts/apply_round7_correction_20260826.py`, each re-verified against local clones before writing. (1) pydantic/pydantic-ai CVE-2026-65975 AI_ROOT_CAUSE→NOT_AI: recorded BIC b31d6072b7 (#6169, Claude Opus 4.8 co-author) is a move refactor — `sanitize_messages` already exists in its parent 0e7401af and the commit is not an ancestor of fixed v1.107.1; true BIC 53964f0ea7 (#5228, Douwe Maan, no AI markers) first wrote the drop logic into ui/_adapter.py, absent from v1.87.0, present from v1.88.0; fix corrected to 54d51dbf31 (#6407; 54d51dbf^ == v1.107.0, not the previously recorded 86029861). (2) coder/coder GHSA-686C-7VGV-V3FX AI_CODE_FLAWED→NOT_AI: the Claude Opus 4.7 revert f2b9ec2b4b is not the minimal BIC of the vulnerable line (`git log -L` traces it to c8246e3e8a, #1064, 2022, pre-AI) and was never released — no tag contains the revert without fix 57b11d40 (all 20 tags containing carrier 9400eaa9 contain the fix). Status moves: NOT_AI 1172→1174, AI_ROOT_CAUSE 188→187, AI_CODE_FLAWED 60→59. Reconciliation re-run: 200/200, 0 problems; `detect_duplicate_tps`: none. Full detail in `artifacts/round7-verdict-report-20260826.md`.
- Correction round 2 (2026-08-26, Grok second-pass audit of the 200 records, `scripts/apply_round7_correction2_20260826.py`): 3 rows re-verified against local clones. (1) relyra CVE-2026-49454 / GHSA-jv46-xfwm-36j7 stays NOT_AI — rejected: the only AI signal on BIC 2aeba972 (human szTheory) is `Made-with: Cursor`, which is non-canonical under the production source policy (`source_policy.py:480/:489`, `source_matcher.py:547-551`); its known fix 2e456897 (AI-written patch to the human `[candidate]` arm) is backfilled, verdict unchanged. (2) openclaw GHSA-VVGP-4C28-M3JM NOT_AI→AI_ROOT_CAUSE — BIC 20523b918ad (2026-02-24, `Made-with: Cursor` canonical first-writer of `trustedProxyAuthOk`); fix corrected to ec45c317 (human Steinberger, the advisory's actual fix; 96fba91b `[AI]` is later broader hardening, recorded in evidence); folded into existing TP alias-3f35b69d (no net-new TP). (3) better-auth GHSA-wxw3-q3m9-c3jr NOT_AI→AI_ROOT_CAUSE (net-new TP) — BIC corrected to b5f3bad6 (2025-10-21, #5470, `Co-authored-by: Copilot` canonical, first writer of the unverified cookie-state parse branch); human fix 9deb7936 adds the oauthState nonce + `state_security_mismatch`. Net: NOT_AI 1174→1172, AI_ROOT_CAUSE 187→189, unique TPs 233→**234**; `audit_record_gates.py` 30→26 (all on non-target pre-existing rows); `detect_duplicate_tps` none; reconciliation 200/200.
- Site publication 2026-08-26 (`scripts/publish_tp_ledger.py`): `web/src/generated/research-data.json` refreshed 232 → **234** cases (AI_ROOT_CAUSE 175 / AI_CODE_FLAWED 59), 234/234 dated, preflight 0 errors. New on the site: better-auth GHSA-WXW3-Q3M9-C3JR (correction-round-2 net-new TP; advisory 2026-05-15, `< 1.6.2` → `1.6.2`, evidence b5f3bad6/9deb7936) and openclaw GHSA-HHFF-FJ5F-QG48 (wave-7 promotion; advisory 2026-04-03, `<= 2026.3.28` → `2026.3.31`, evidence b9b47f50/ee52f642). GHSA-VVGP-4C28-M3JM stays a single case (fold row `publish: false`). Inputs: `first-party-advisory-dates.json` +2, `first-party-advisory-releases.json` +2, `generated-code-evidence.json` 133 → 135 (`.bak-20260826` each).
Backup: `artifacts/funnel-account-20260817.jsonl.bak-round7-correction2-20260826` (post-correction-round-2; pre: `artifacts/funnel-account-20260817.jsonl.bak-round7-correction-20260826`; pre-wave: `artifacts/funnel-account-20260817.jsonl.bak-round7-20260825`). Remaining pool: 0.

## Gogs causal closure - 2026-08-23

Three Gogs partial-wave rows carried complete NOT_AI research in `shard-042-out.jsonl` but were not yet closed in the ledger. Each now has a canonical `causal_research` dossier (atomic introducer, parent boundary, direct fix, AI-marker inspection) and `CONFIRMED_NOT_AI` review state.

| class_id | Advisory | Introducer | Fix | Verdict |
|---|---|---|---|---|
| alias-771f47230669a59d649529ec | CVE-2026-52797 (git diff option injection) | 01c8df01ec0 (Joe Chen, 2019) | 68b3c8f339b (#7871) | NOT_AI |
| alias-da4217b7b50e1d96c772489d | CVE-2025-64111 (symlink path RCE) | 3650b32ec58 (2024) | c3eca1fca3a (#8082) | NOT_AI |
| alias-df15c3c07b638f9f46d9acc0 | GHSA-6vxv-wg6j-5qwp (ipynb XSS) | 9af0dd23dd6 (Herbert, 2017) | f6b8c5847de (#8330) | NOT_AI |

Backup: `artifacts/funnel-account-20260817.jsonl.bak-gogs-remaining-20260823`.

## Round6 causal research wave - 2026-08-24 (complete: 1182/1182)

Round6 is the prioritized wave over the 1,182-case priority pool (`round6/priority-pool.jsonl`). Workers pA-pG run the 3-step causal method (vulnerability understanding, atomic BIC decomposition with parent-absence verification, AI-marker assessment on vulnerable lines). This checkpoint archives the final 68 cases (pA lane completion, 169/169), closing the wave at 1182/1182 archived; all lanes emitted `BATCH_COMPLETE`.

- Final wave verdicts: 768 NOT_AI, 367 EVIDENCE_GAP, 36 AI_ROOT_CAUSE, 7 AI_CODE_FLAWED, 4 BLOCKED (final 68: 63 NOT_AI, 3 AI_ROOT_CAUSE, 1 EVIDENCE_GAP, 1 BLOCKED).
- Archive fields: `round6_research`, `round6_verdict`, `round6_research_source` (per row); EVIDENCE_GAP maps to PARTIALLY_ANALYZED.
- EVIDENCE_GAP here is dominated by classes whose advisory identity cannot be pinned locally (no `.alias_class_member_map.json` entry, ambiguous repo-level collapse); the no-inference rule forbids guessing among candidate advisories, so those rows stay PARTIALLY_ANALYZED.
- The `round6_research` key presence alone is not an archive marker: an unrelated pipeline run had stamped empty `{}` placeholders on unresearched rows, which would have silently skipped the final 68. The checkpoint now treats a row as archived only when it carries `round6_verdict` or a non-empty research dict.
- Notable AI_ROOT_CAUSE: labring/fastgpt `fetchThreadReplies` thread-context injection (no allowlist filter, `Co-authored-by: Claude Opus 4.6` trailer on the vulnerable lines; fixed 30h later by filtering thread messages through the sender allowlist).
- Notable AI_CODE_FLAWED: nousresearch/hermes-agent regex-bypass in the context-file prompt-injection scanner — the AI-co-authored commit 95b6bd5df6 (Claude Opus 4.6 trailer) first wrote the vulnerable element, but the flawed blocklist approach was copied from a human-written skills_guard list, so AI implicated but not sole root.
- Notable NOT_AI: openc3/cosmos CVE-2025-68271 unauthenticated RCE via `eval(self)` in `String#convert_to_value` — BIC 320cb782 is the 2014 initial commit (pre-AI), fix 01e9fbc5 swaps eval → YAML.safe_load.
- Notable NOT_AI: n8n-io/n8n CVE-2026-72766 Send Email node arbitrary file read/SSRF — BIC is the 2019 repository root commit (pre-AI, `introducer_parent_absent=true`); fix-side AI trailers (Claude Opus 4.8, Cursor) concern the fix, not the introducer.
- Notable NOT_AI: zhongyu09/openchatbi CVE-2026-5586 Text2SQL prompt-injection RCE — BIC is the first code commit (2025-09-09, no AI markers, `introducer_parent_absent=True`); repo-wide AI trailers are post-advisory and never touched the vulnerable sink.
- Malformed-field repair (5 rows, verified against GitHub API 2026-08-24): apache/arrow introducer_sha corrected to `f62213921b003cc716d6fe50d8604560cea4a3d4` (41-char stored value dropped a char); modelcontextprotocol/python-sdk introducer_sha corrected to `4cbf8154306aa5b96b2bb3fc83ac5984d217a0f5` (39-char stored value, root commit with no parents, confirmed); vllm-project/vllm introducer_parent corrected to `37dfa6003782d872a375cc41429ca16fe241f83f` (10-char truncation); significant-gravitas/autogpt and ultradagcom/core introducer_parent values were `sha^ (parent)` shell fragments, normalized to their bare 40-hex parents (`d82e57719677e972cadf1fc890908dc904db332c`, `6462f64ec2af07129bdd6aade7a3653eb133b39f`). Parent-of-introducer relationships re-verified for arrow, vllm, and python-sdk.
- BIC fine-grained decomposition (`f2f7a68`): 5 previously-unverified squashes decomposed to atomic BICs — autogpt 57a06f708 → 583a9a9e (AI markers ON atomic BIC), grackle 3837cbd0 → 0f7e831a (AI markers ON atomic BIC), openclaw 8c852d86 4/4 (vulnerable-line BIC 9f40ec89 has NO AI marker), consul b1cd635f 13/13 (vulnerable-line BIC e42e734 has NO AI marker), llm_memory d3d69dc 5/5 (vulnerable-line BIC 696f8e39 has NO AI marker). The 3 weakened cases (openclaw/consul/llm_memory) keep their verdict with `bic_analysis` notes; downgrade review suggested.

Backup: `artifacts/funnel-account-20260817.jsonl.bak-round6-20260823`. Remaining pool: 0.

## Duplicate TP fold - 2026-08-23

Seven TP class rows were the same official GHSA as another TP. Two SpecifyJS squash aliases were already `publish: false`. The other five were only merged at site publish time; they are now folded on the canonical rows as well. Unique TPs are 195 (143 + 52), matching the public catalog.

| class_id | Folded into | Kept class |
|---|---|---|
| alias-4fdb74a9ca3848a9fc21e342 | GHSA-5C7W-4WM3-85VW | existing GHSA-5C7W row |
| alias-302ce3ba91db5b1f0e1a21b7 | GHSA-2944-57XV-2682 | existing GHSA-2944 row |
| alias-33047e254a1af181f23c0c53 | GHSA-7JM2-G593-4QRC | alias-ef917a24bf7209fd1f889026 |
| alias-f8d8e53edbeacc7b689a133b | GHSA-8G7G-HMWM-6RV2 | alias-c5a7e76e9787edf4ea076555 |
| alias-945d447820a8998f330f65d1 | GHSA-G39V-CVJH-8FPF | alias-02fb7aeb21b9f4e1ab18fbce |
| alias-ca062bdf2a1afef0fdfe5205 | GHSA-PV2J-RGHR-V5R9 | alias-adaf8ed9e0a157cba9b63805 |
| alias-3a0294dfd1f9cff8531aacfd | GHSA-W28W-GP39-M4P6 | alias-50a179b091fae05cd3c940e9 |

Backup: `artifacts/funnel-account-20260817.jsonl.bak-fold-dupes-20260823-222447`.

## Site publication reconciliation - 2026-08-23

Eight published TPs were Incomplete on the site without an `ir_chain`. Research was written back onto the canonical rows (`site_publication`, `site_scope`, `repo`, `advisory_identity`, `ir_chain`). Two SpecifyJS squash aliases were marked `publish: false` here; five more same-GHSA TP pairs were folded in the section above. Unique TPs are 195.

| class_id | Change |
|---|---|
| alias-23266042a88424523b7b8f48 | GHSA-8JQH: `site_scope` AI_ROOT_CAUSE (direct `send_webhook` intro). |
| alias-c5a7e76e9787edf4ea076555 | GHSA-8G7G: `site_scope` AI_ROOT_CAUSE (path-join intro, not sibling SSRF). |
| alias-9f69684e62a2b96f144d613f | GHSA-8359: `site_scope` AI_CODE_FLAWED (HTTP `$ref` gate, not a file:// fix). |
| alias-afc1d67fcdd491fd6884883e | GHSA-5RV5: repo `lostisland/faraday`, chain residual of GHSA-33MH. |
| alias-7224ab612b76b7dd1c18d614 | Residual is GHSA-FRVJ / CVE-2026-59221, not CVE-2026-54017. |
| alias-203bff3ee3277cd64f94c6bc | Official id GHSA-J5QP-P44G-2M49 with chain. |
| alias-4fdb74a9ca3848a9fc21e342 | `publish: false`; gql half is GHSA-5C7W. |
| alias-302ce3ba91db5b1f0e1a21b7 | `publish: false`; PT-005 is GHSA-2944. |

Backup: `artifacts/funnel-account-20260817.jsonl.bak-site-class-identity-20260823-163418`.

## Round3 causal research archive - 2026-08-21

Round3 completed 50 causal audits over the previous partial-top-50 selection, with full 18-field causal records archived into the canonical ledger.

- Verdicts: 28 NOT_AI, 1 AI_ROOT_CAUSE, 17 EVIDENCE_GAP, 4 BLOCKED.
- Reclassification: alias-fe248dd6926bbcefe1459a8b (PrestaShop multi-sink stored XSS) was NOT_AI in the round3 file, but the advisory is a multi-sink class and the original vulnerable template writer predates reachable upstream history; it is retained as PARTIALLY_ANALYZED / EVIDENCE_GAP.
- The one new AI_ROOT_CAUSE is alias-303ca6a3bcd91ac79f484238 (wevm/mppx), introducer 2566a1a0c2d9b8b2a80a4afbc1a95c9f6b7e56ba with AI marker on the vulnerable writer.
- Canonical fields: round3_research (full record), round3_verdict, round3_research_source, round3_reclassification where applicable; statuses were updated in place.
- Deferred bucket: round4-pending.jsonl now contains 22 rows (17 EVIDENCE_GAP + 4 BLOCKED + 1 reclassified) for future deep research; old selection manifest was marked completed.
- Backup: artifacts/funnel-account-20260817.jsonl.bak-round3-20260821.

## NOT_AI causal review

The current 39 NOT_AI classes were reviewed at the semantic-causality level. NOT_AI is an attribution result, not a claim that remediation is complete.

- Second review coverage: 39/39.
- Attribution conclusion: 39/39 have a semantic attribution record.
- Evidence gate: 39/39 have mechanism, introducer, AI-role, and fix-or-no-fix evidence.
- Remediation dimensions: 36 FIX_VERIFIED; 1 FIXED_AFTER_INCOMPLETE_INTERMEDIATE_FIX; 1 FIX_WITH_KNOWN_DNS_REBINDING_RESIDUAL; 1 NO_FIX_HEAD_STILL_VULNERABLE.
- Lineage dimensions: 3 ROOT_OR_IMPORT_BOUNDARY; 1 PUBLIC_SOURCE_MOVE_BOUNDARY; 28 MULTI_INTRODUCER_BOUNDARY; 7 PARENT_VERIFIED.
- Causal review dimensions: 33 MECHANISM_AND_ATTRIBUTION_CLOSED; 3 history boundary; 2 remediation boundary; 1 no-fix.
- Local and remote Git lineage, root/import boundaries, and multi-introducer parent maps are materialized for all 39 rows.
- The ciguard symlink case is recorded separately as AI_ROOT_CAUSE because its introducer carries a Claude co-author marker and creates the vulnerable walker.
- Multi-introducer and aggregate-fix boundaries remain explicit; they are not collapsed into a fake single BIC.
- Direct Git recheck: 9/39 NOT_AI rows are now routed through `.ai-slop/state/notai-review/notai-direct-recheck-20260819.jsonl`; this corrected stale package-import/dependency/release SHAs for SVGO, Kubewarden, Hatchet, OpenAM, and five MotionEye advisories.
- Independent raw-source manifest: 39/39 `SOURCE_COMPLETE`, 0 identity mismatches.
- Ledger projection reconciliation: 39/39 NOT_AI rows now project the canonical causal fields; the 9 direct rechecks override only non-empty fields, so they cannot erase canonical mechanism or closure evidence with nulls. Projection conflict audit: 0.
- OpenAM retains an explicit public source-move boundary; MotionEye retains separate atomic introducers for media preview/delete, movie playback, config permissions, restore/action execution, and filename validation.
- Explicit no-fix cases: 1.
- Canonical reconciliation: .ai-slop/state/notai-review/notai-causal-canonical-20260819.jsonl.
- Per-row semantic provenance: .ai-slop/state/notai-review/notai-provenance-audit-20260819.jsonl (39/39 matched semantic and second-review manifests).
- Detailed second review: .ai-slop/state/notai-review/notai-second-review-20260819.jsonl.
- Final second-review manifest: 39/39 rows. Attribution evidence is closed; remediation and lineage dimensions remain visible above.
- Legacy closure dossier: .ai-slop/state/notai-review/legacy-9router-causal-20260819.jsonl.
- ciguard causal dossier: .ai-slop/state/notai-review/ciguard-causal-20260819.jsonl.
- Kiota causal dossier: .ai-slop/state/notai-review/kiota-causal-20260819.jsonl.
- AI-role adversarial review: 39/39 rows passed. It found no AI introducer evidence: 30 rows have no causal AI marker, 5 have AI only on a complete fix, 1 has AI only in a PR documentation summary, and 3 have remediation caveats without causal AI evidence. Artifact: .ai-slop/state/notai-review/notai-ai-role-adversarial-20260820.jsonl.
- The 5 AI-fix-only rows remain NOT_AI because the vulnerable behavior was introduced by a human commit and the AI-assisted fixes are complete; this is distinct from AI_CODE_FLAWED. Incomplete or residual remediation is recorded separately and is not silently treated as fixed.

## Final NOT_AI re-audit correction - 2026-08-20

- Three prior NOT_AI rows were requeued to PARTIALLY_ANALYZED: two ciguard cases whose available root/aggregate metadata does not resolve the introducer AI role, and the Nexent case whose 199-file Code-transfer import root hides pre-import authorship and AI provenance.
- Two ImageMagick cases were retained after correcting their causal boundaries against the real repository: the MIFF allocation-failure leak starts at the 2009 import root; the LZMA writer flaw starts at 263771792, not the later 330af6c refactor.
- MasterGo was retained after correcting its immediate parent to dd3169bbf2fd8bace8393035d42bf7ec83b35ccb; the head remains unfixed, and the human GetC2d addition is now parent-verified.
- Correction log: .ai-slop/state/notai-review/notai-reaudit-corrections-20260820.jsonl.

## BLOCKED boundary review - 2026-08-19

All 22 current BLOCKED rows carry a deduplicated boundary dossier. The dossiers establish mechanism and ownership boundary, but do not promote a case without atomic introducer, parent absence, direct fix hunk, squash decomposition, and causal AI evidence.

- Claude Code: 20 cases; 19/20 have an exact published npm/platform fixed-version transition with a changed bundled artifact. Within those 19, CVE-2026-54316 now has a real Linux x64 target-context diff confirming the vulnerable bare `huggingface.co` allowlist was narrowed to `huggingface.co/docs`; one fixed version is no longer retrievable from npm. These package transitions close published behavior, but not the atomic Git introducer, direct fix hunk, squash decomposition, or AI authorship.
- NestJS devtools: 1 case; npm 0.0.1--0.2.0 vulnerable behavior and 0.2.1 remediation are closed from local tarballs. The package has no reachable public Git object history, so introducer/fix lineage and AI role remain unverified.
- Arnold USD: 1 case; affected importer is closed Autodesk code, while arnold-usd is a carrier.

Status remains BLOCKED for all 22 rows; missing causal history is not evidence for NOT_AI.
- Final machine-readable boundary fields are present on 22/22 rows: implementation boundary, causal status, fix status, AI-role status, and evidence reference.
- Boundary evidence index: .ai-slop/state/blocked-deepwave/blocked-boundary-evidence-index-20260819.jsonl (22/22 rows, no GitHub API).
- Evidence integrity: 22/22 second-review dossiers have concrete mechanisms, conclusions, remaining gaps, next boundaries, and evidence references; 65 references resolve to local artifacts and 1 is an explicitly recorded Autodesk advisory URL.
- Interpretation boundary: BLOCKED means the vulnerability mechanism is understood where stated, but atomic introducer/fix lineage and AI causality remain unavailable; it is not equivalent to a completed causal review.

## BLOCKED second boundary reconciliation - 2026-08-20

- Reconciled all 22 current BLOCKED rows against the canonical boundary audit and evidence index; coverage is 22/22 unique class IDs.
- Second-review summary: `.ai-slop/state/blocked-deepwave/blocked-second-review-summary-20260820.jsonl`.
- All 22 remain `RETAIN_BLOCKED`: 20 private/closed Claude Code implementation-history boundaries, 1 NestJS public-package-history boundary, and 1 closed Autodesk Arnold implementation boundary.
- NestJS is now classified as `SOURCE_UNAVAILABLE` rather than `CAUSAL_CHAIN_OPEN`: the package mechanism and 0.2.1 fix are understood; only commit-level provenance and AI-role evidence remain unavailable.
- Claude Code cli.js.map snapshot evidence is recorded separately in .ai-slop/state/blocked-deepwave/claude-code-source-map-evidence-20260820.jsonl. Its 20 records have null class_id values and broad keyword matches, so it is retained as raw material only and excluded from per-case mechanism/lineage acceptance. The authoritative mechanism evidence is the canonical semantic dossier plus the 20 case-specific deep reviews; none of these proves the vulnerable-line introducer, parent absence, direct fix, squash members, or AI role.
- The second reconciliation produced no new causal Git lineage and did not change ledger bucket counts.
- Claude Code cached before/fixed bundle comparison is recorded in .ai-slop/state/blocked-deepwave/claude-code-bundle-diff-20260820.jsonl: 18/20 cases show mechanism-related keyword context changes, 1/20 has the fixed artifact unavailable (0.2.111), and the former 1/20 platform-binary result for CVE-2026-54316 was a Windows placeholder comparison and is superseded by the real Linux x64 targeted evidence below. These are published-artifact behavior signals only, not Git fix commits or AI attribution.
- All 20 Claude tarballs were checked for source/history material; they contain bundled CLI/platform members but no parented Git history, atomic source lineage, squash members, or causal AI metadata. They therefore remain BLOCKED.
- The 20 Claude bundle signals are projected into the BLOCKED boundary index as supplemental evidence; the primary causal boundary remains SOURCE_UNAVAILABLE.
- CVE-2026-54316 targeted binary evidence: `.ai-slop/state/blocked-deepwave/claude-code-54316-linux-bundle-evidence-20260820.jsonl`; the Windows placeholder comparison was discarded as invalid evidence.

## Integrity

- JSONL rows: 29593/29593 parse successfully.
- Unique class_id: 29593/29593.
- Advisory identity: 29,593/29,593 rows carry hash-proven `advisory_ids` (sha256 of sorted census-cased member IDs + trailing newline == class_id suffix; 248/248 TP rows pass). The leftover intake of 5,469 is hash-proven 5,469/5,469. The former no-ID row `alias-bd1066d6c07a95b9fb97e4a2` (meshtastic/firmware) was user-filled on 2026-08-26 as `CVE-2024-47065` (repo-level advisory; externally verified) — see "Advisory identity recovery" section.
- BLOCKED boundary dossiers: 22/22 unique class_ids.
- NOT_AI evidence audit: 39/39 passed; no row is counted as fully remediated unless remediation_status is FIX_VERIFIED.
- NOT_AI dimension fields: notai_attribution_status, notai_remediation_status, notai_lineage_status, notai_causal_review_status.
- Ledger backups: leftover UNANALYZED intake (funnel-account-20260817.jsonl.bak-leftover-unanalyzed-20260826, pre-merge; latest); chain: .bak-advisory-lane-merge-20260826, .bak-advisory-recover-20260826, .bak-advisory-correct-20260826, .bak-advisory-backfill-20260826, .bak-window-extend-20260826, .bak-round7-correction2-20260826, .bak-round7-correction-20260826, .bak-round7-20260825 (pre-wave), .bak-final-reconcile-20260819.

- Canonical manifest repair: 39/39 records rebuilt from ledger causal_research; direct_fix_sha/fix_sha unified and explicit no-fix preserved.
- Direct-recheck overrides: 9; each retains newer targeted Git evidence while preserving canonical fields not covered by that recheck.
- Multi-introducer causal boundaries: 9 projected review states (8 multi-introducer cases plus 1 explicit source-move boundary); each retains separate introducer roles and is not collapsed into a fake single BIC.
- Projection repair script: reconcile_notai_projection_20260820.py; it applies canonical evidence first and non-empty direct-recheck fields second.
- Direct Git recheck artifact: `.ai-slop/state/notai-review/notai-direct-recheck-20260819.jsonl`; generator: `reconcile_notai_direct_recheck_20260820.py`.
- ImageMagick squash evidence: short 9d72f1a800 resolved to 9d72f1a800b88a59673d77b1da69d047daa88523 with parent b9cfe27bef51dbbd1f05aef89c767749d7e37864.

## Round8 causal research wave - 2026-08-26

- 202 PARTIALLY_ANALYZED targets researched (round8/cases-202.jsonl), one subagent per case, records at .ai-slop/state/research-queue/round8/records-wNNN.jsonl (w000-w201).
- Verdicts: NOT_AI 195, AI_ROOT_CAUSE 3 (w076 anubissbe/projecthub-mcp, w080 hulupeep/mcp-ui-probe, w166 astralisone/rive-mcp-server-core - all Claude Code generated-with markers on BIC), AI_CODE_FLAWED 2 (w020 budibase codex/* branch convention, w195 dynatrace-oss/dynatrace-mcp Copilot co-author), BLOCKED 2 (w087 anthropics/claude-code closed-source; w189 guardrails-ai supply-chain publish with no in-repo introducer).
- Unpatched (fix_sha null): 15 cases (w007, w023, w076, w078, w080, w087, w088, w092, w093, w129, w155, w166, w168, w183, w197).
- Landing: scripts/update_ledger_round8_20260826.py; backup artifacts/funnel-account-20260817.jsonl.bak-round8-20260826; 202 archived, TP-duplicate gate pass; post-land 202/202 round8_research rows verified byte-identical to worker records, statuses flipped (NOT_AI 1367, AI_ROOT_CAUSE 192, AI_CODE_FLAWED 61, BLOCKED 33, PARTIALLY_ANALYZED 5960, UNANALYZED 16511).
- Gates: 202/202 audit_record_gates.py ok; canon sweep 202/202 class_id == cases-202.jsonl.
- Report: artifacts/round8-verdict-report-20260826.md.
- Double-confirm packet for external review: artifacts/round8-double-confirm-packet-20260826.md (reviewer re-run commands, focus list, known soft spots).
- Round8 correction 2026-08-27 (post double-confirm): 5 records revised (w020/w195 -> NOT_AI, w156/w186 -> BLOCKED, w147 BIC -> 5ba6f2ef87); final NOT_AI 195 / AI_ROOT_CAUSE 3 / BLOCKED 4; ledger backup .bak-round8-correction-20260827; published catalog 237 rows (+3 MCP TPs, preflight OK, zero ALIAS-*).

## Evidence-envelope rule (canon, 2026-08-27)

A ledger row may close to a terminal status (NOT_AI / AI_ROOT_CAUSE /
AI_CODE_FLAWED) only if its payload carries the full re-derivation envelope,
so any future model can re-scan and re-derive the verdict without session
context:

1. `advisory_ids` non-null (CVE/GHSA anchor);
2. a single 40-hex `introducer_sha` (BIC) — BLOCKED rows exempt, but their
   `reasoning` must state why no BIC exists (closed source / clone mismatch /
   package mis-map);
3. `ai_marker` describing the commit-object-level signal (or its absence);
4. `reasoning` (plus `bug_semantics`/`evidence`) text chain.

Mechanical requirements: `introducer_sha` holds exactly one 40-hex sha —
multi-introducer cases split into `decomposed_shas[]` plus one primary BIC;
no annotations, splices, or dirty characters in the sha field. Verdict
payloads live in the row-level `*_research` dict (authoritative); lane
arrays (`squash_audit[]`, `partial_wave[]`, `blocked535[]`) are supporting
detail, never the sole carrier of the envelope. Every future landing gate
must include `scripts/audit_envelope.py` over the affected rows; failures
BLOCK the landing.

Repayment executed 2026-08-27: all 1,653 closed rows now pass
`scripts/audit_envelope.py` (backup .bak-envelope-repay-20260827). 354
ai_marker fields normalized; 37 spliced sha fields canonicalized; 6 BICs
re-derived and clone-verified (openclaw ×2, engram, mcp-memory-service,
grackle, datamodel-code-generator); 5 no-BIC-by-nature rows documented;
1 BLOCKED row envelope repaired. Ledger statuses, row count, and advisory
coverage unchanged.
