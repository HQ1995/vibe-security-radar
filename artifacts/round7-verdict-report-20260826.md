# Round7 causal research wave — verdict × mechanism report (2026-08-26)

Round7 is the prioritized causal wave over the **200 highest-opportunity cases** from the 6,357 PARTIALLY_ANALYZED ledger rows (`round7/priority-pool.jsonl`, tier C=90 / A=90 / D=20). Every case ran the full AUDIT-PROTOCOL method: vulnerability understanding, minimal atomic BIC identification with parent-absence verification, fix identification, and AI-role adjudication **on the minimal BIC's vulnerable lines only**.

## Final verdicts (200/200 archived)

| Verdict | Count | Ledger status |
|---|---:|---|
| NOT_AI | 192 | NOT_AI |
| AI_ROOT_CAUSE | 3 | AI_ROOT_CAUSE |
| AI_CODE_FLAWED | 0 | AI_CODE_FLAWED |
| EVIDENCE_GAP | 5 | PARTIALLY_ANALYZED (kept open) |

## Verdict × cause_category

Cause categories derived from `bug_semantics` via the same `cause_of()` classifier `scripts/publish_tp_ledger.py` uses for site publication.

| cause_category | NOT_AI | AI_ROOT_CAUSE | AI_CODE_FLAWED | EVIDENCE_GAP | Total |
|---|---:|---:|---:|---:|---:|
| injection | 78 | 0 | 0 | 0 | 78 |
| auth_access | 41 | 3 | 0 | 0 | 44 |
| other_ambiguous | 35 | 0 | 0 | 5 | 40 |
| ssrf_network | 18 | 0 | 0 | 0 | 18 |
| validation_fail_open | 8 | 0 | 0 | 0 | 8 |
| path_link | 7 | 0 | 0 | 0 | 7 |
| resource_abuse | 5 | 0 | 0 | 0 | 5 |
| **Total** | **192** | **3** | **0** | **5** | **200** |

## New true positives (2)

| class_id | repo | Advisory | BIC | Fix | Verdict |
|---|---|---|---|---|---|
| alias-cfe8a69b17c7144c755c5961 | openclaw/openclaw | CVE-2026-41374 / GHSA-hhff-fj5f-qg48 | b9b47f50023d9f6384372bad6eee1a181b98c48e | ee52f64226a03efadfdf1e3b759e13424a3d4e41 | AI_ROOT_CAUSE |
| alias-f0b371318e30448b9a250d8a | better-auth/better-auth | GHSA-wxw3-q3m9-c3jr | b5f3bad633d8ae79fd5ffbb35ec2a39afdfc2f5e | 9deb7936aba7931f2db4b460141f476508f11bfd | AI_ROOT_CAUSE |

- **openclaw GHSA-hhff-fj5f-qg48 (AI_ROOT_CAUSE)**: BIC b9b47f50 (2026-03-02, "fix(discord): use correct content_type property for audio attachment detection") carries `Co-Authored-By: Claude Opus 4.6` on the exact vulnerable lines (content_type detection, message-handler.preflight.ts). It activated the previously-dead pre-auth audio transcription path in requireMention guilds; parent 319b7c68 demonstrably lacks the live behavior (dead camelCase check).
- **better-auth/better-auth GHSA-wxw3-q3m9-c3jr (AI_ROOT_CAUSE)**: BIC b5f3bad6 (2025-10-21, #5470, `Co-authored-by: Copilot` canonical) is the first writer of the unverified cookie-state parse branch; parent 3a3434b4 is absent (verified). The human fix 9deb7936 (2026-04-09, #8949) adds the oauthState nonce + `state_security_mismatch` check.

The BIC was verified directly against the local clone (cat-file -e, parent line, parent-absence grep, message trailers). `detect_duplicate_tps` over the full post-round7 ledger, re-run after the correction below: **no duplicates**.

## Correction after external cross-check (Grok, 2026-08-26)

An independent external cross-check (Grok) flagged that two of the AI attributions pointed at non-BIC commits. Every claim was re-verified against the local clones before any record was changed: openclaw stands, pydantic-ai and coder are re-adjudicated NOT_AI. The original `update_ledger_round7_20260825.py` output in Ledger landing is preserved as recorded; the correction is layered on top.

- **pydantic-ai CVE-2026-65975: AI_ROOT_CAUSE → NOT_AI.** The recorded BIC b31d6072 (#6169, 2026-07-03, Co-authored-by Claude Opus 4.8) is a move refactor, not the first writer: `sanitize_messages` already exists in its parent 0e7401af at `ui/_adapter.py:347`, and the commit is NOT an ancestor of the fixed version v1.107.1 (first ships v2.5.0). The true minimal BIC is **53964f0ea79fdcb178fef705c6b5c64198c0ee36** (#5228, Douwe Maan, 2026-04-28, no AI trailers): it first wrote `UIAdapter.sanitize_messages` with the trailing-message drop logic (`last_index = len(messages) - 1`) into `ui/_adapter.py`; parent 1b4f9062 contains no `last_index`; the BIC is absent from v1.87.0 and present from v1.88.0, the advisory lower bound. The fix is also corrected: **54d51dbf3189cb7639949253951eda52d0e19054** (#6407, David SF, 2026-07-10, no markers) strips dangling tail tool calls after drops; it is present in v1.107.1, absent from v1.107.0, and `54d51dbf^` == v1.107.0. The previously recorded fix 86029861 (#6319) resolves a different `sanitize_messages` issue. AI marker on a non-BIC commit → demoted per protocol.
- **coder/coder GHSA-686C-7VGV-V3FX: AI_CODE_FLAWED → NOT_AI.** The revert f2b9ec2b (2026-05-13 12:04, Co-Authored-By Claude Opus 4.7) is real but is not the minimal BIC of the vulnerable lines: `git log -L` on `res, err := http.DefaultClient.Do(req)` (azureidentity.go:102) traces to **c8246e3e8ade9c447aca6f93a6ec58dda0a715ea** (#1064, Kyle Carberry, 2022-04-19, no AI markers, pre-AI era), whose parent 118a47e4 contains no `http.DefaultClient`. The 2026 incident: fb3aef1883 (11:55) hardened the cert fetch; the AI revert f2b9ec2b and its squash carrier 9400eaa9 (12:10, #25273, human, no marker) both deleted it; fix 57b11d40 (12:51, #25274, human, no marker; `57b11d40^` == 9400eaa9) restored it. f2b9ec2b appears in no tag, and all 20 tags containing 9400eaa9 (earliest v2.34.0) also contain 57b11d40 — the vulnerable window (~47 minutes) was never released. AI marker on a non-BIC, unreleased commit → demoted per protocol.
- **openclaw CVE-2026-41374: stands AI_ROOT_CAUSE.** BIC b9b47f50 (Co-Authored-By: Claude Opus 4.6) writes the exact vulnerable `content_type` lines; parent 319b7c68 carries the dead camelCase `contentType` check; fix ee52f642 gates the audio preflight on member access.

Post-correction landing: lane re-reconciliation 200/200 (NOT_AI 194 / AI_ROOT_CAUSE 1 / AI_CODE_FLAWED 0 / EVIDENCE_GAP 5, 0 problems); ledger status NOT_AI 1172→1174, AI_ROOT_CAUSE 188→187, AI_CODE_FLAWED 60→59; unique confirmed TPs 235→**233** (246 TP-status rows − 13 `site_publication.publish: false` folds); `detect_duplicate_tps` still none.

## Correction round 2 (Grok second-pass audit of the 200 records, 2026-08-26)

A second independent pass (Grok) audited all 200 archived records and flagged 3 for NOT_AI → AI. Every claim was re-verified against the local clones before any record was changed: one upheld (relyra, non-canonical marker), two confirmed (openclaw, better-auth). The round-1 Correction above is preserved as recorded; this round is layered on top.

- **relyra CVE-2026-49454 / GHSA-jv46-xfwm-36j7: REJECTED — stands NOT_AI.** The only AI signal on the BIC 2aeba972 (human author szTheory) is the trailer `Made-with: Cursor`, which is NOT canonical HAS_AI evidence under the production source policy: the verb "Made" is not in `EXPLICIT_ATTRIBUTION_VERBS`, and it is not a co-author, footer, or `Assisted-by` line (`cve-analyzer/src/cve_analyzer/source_policy.py:480/:489`, `source_matcher.py:547-551`; `unknown_tool_attribution_is_production_evidence=False`). The BIC stands human-written; the NOT_AI verdict holds. This is a documented disagreement with the external cross-check, resolved in favor of the production source policy + local evidence.
- **relyra CVE-2026-49454 — fix backfill (independent fact, verdict unchanged):** the record was closed NOT_AI without recording the known fix. The fix is **2e456897af3158c175bb490ce7fc51d6241c8922** (2026-05-24, szTheory, `Co-Authored-By: Claude Opus 4.7`), which patches the human-authored `[candidate]` arm of the BIC. AI writing the fix does not make the BIC AI-written, so the verdict stays NOT_AI; the row now passes the fact gate.
- **openclaw GHSA-VVGP-4C28-M3JM: CONFIRMED — NOT_AI → AI_ROOT_CAUSE (folded).** BIC 20523b918adff4feae378ac9965e204c56b6e3d8 (2026-02-24, `Made-with: Cursor` canonical via first-writer `git log -S 'trustedProxyAuthOk'`) is the true minimal BIC; parent d84659f22fc59d9eecfa6f1cebe24b79674bed5a is absent. **Fix corrected to ec45c317f5d0631a3d333b236da58c4749ede2a3** (human Steinberger, 2026-02-26, no AI trailer) — the advisory's actual fix — NOT 96fba91b (2026-05-13, `[AI]` #81288, a broader deletion of the whole bypass three months later; recorded in `evidence` as later hardening; dossier `scripts/audit_results/GHSA-vvgp-4c28-m3jm.json`, conf 0.99, `fix_commit=ec45c317`). `squash_decomposed` true→false, `decomposed_shas` 7→[] (the 7 members were all locally unverifiable; 20523b918ad is a locally-verified atomic first-writer, not a squash member). `advisory_ids` = `["GHSA-VVGP-4C28-M3JM"]` (no local CVE mapping). This row is a **duplicate** of existing TP alias-3f35b69df081559ab1fad010, so a ledger-level fold `site_publication={publish:false, folded_into: GHSA-VVGP-4C28-M3JM, kept_class_id: alias-3f35b69df081559ab1fad010}` is recorded — no net-new TP.
- **better-auth GHSA-wxw3-q3m9-c3jr: CONFIRMED — NOT_AI → AI_ROOT_CAUSE (net-new TP).** BIC corrected to b5f3bad633d8ae79fd5ffbb35ec2a39afdfc2f5e (2025-10-21, #5470, `Co-authored-by: Copilot` canonical, first writer of the unverified cookie-state parse branch); parent 3a3434b403187ddace8cf35a1ee6ae88aeb11377 absent (verified). The previously-recorded move commit 34c8a4bd2a7a60cbf1232141ca270c08045e1af6 (#6675, human) is the carrier, not the introducer; the phantom 3d3435b32ded (unresolvable) is removed. Human fix 9deb7936aba7931f2db4b460141f476508f11bfd (2026-04-09, #8949) adds the oauthState nonce + `state_security_mismatch` check.

Post-correction-round-2 landing: wave 200/200 reconciliation (NOT_AI 192 / AI_ROOT_CAUSE 3 / AI_CODE_FLAWED 0 / EVIDENCE_GAP 5, 0 problems); ledger status NOT_AI 1174→1172, AI_ROOT_CAUSE 187→189, AI_CODE_FLAWED 59 and PARTIALLY_ANALYZED 6162 unchanged; unique confirmed TPs 233→**234** (248 TP-status rows − 14 `site_publication.publish: false` folds); `audit_record_gates.py` 30→26 failures (all 26 on non-target pre-existing rows; the 3 target rows are gate-clean); `detect_duplicate_tps` none. Backup: `artifacts/funnel-account-20260817.jsonl.bak-round7-correction2-20260826`.

## EVIDENCE_GAP (5, remain PARTIALLY_ANALYZED)

All five are advisory-identity-pinning failures (no-inference rule forbids guessing among candidates); causal evidence for the mechanism is recorded but the class cannot be uniquely bound to one advisory.

| class_id | repo | Gap |
|---|---|---|
| alias-094830ca6d0802876f64ca33 (qG) | openclaw/openclaw | 1,342-id candidate pool; alias member_ids lost from local census artifacts. |
| alias-0f4e0576cb9861ef591e61ff (qJ) | franklioxygen/mytube | 4 candidate CVEs remain after sibling-class elimination. |
| alias-0fec81a0c9a99d6d4d208bd6 (qJ) | labring/fastgpt | 23 candidate CVEs remain. |
| alias-124590fbf2b4fa0bcd9e7458 (qJ) | lin-snow/ech0 | 22 candidate advisories remain. |
| alias-142fa0783726f85297cce7ca (qJ) | coollabsio/coolify | 41 candidate CVEs remain. |

## Lane breakdown (14 lanes, 200 records, 0 duplicates)

| Lane | Cases | Verdicts | Notes |
|---|---:|---|---|
| pA / pB / pC | 3 | 3 NOT_AI | carried into round7 from the earlier partial pool (gitpython, ciguard, openclaw) |
| qA / qB / qC | 19 | 18 NOT_AI, 1 AI_ROOT_CAUSE | qC holds the openclaw AI_ROOT_CAUSE above |
| qG | 3 | 2 NOT_AI, 1 EVIDENCE_GAP | openclaw 1342-id pool identity failure above |
| qH | 7 | 7 NOT_AI | gitpython, gogs, gitea×2, filebrowser, fickling, fleet |
| qI | 14 | 14 NOT_AI | haxtheweb via haxcms-php clone (pinned clone is the issue tracker) |
| qJ | 14 | 10 NOT_AI, 4 EVIDENCE_GAP | identity-pinning failures above |
| qK | 13 | 13 NOT_AI | two workers (NoSHAQK + NoSHAQK2) |
| qL | 13 | 13 NOT_AI | pydantic-ai corrected to NOT_AI (see Correction) |
| qM | 13 | 13 NOT_AI | coder/coder corrected to NOT_AI (see Correction); openclaw MINIMAX_API_HOST + env-vars cases closed NOT_AI (human BICs) |
| qZ | 101 | 99 NOT_AI, 2 AI_ROOT_CAUSE | 15 open-webui + 86 B1 mechanical backfill (round6 pre-adjudicated); 12 squash-decomposed; 4 orphaned-BIC policy rows; 2 root-commit BICs |

## Quality-control events

- **qZ short-SHA repair**: 12 lines carried truncated round6 SHAs (langflow×5, langsmith-sdk×2, mlflow, n8n, parse-server, litellm); each resolved to full 40-hex via `git rev-parse <short>^{commit}` per clone with roundtrip + `cat-file -e` verification. qZ re-verified at 101 lines, 0 problems.
- **qM race resolution**: the main session and worker NoSHAQM both worked the last 2 cases; NoSHAQM's final line for alias-ffaed51e4737ccd1a6bc418a is byte-identical to the ledger row (all 18 keys diff-clean), so no ledger rewrite was needed.
- **Orphaned-BIC policy**: 4 rows have BICs unreachable from origin (force-push/rebase); per policy `introducer_parent=null`, verdict stands on recorded evidence, `remaining_gap` documents the orphan — no flip to BLOCKED.
- **Reconciliation**: final full-lane check = 200/200 pool coverage, 0 duplicate class_ids, all 18 keys present, all verdicts in domain, all SHAs 40-hex, `direct_fix_sha == fix_sha` everywhere, gap fields present on all EVIDENCE_GAP rows.

## Ledger landing

- `scripts/update_ledger_round7_20260825.py` output: `{"archived": 200, "pool_completed": 200, "skipped_existing": 0, "tp_duplicate_gate": "pass"}`.
- Backup: `artifacts/funnel-account-20260817.jsonl.bak-round7-20260825`.
- Status deltas: PARTIALLY_ANALYZED 6357 → 6162 (−195 = 200 − 5 EVIDENCE_GAP); NOT_AI 980 → 1172; AI_ROOT_CAUSE 186 → 188; AI_CODE_FLAWED 59 → 60; BLOCKED unchanged (31); UNANALYZED unchanged (16248).
- Unique confirmed TPs: **235** (248 TP-status rows − 13 `site_publication.publish: false` folds; pre-round7 net count was 232, +3 from this wave).
- Correction (2026-08-26, after external cross-check): 2 rows re-adjudicated via `scripts/apply_round7_correction_20260826.py` (pydantic-ai AI_ROOT_CAUSE→NOT_AI; coder AI_CODE_FLAWED→NOT_AI); backup `artifacts/funnel-account-20260817.jsonl.bak-round7-correction-20260826`. Status deltas vs the pre-round7 baseline become: NOT_AI 980 → 1174; AI_ROOT_CAUSE 186 → 187; AI_CODE_FLAWED 59 → 59; PARTIALLY_ANALYZED 6357 → 6162. Unique confirmed TPs: **233** (246 TP-status rows − 13 `site_publication.publish: false` folds; pre-round7 net was 232, +1 net from this wave after correction). Reconciliation re-run: 200/200, 0 problems; `detect_duplicate_tps`: none.
- Correction round 2 (2026-08-26, Grok second-pass audit of the 200 records): 3 rows via `scripts/apply_round7_correction2_20260826.py` — relyra CVE-2026-49454 stands NOT_AI (rejected, `Made-with: Cursor` is non-canonical) with its known fix 2e456897 backfilled; openclaw GHSA-VVGP-4C28-M3JM → AI_ROOT_CAUSE (folded into existing TP alias-3f35b69d, fix corrected to ec45c317); better-auth GHSA-wxw3-q3m9-c3jr → AI_ROOT_CAUSE (net-new TP, BIC corrected to b5f3bad6). Backup `artifacts/funnel-account-20260817.jsonl.bak-round7-correction2-20260826`. Status vs pre-round7 baseline: NOT_AI 980 → 1172, AI_ROOT_CAUSE 186 → 189, AI_CODE_FLAWED 59 → 59, PARTIALLY_ANALYZED 6357 → 6162. Unique confirmed TPs: **234** (248 TP-status rows − 14 `site_publication.publish: false` folds; pre-round7 net was 232, +2 net from this wave after both corrections). `audit_record_gates.py`: 26 failures (all on non-target pre-existing rows). Reconciliation 200/200, 0 problems; `detect_duplicate_tps`: none.
- Pool rows marked `selection_state=completed` (200/200); `round7/archived-ids.txt` written (200 ids).

Site publication (`web/src/generated/research-data.json`) **published 2026-08-26** (user instruction). 232 → **234** cases (AI_ROOT_CAUSE 175 / AI_CODE_FLAWED 59), 234/234 with traceable publication dates, preflight 0 errors. Published this round: better-auth GHSA-WXW3-Q3M9-C3JR (net-new TP; real advisory date 2026-05-15, range `< 1.6.2` → `1.6.2`, code evidence from b5f3bad6/9deb7936) and openclaw GHSA-HHFF-FJ5F-QG48 (wave-7 promotion; date 2026-04-03, range `<= 2026.3.28` → `2026.3.31`, code evidence from b9b47f50/ee52f642). GHSA-VVGP-4C28-M3JM remains a single case — the correction-2 fold row (`publish: false`) contributes no duplicate. Input tables updated: `first-party-advisory-dates.json` (+2), `first-party-advisory-releases.json` (+2), `generated-code-evidence.json` (133 → 135); `.bak-20260826` backups of all three.
