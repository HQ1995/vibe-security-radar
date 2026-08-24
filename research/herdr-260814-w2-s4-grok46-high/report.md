# Wave-2 adjudication-2 kind-1 directroot (grok-4.6 high)

Verdict first: reviewed 15/15. CONFIRM 0, NARROW 0, FALSE_POSITIVE 5, UNKNOWN 10. terminal_true=5 terminal_false=10. countable_proposal=0. Worker PASS/CONFIRM is proposal only. Canonical ledger was not edited. Publication and greater-than-200 stay HOLD.

## Method

Kind-1 directroot rows from autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-2.jsonl. Each row already names best.ai_sha plus a fix. Local first-party GHSA objects were loaded from frozen advisory-database clones. Candidate commits were typed in /home/hanqing/.cache/ghsa200-w3-fetch clones. GitHub API was not used. Missing parent/fix blobs stay UNKNOWN and are not converted into FAIL/FALSE_POSITIVE. FALSE_POSITIVE is used only where the candidate message and blamed files positively show a different mechanism or a carrier (grammar, sibling parse_str vs unserialize, changelog, license/SPDX headers). AI_INCOMPLETE_REMEDIATION is not assigned because the patch-delta later-fix amendment was not replayed.

## Counts

- assigned 15, reviewed 15, unreviewed 0. Conservation 15=15+0.
- CONFIRM 0 NARROW 0 FALSE_POSITIVE 5 UNKNOWN 10
- identity PASS on all 15 first-party github-reviewed objects (none withdrawn).
- uniqueness PASS where absent from canonical84 (ledger_ok=True, hits=0).

## Per-row

| # | case_id | repository | verdict | conf | failing | open | note |
|---|---|---|---|---|---|---|---|
| 1 | GHSA-J6V5-G24H-VG4J | MontFerret/ferret | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Do not treat Copilot co-author branding on Feat/modules as origin of the path-traversal sink. |
| 2 | GHSA-4JVX-93H3-F45H | OpenC3/cosmos | UNKNOWN | MEDIUM | none | topology_gate, but_for_gate, fix_reversal_gate, release_gate | Incomplete-remediation patch-delta cannot close without the later fix blob. Missing evidence is UNKNOWN, never FAIL. |
| 3 | GHSA-45Q4-X4R9-8FQJ | go-vikunja/vikunja | FALSE_POSITIVE | HIGH | ai_hunk_gate, topology_gate, but_for_gate | fix_reversal_gate, release_gate | Positive counterevidence from the candidate message; not a missing-evidence FAIL. |
| 4 | GHSA-VFGX-5Q85-58Q3 | jahlives/openssl_encrypt | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Claude trailer on a refactor is insufficient without a blamed PRNG hunk. |
| 5 | GHSA-4MPH-V827-F877 | locutusjs/locutus | FALSE_POSITIVE | HIGH | ai_hunk_gate, topology_gate, but_for_gate | fix_reversal_gate, release_gate | Positive sibling-path counterevidence. Not countable AI_INCOMPLETE_REMEDIATION. |
| 6 | GHSA-X2HW-PX52-WP4M | stellar/rs-soroban-sdk | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Routing via crypto feature commit is not causal proof. |
| 7 | GHSA-HQJG-PWW4-PCGQ | google/clasp | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Docs-only claim is not converted to FAIL while the blamed file is the advisory sink and the parent diff is unavailable. |
| 8 | GHSA-3RMJ-9M5H-8FPV | withastro/astro | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Merge-carrier suspicion is not converted to topology FAIL without a parent list replay. |
| 9 | GHSA-JMH7-G254-2CQ9 | gradio-app/gradio | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Stored-label disagreement is recorded; missing parent keeps ai_hunk UNKNOWN rather than FAIL. |
| 10 | GHSA-C32J-VQHX-RX3X | jwt/ruby-jwt | FALSE_POSITIVE | HIGH | ai_hunk_gate, topology_gate, but_for_gate | fix_reversal_gate, release_gate | Positive counterevidence that the AI trailer is changelog-only. |
| 11 | GHSA-M98R-6667-4WQ7 | aegra/aegra | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Same-file proximity is not but-for proof. |
| 12 | GHSA-G3VG-VX23-3858 | oscal-compass/compliance-trestle | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Build-tooling AI trailer is not converted to FAIL without a parent diff showing cache.py logic unchanged. |
| 13 | GHSA-FQ7H-9X26-6J22 | external-secrets/external-secrets | FALSE_POSITIVE | HIGH | ai_hunk_gate, topology_gate, but_for_gate | fix_reversal_gate, release_gate | Positive carrier/wrong-surface counterevidence from the candidate message. |
| 14 | GHSA-FPW6-HRG5-Q5X5 | lin-snow/Ech0 | FALSE_POSITIVE | HIGH | ai_hunk_gate, topology_gate, but_for_gate | fix_reversal_gate, release_gate | Mechanical header carrier. Directroot packet AI sha is not the GHSA hunk. |
| 15 | GHSA-QX5F-GHC2-7G5C | ethyca/fides | UNKNOWN | LOW | none | ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Same privacy-request surface is not causal proof. |

## Per-gate failures and opens

- identity_gate: PASS 15, FAIL 0, UNKNOWN 0
- ai_hunk_gate: PASS 1, FAIL 5, UNKNOWN 9
- topology_gate: PASS 0, FAIL 5, UNKNOWN 10
- but_for_gate: PASS 0, FAIL 5, UNKNOWN 10
- fix_reversal_gate: PASS 0, FAIL 0, UNKNOWN 15
- release_gate: PASS 0, FAIL 0, UNKNOWN 15
- uniqueness_gate: PASS 15, FAIL 0, UNKNOWN 0

FAIL is limited to five FALSE_POSITIVE rows where the assigned AI sha is positively the wrong surface:

- GHSA-45Q4-X4R9-8FQJ vikunja: Copilot grammar commit vs HTML injection in overdue emails.
- GHSA-4MPH-V827-F877 locutus: Claude parse_str includes() guard (GHSA-rxrv) vs unserialize() pollution.
- GHSA-C32J-VQHX-RX3X ruby-jwt: Copilot changelog on a ruby-head compat commit vs empty-key HMAC.
- GHSA-FQ7H-9X26-6J22 external-secrets: Copilot license-header CI vs secret overwrite.
- GHSA-FPW6-HRG5-Q5X5 Ech0: SPDX header prepend vs irrevocable expiry=never tokens.

OpenC3 GHSA-4JVX-93H3-F45H is the only row with ai_hunk PASS: Claude co-authored an explicit ToolConfigModel path-traversal denylist that the GHSA names. Later fix e6efccbd148b and parent blobs are missing, so topology/but_for/fix_reversal/release stay UNKNOWN and the row is not labeled AI_INCOMPLETE_REMEDIATION.

## Evidence paths

- Slice: autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-2.jsonl
- Slice sha256: 27b72afa0995d061aa0e489a3342281a8135657a8ff9cb7170724aac25278d46
- Contract: autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
- Advisories: /home/hanqing/.cache/cve-analyzer/advisory-database and ghsa200-worker-clones frozen copies
- Repo clones: /home/hanqing/.cache/ghsa200-w3-fetch/<owner>__<repo>
- L0 ledger (read-only uniqueness): autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl
- Owned outputs: autoresearch/herdr-260814-w2-s4-grok46-high/{result.json,cases.jsonl,report.md}

## Disagreement with stored labels

Slice rows carry no seven-gate labels. This directory previously held kind-2 slice-04 UNKNOWN proposals; those files are replaced. GHSA-JMH7 had a prior sample-lane AI_NOT_HUNK_AUTHOR FAIL; this packet keeps UNKNOWN because the Gradio 6.0 squash parent blobs are missing. No original_vulnerability block: no AI_INCOMPLETE_REMEDIATION verdict.

## Claim boundary

Worker FALSE_POSITIVE/UNKNOWN is a proposal. Leader replay is required before anything counts. Canonical84 remains the only claim source.
