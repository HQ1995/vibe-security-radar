# Wave 2 adjudication 3: verdict-first report

## Result

All 15 assigned rows are terminal. This slice proposes two countable `NARROW` cases, both under the `AI_INCOMPLETE_REMEDIATION` patch-delta rule, and rejects the other 13 rows as `FALSE_POSITIVE`. There are no `CONFIRM` or `UNKNOWN` rows. These are worker proposals only; canonical84 and publication state remain unchanged and `HOLD`.

Gate order in the table is identity / AI hunk / topology / but-for / fix reversal / release / uniqueness.

| Case | Verdict | Class | Gates | Decisive scope or failure |
|---|---|---|---|---|
| GHSA-6XJ8-QV9J-XCJQ | FALSE_POSITIVE | UNRELATED_TRANSIENT_PROMPT_FEATURE | P/F/P/F/P/U/P | Right-aligned transient prompt work does not touch the path segment's untrusted second template evaluation. |
| GHSA-VX7X-VCC2-C44G | FALSE_POSITIVE | EARLIER_REMOTE_REF_GATE_NOT_DNS_GUARD | P/F/P/F/P/P/P | The DNS guard was introduced by later commit `5fdba4a`; the candidate did not author its unpinned lookup. |
| GHSA-4VGR-H27G-CF9P | FALSE_POSITIVE | ERROR_SERIALIZATION_REFACTOR_OLD_SESSION_RACE | P/F/P/F/P/U/P | Error serialization changed; the shared HTTP session model did not. |
| GHSA-WHWG-VH4F-PMMF | FALSE_POSITIVE | PRECEDES_HUMAN_PURGE_EDGE_REWRITE | P/F/P/F/P/U/P | The candidate predates the human commit that added `with_perms(false)` to the new edge purge path. |
| GHSA-RFR2-MQ9M-X2QX | FALSE_POSITIVE | UNTOUCHED_DIRECT_URL_SIBLING | P/F/P/F/P/P/P | The direct `--url` SSRF is a pre-existing sibling of the candidate's nested-reference gate. |
| GHSA-WP87-MGVQ-5J93 | FALSE_POSITIVE | ERROR_SERIALIZATION_REFACTOR_OLD_USE_AUTOCREATE | P/F/P/F/P/U/P | The candidate does not change `USE NS/DB` materialization or authorization. |
| GHSA-FW57-JGCH-PGF3 | FALSE_POSITIVE | CODEQL_PAGINATION_WRONG_EDGE | P/F/P/F/P/U/P | The CodeQL cleanup never touches the `Accept-Language` parser sink. |
| GHSA-7WPJ-VVMV-PGM8 | FALSE_POSITIVE | SEMANTICS_PRESERVING_WORKSPACE_MOVE | P/P/P/F/P/P/P | The candidate authors the new workspace copy, but copies the same vulnerable `out_dir.join(filename)` logic from the parent; a move fails but-for. |
| GHSA-8359-H9FX-J6V9 | NARROW | AI_INCOMPLETE_REMEDIATION | P/P/P/P/P/P/P | Only the candidate gate's omitted `file://` and external local-path cases. |
| GHSA-6X6H-QQR7-855W | FALSE_POSITIVE | SECURITY_FIX_MEMBER_NOT_ORIGIN | P/P/P/F/P/F/P | The candidate is a member of the CORS fix series, not a vulnerable origin; the complete fix series first ships together. |
| GHSA-4JWF-M4WG-8P66 | FALSE_POSITIVE | UNRELATED_CAPABILITY_FIELD_MAPPING | P/F/P/F/P/F/P | Mapping `confirmation.isNonConsequential` neither creates nor validates `static_template.file`. |
| GHSA-954P-556P-R752 | NARROW | AI_INCOMPLETE_REMEDIATION | P/P/P/P/P/P/P | Only the candidate gate's default `None` branch that warns and still fetches an untrusted HTTP(S) `$ref`. |
| GHSA-5QFP-32CF-69JH | FALSE_POSITIVE | ERROR_SERIALIZATION_REFACTOR_OLD_SESSION_ENUMERATION | P/F/P/F/P/U/P | The candidate leaves HTTP session enumeration and cross-caller targeting unchanged. |
| GHSA-JFM3-95JQ-Q3RF | FALSE_POSITIVE | INLINE_FOOTNOTE_CONFIG_WRONG_EDGE | P/F/P/F/P/F/P | An inline-footnote switch does not author duplicate named-definition backref amplification. |
| GHSA-RM43-82J9-R4MJ | FALSE_POSITIVE | PREEXISTING_UNTRUSTED_ROUTE_PRESERVED | P/F/P/F/P/P/P | New constant tab routes do not cause the older request-controlled `/agents` and static path joins. |

## Countable patch deltas

### GHSA-8359-H9FX-J6V9

Candidate `f6d4cbd3440a84e801566fa758ab2bf483322082` is an atomic Claude-coauthored security change. It adds the `allow_remote_refs` boundary in `JsonSchemaParser._get_ref_body`, explicitly exempts `file://`, and leaves external relative local paths unconstrained. Versions 0.56.0 through 0.61.0 contain that attempted remediation. Fix `2ff4a72b4550a2b2069754c5b075b1655067e5fb` changes the exact gate so `file://` is covered and introduces resolved-path confinement against `base_path`; 0.62.0 contains the closure. The scope is intentionally narrower than all local-file handling, and the required `original_vulnerability` block is present in `cases.jsonl`.

### GHSA-954P-556P-R752

The same candidate adds the tri-state HTTP(S) `$ref` boundary and rewrites the HTTP fetch helper, but its compatibility default only warns and proceeds. The first-party advisory explicitly identifies this fail-open default. Versions 0.56.0 through 0.60.2 contain the incomplete attempt. Fix `5fdba4a09f2d7a9996a504975b7ef7d63e3715bb` directly hardens the candidate-touched shared fetch path with URL/IP checks, manual redirect validation, and explicit private-network opt-in; 0.61.0 contains the closure. The required `original_vulnerability` block records unknown original IDs and introducing SHA as `null` rather than inventing them.

The sibling `GHSA-RFR2-MQ9M-X2QX` is not transferred into either acceptance: direct CLI `--url` fetching predates the candidate, and that advisory explicitly distinguishes its entry point. Likewise `GHSA-VX7X-VCC2-C44G` belongs to the later `5fdba4a` DNS guard and its pinning fix, not to candidate `f6d4cbd`.

## Decisive counterevidence

- LightRAG candidate `df68d75f` changes exact-list equality to wildcard membership and therefore closes the mixed-wildcard residual left by parent fix `09567a4c`. Follow-up `ebba6548` makes an explicitly empty origin list fail closed, but the candidate already disables credentials whenever `*` is present. All three commits first appear in fixed `v1.5.4`; there is no released candidate-only residual interval.
- SurrealDB candidate `54efe747` performs scan-cursor work. At that commit, the old purge path uses the caller's `opt`. Fix-parent blame attributes the later `with_perms(false)` edge-purge implementation to human commit `25d16748781`, after the candidate.
- Wakaru is the only rejected row whose AI-hunk gate passes independently of the two patch-delta cases. The workspace split creates the new CLI file, but its parent has the same attacker-controlled filename join. Local ancestry proves the copy in the 1.0.0 release and its closure in 1.4.0; release evidence cannot repair failed but-for causality.
- CommonMark candidate `84870f31` remains in the Unreleased changelog section and is unrelated to duplicate named footnotes. Candidate and fix are both ancestors of release commit `5703d83b` for 2.9.0, so no candidate-only affected release exists.

## Gate and label accounting

- Identity: 15 PASS.
- AI hunk: 4 PASS, 11 FAIL.
- Topology: 15 PASS.
- But-for: 2 PASS, 13 FAIL.
- Fix reversal: 15 PASS.
- Release: 6 PASS, 3 FAIL, 6 UNKNOWN.
- Uniqueness: 15 PASS.

The six release `UNKNOWN` values were preserved as missing evidence and were not converted into failures. Those rows are nevertheless terminal false positives because their candidate-specific AI-hunk and but-for gates decisively fail.

Two stored routing `REJECT` labels are challenged: `GHSA-8359-H9FX-J6V9` and `GHSA-954P-556P-R752`. The earlier rows relied on deleted-line blame and did not apply the contract's incomplete-remediation patch-delta rule. The current review proves the candidate-added boundary, released residual, first-party advisory binding, and later closure at a narrowed scope. The prior LightRAG `AI_INCOMPLETE_REMEDIATION_OUT_OF_LANE` hint remains rejected after release and same-invariant replay.

## Evidence and reproducibility

Primary inputs are `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-3.jsonl`, the frozen reviewed advisory objects under `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/`, and the nine local analysis clones recorded per case in `cases.jsonl`. Every row contains its advisory path, candidate and parent metadata, minimum-fix metadata, release statement, evidence paths, and replay commands.

No GitHub API, REST request, or network fetch was used for this slice. Canonical84, truth-layer documents, tracked source, and other campaign directories were not edited.
