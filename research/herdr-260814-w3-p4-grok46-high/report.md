# Wave 2 adjudication 4: verdict-first report

## Result

All 14 assigned rows are terminal `FALSE_POSITIVE`. This slice proposes zero countable cases. There are no `CONFIRM`, `NARROW`, or `UNKNOWN` rows. Worker output is a proposal only; canonical84 and publication remain `HOLD` at 84 strict released identities. Greater-than-200 stays unsupported.

Gate order in the table is identity / AI hunk / topology / but-for / fix reversal / release / uniqueness.

| Case | Verdict | Class | Gates | Decisive failure |
|---|---|---|---|---|
| GHSA-4F78-QHMW-8J8M | FALSE_POSITIVE | CHROMIUM_ROLLER_WRONG_HUNK | P/F/P/F/P/P/P | Roller plus Claude patch-conflict helpers only swap a git-revision include, not dock_state. |
| GHSA-C4C3-PG64-4M4V | FALSE_POSITIVE | BETA_SUFFIX_TEST_WRONG_EDGE | P/F/P/F/P/P/P | Cursor beta-suffix tests do not author assignWithDepth. |
| GHSA-87X5-VMC3-756J | FALSE_POSITIVE | SYSTEM_FINGERPRINT_WRONG_EDGE | P/F/P/F/P/U/P | Claude adds system_fingerprint; the prompt-list bound arrives later. |
| GHSA-XC48-889X-5QMW | FALSE_POSITIVE | WORKSPACEID_CARRIER_NOT_ENV_DENYLIST | P/F/P/F/P/P/P | gemini-code-assist workspaceId plumbing is not the MCP env denylist. Incomplete rem of CVE-2025-8943 is a different commit. |
| GHSA-JR45-8VMC-QM54 | FALSE_POSITIVE | DELETEAT_TTL_NOT_CACHE_CONTROL_OWS | P/F/P/F/P/U/P | Claude rewrite of determineDeleteAt is not parseCacheControlHeader OWS trimming. |
| GHSA-W62W-66V9-VVGV | FALSE_POSITIVE | NEW_ROUTE_ON_PREEXISTING_UNVALIDATED_MUX | P/F/P/F/P/P/P | GetObjectAttributes is a new caller on the old SkipClean router. The GHSA PoC is generic object GET. |
| GHSA-RQ84-P6RR-VF89 | FALSE_POSITIVE | LOG_ENV_CLEANUP_AND_WRONG_FIX_SHA | P/F/P/F/F/U/P | Candidate drops SRC_LOG_LEVELS. Assigned fixes are an auth refactor, not RFC 7662 introspection. |
| GHSA-F2R8-JV7C-XQMP | FALSE_POSITIVE | CHROMIUM_ROLLER_WRONG_HUNK | P/F/P/F/P/P/P | Same roller SHA as GHSA-4F78; ShowItemInFolder still used OpenPath. Shared SHA is not mechanism equality. |
| GHSA-QHJ8-Q5R6-8Q6J | FALSE_POSITIVE | CHANGELOG_ONLY_FIX_REF | P/F/P/F/F/U/P | Assigned commit-ref only edits CHANGELOG.md and has no AI marker. |
| GHSA-JQ43-27X9-3V86 | FALSE_POSITIVE | SECURITY_FIX_USED_AS_ORIGIN | P/F/P/F/P/U/P | Human SMTP sanitizer is the closure. An AI-agent discovery write-up is not hunk authorship. |
| GHSA-4HX9-48XH-5MXR | FALSE_POSITIVE | SECURITY_FIX_USED_AS_ORIGIN | P/F/P/F/P/U/P | Human LDAP referral fix used as origin. |
| GHSA-RJ4J-2JPH-GG43 | FALSE_POSITIVE | SECURITY_FIX_USED_AS_ORIGIN | P/F/P/F/P/U/P | Human PR 3911 path validation used as origin. |
| GHSA-7C4H-VH2M-743M | FALSE_POSITIVE | SECURITY_FIX_USED_AS_ORIGIN | P/F/P/F/P/U/P | Human community-package version validation used as origin. |
| GHSA-26GQ-GRMH-6XM6 | FALSE_POSITIVE | SECURITY_FIX_USED_AS_ORIGIN | P/F/P/F/P/F/P | Human mermaid dependency bump. Upstream renderer XSS is not an AI gogs origin. |

## Eligible classes that did not land

Root, contributor, new-surface, and explicit incomplete-remediation were considered. None closed all seven gates:

- Flowise looks like residual remediation of CVE-2025-8943, but candidate b5f7fac0 does not rewrite `validateEnvironmentVariables`. The patch-delta rule therefore does not apply, and no `original_vulnerability` block is emitted.
- undici looks like residual remediation of GHSA-pr7r-676h-xcf6, but candidate 90775009 rewrites deleteAt TTL, not the Cache-Control parser.
- SeaweedFS GetObjectAttributes is a new route on a preexisting unvalidated mux. Old-bug preservation / new caller fails but-for at GHSA scope. The first-party PoC is not the `?attributes` verb.
- Kind-2 rows all use the advisory fix commit as the candidate. Partial fixes used as origins are not strict released cases.

## Gate and label accounting

- Identity: 14 PASS.
- AI hunk: 0 PASS, 14 FAIL.
- Topology: 14 PASS. Packet `parent` fields often differed from git first-parent; analysis clones supplied the true `%P`.
- But-for: 0 PASS, 14 FAIL.
- Fix reversal: 12 PASS, 2 FAIL (changelog-only matrix SHA; open-webui assigned refac SHAs).
- Release: 5 PASS, 1 FAIL, 8 UNKNOWN. UNKNOWN means missing local tag binding and was not converted into FAIL except gogs, where the assigned SHA is itself the fix so no AI-containing vulnerable artifact exists.
- Uniqueness: 14 PASS. Canonical84 has none of these identities. The two electron rows share a roller SHA and remain distinct non-countable mechanisms.

Row conservation: 14 assigned = 14 reviewed + 0 unreviewed.

Stored batch28 labels for the eight kind-1 rows were REJECT / NO_BLAME_HUNK_PROOF or SHA_SHARE_WITHOUT_MECHANISM_EQUALITY. This review agrees; disagreement list is empty.

## Claim boundary

A worker FALSE_POSITIVE or PASS is a proposal. L0 remains `autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl` (computed sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`), status HOLD, 84 strict released identities, greater-than-200 unsupported. This directory did not edit that ledger, web data, or any other campaign path.

## Evidence and reproducibility

Primary inputs are `adjudication-4.jsonl` (sha256 `3264d02737cfef400e3e70cd45a6e88c852b46f6d98f3a5320c85af1ca9b563f`), CONTRACT.md, wave2/SPEC.md, and the frozen GitHub-reviewed advisory objects under `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/`. Git parent/candidate/fix objects were read from packet clones under `/home/hanqing/.cache/ghsa200-w3-fetch/` and analysis clones under `/home/hanqing/.cache/cve-analyzer/repos/` and `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/`. Caches were used read-only. No GitHub API, REST, or smart-HTTP fetch was required. No owned temporary clone was created.

Replay commands for every row are in `cases.jsonl` and `replay.txt`.

