# Wave 2 adjudication report: `adjudication-1.jsonl`

## Verdict first

All 15 assigned rows were adjudicated against local first-party advisory objects and local Git history.

- **1 NARROW**: `GHSA-282G-FHMX-XF54` (ZITADEL), limited to the AI-added generic `UpdateUser` surface. All seven gates pass at that narrowed scope. This is a worker proposal, not canonical admission.
- **1 UNKNOWN**: `GHSA-4RMQ-MC2C-R495` (Babylon). The candidate commit contains the exact vulnerable predicate and the fix reverses it, but the candidate is a 249-file backport/squash with many human coauthors and one generic Copilot trailer. AI member-to-hunk topology is unresolved, so `ai_hunk_gate` and `topology_gate` remain `UNKNOWN` and the row is non-terminal.
- **13 FALSE_POSITIVE**: primary diffs positively show a wrong edge, old-bug preservation, sibling change, client/server scope mismatch, test-only change, or refactor carrier. These are not failures inferred from missing evidence.
- **0 CONFIRM**, **0 AI_INCOMPLETE_REMEDIATION**, and **1 countable proposal** at the narrowed ZITADEL scope.

The packet delta is **+1 proposal only**. The current claim source remains immutable L0 `canonical84` at 84 strict released identities, status **HOLD**; more than 200 remains unsupported.

## Gate summary

- `identity_gate`: `PASS` for all 15. Every local advisory object is active, GitHub-reviewed, names the repository and public mechanism, and supplies affected/fixed package ranges.
- `ai_hunk_gate`: `PASS` for the narrowed ZITADEL `UpdateUser` surface and for the exact mechanically renamed Gogs symlink-check line; `UNKNOWN` for Babylon because the generic squash trailer cannot be assigned to the vulnerable member hunk; `FAIL` for the other 12 because source diffs positively disprove the proposed candidate edge. The Gogs line still fails `but_for_gate` because the rename preserves its semantics.
- `topology_gate`: `PASS` for 13 rows where the candidate, parent, and fix relationship is resolved, even when that resolution proves a wrong edge; `UNKNOWN` for Babylon; and `FAIL` for Coder because its many-author cherry-pick carrier cannot transfer the generic Copilot trailer to the security hunk.
- `but_for_gate`: `PASS` for narrowed ZITADEL and for Babylon's commit-level delta; `FAIL` for the 13 false positives. Removing those candidates does not eliminate or materially shrink the advisory mechanism.
- `fix_reversal_gate`: `PASS` for all 15 because each minimum first-party fix closes the advisory invariant. That fact does not turn an unrelated candidate into a causal origin; the decisive candidate-specific gates still fail.
- `release_gate`: `PASS` for 9 rows with both candidate-containing vulnerable and fix-containing released artifacts, and `FAIL` for 6 without candidate-specific pre-closure release containment. In particular, ZITADEL passes at the narrowed v4 scope (`v4.0.0` through `v4.11.0`, fixed by the patch-equivalent commit in `v4.11.1`) and Babylon passes for `v4.0.0`/`v4.1.0`, fixed in `v4.2.0`. Release containment does not rescue a failed causal gate.
- `uniqueness_gate`: no assigned GHSA identity overlaps L0 `canonical84`. The proposed ZITADEL mechanism and the Babylon unresolved mechanism are distinct from the frozen identities; uniqueness does not compensate for any failed or unknown causal gate.

`HIGH` confidence on a false positive means the exact proposed edge was disproved. It does not assert that no other AI-authored origin could ever be found. `UNKNOWN` is retained wherever attribution evidence is genuinely missing.

## Per-row adjudication

| # | Case and repository | Verdict / class | Candidate-to-fix evidence and failed or open gates |
| ---: | --- | --- | --- |
| 1 | `GHSA-J6XF-JWRJ-V5QP` — `coder/coder` | **FALSE_POSITIVE** — release carrier / wrong edge | `e5a74a77` is a broad “pull in cherry picks” carrier with many human coauthors and a Copilot trailer. Its delta contains no relevant session-token expiry hunk in `coderd/apikey.go`, `coderd/provisionerdserver/provisionerdserver.go`, or `coderd/database/queries/apikeys.sql`; `20d67d7d` adds that remediation. `ai_hunk_gate` and `but_for_gate` fail; carrier attribution also prevents topology closure. |
| 2 | `GHSA-9GQJ-5W7C-VX47` — `anthropic-experimental/sandbox-runtime` | **FALSE_POSITIVE** — old behavior preserved | `23e9e226` is explicitly Claude-attributed and adds seccomp/Unix-socket hardening, but its parent already drives Linux network restriction independently of the empty-domain residual, and the candidate preserves that logic. `bea2930c` later fixes an intervening empty-`allowedDomains` path by distinguishing “restriction required” from “proxy required.” The proposed candidate is not the advisory origin or an incomplete remediation. `ai_hunk_gate` and `but_for_gate` fail for this mechanism. |
| 3 | `GHSA-4RMQ-MC2C-R495` — `babylonlabs-io/babylon` | **UNKNOWN** — attribution topology unresolved | `2bd95856` creates `x/costaking/keeper/hooks_finality.go`; its `AfterBtcDelegationUnbonded` returns on `!isFpActiveInPrevSet || !isFpActiveInCurrSet`, leaving phantom stake when unbonding and FP deactivation coincide. `e65c3a55` changes the exact predicate to `!isFpActiveInPrevSet`. Candidate-only release tags include `v4.0.0` and `v4.1.0`; fixed tags start at `v4.2.0`. Identity, commit-level but-for, reversal, release, and uniqueness pass. `ai_hunk_gate` and `topology_gate` remain `UNKNOWN` because the huge backport/squash does not map its generic Copilot trailer to this member hunk. |
| 4 | `GHSA-G754-HX8W-X2G6` — `quic-go/quic-go` | **FALSE_POSITIVE** — old bug preservation | `b7886d5c` updates QPACK and related HTTP/3 code, but the advisory affects the pre-existing absence of a decoded field-section limit (`introduced: 0`). `5b2d2129` adds the limit; no candidate-authored vulnerable hunk is reversed. `ai_hunk_gate` and `but_for_gate` fail. |
| 5 | `GHSA-3CPP-FV95-MPR5` — `shopware/shopware` | **FALSE_POSITIVE** — test-only edge | `543eb637` adds document snapshot tests and test support. The SSRF repair `f32737b3` changes production document templates to sanitize invoice rendering. Test-file overlap is not production hunk authorship. `ai_hunk_gate` and `but_for_gate` fail. |
| 6 | `GHSA-8XQ3-W9FX-74RV` — `silverbucket/webfinger.js` | **FALSE_POSITIVE** — test/tooling edge | `ff1abb86` adds browser/integration infrastructure, tests, build files, and documentation; it does not change the vulnerable `src/webfinger.ts` lookup logic. `b5f2f2c9` changes that source file to close blind SSRF. `ai_hunk_gate` and `but_for_gate` fail. |
| 7 | `GHSA-J975-95F5-7WQH` — `modelcontextprotocol/python-sdk` | **FALSE_POSITIVE** — sibling same-file change | The packet's explicit candidate marker does not map the advisory hunk. `7901552e` sends `CONNECTION_CLOSED` errors to pending requests after stream shutdown, while `7b420656` catches `ClosedResourceError` and protects exception cleanup in the receive loop. Same-file proximity does not establish the advisory edge. `ai_hunk_gate` and `but_for_gate` fail. |
| 8 | `GHSA-3QHF-M339-9G5V` — `modelcontextprotocol/python-sdk` | **FALSE_POSITIVE** — wrong same-file edge | `568cbd1a` is Claude-attributed but moves incoming-message handling from a shared memory stream to subclass dispatch. `29c69e6a` catches request-validation exceptions and returns `INVALID_PARAMS`. The two-line blame route is not the malformed-request DoS origin. `ai_hunk_gate` and `but_for_gate` fail. |
| 9 | `GHSA-WF93-3GHH-H389` — `OpenListTeam/OpenList` | **FALSE_POSITIVE** — unrelated config-adjacent change | `016ed90e` implements stream-cache buffer freeing and touches configuration files for that feature. It does not introduce `TlsInsecureSkipVerify: true`; `e3c664f8` reverses that pre-existing default. `ai_hunk_gate` and `but_for_gate` fail. |
| 10 | `GHSA-282G-FHMX-XF54` — `zitadel/zitadel` | **NARROW** — `AI_NEW_SURFACE_CONTRIBUTOR` | `8fc11a73` is a single-parent Copilot-coauthored feature commit that creates `internal/api/grpc/user/v2/human.go`, including the generic `updateUserTypeHuman` route, and maps client-controlled `IsVerified` into `command.Email.Verified` and `command.Phone.Verified`. The older `UpdateHumanUser` path predates it, so broad root attribution is rejected; removing this commit does eliminate the new generic `UpdateUser` surface. `02615362` adds a shared permission requirement whenever verified email/phone is supplied; its patch-equivalent `288f064e` is in `v4.11.1`. All seven gates pass only at this explicit narrowed surface. |
| 11 | `GHSA-FC6G-2GCP-2QRQ` — `rustfs/rustfs` | **FALSE_POSITIVE** — dependency/carrier edge | `0da943a6` is a Dependabot dependency bump with a Copilot trailer and broad bundled changes, but it does not author the vulnerable `rustfs/src/auth.rs` trust of `X-Forwarded-For`/`X-Real-IP`. `b4ba62fa` changes the actual SourceIp authorization path. `ai_hunk_gate` and `but_for_gate` fail. |
| 12 | `GHSA-89MR-XQFV-758M` — `gogs/gogs` | **FALSE_POSITIVE** — semantics-preserving rename | `36d56d55` mechanically renames `osutil.IsSymlink` to `osx.IsSymlink` on the exact blamed line in `internal/database/repo_editor.go`, so hunk attribution and topology are resolved. The leaf-only behavior predates and survives the rename; `04cb8afb` replaces it with full-path walking. `ai_hunk_gate` and `topology_gate` pass, but `but_for_gate` fails decisively. |
| 13 | `GHSA-WV27-2VQP-J7G5` — `gogs/gogs` | **FALSE_POSITIVE** — rename carrier / old behavior | The same `36d56d55` package rename does not create mirror-settings local repository import. Its one-parent topology is resolved, but no relevant candidate hunk exists; `11e19f28` adds remote-address validation on mirror updates. `ai_hunk_gate` and `but_for_gate` fail; `topology_gate` passes. |
| 14 | `GHSA-35HP-HQMV-8QG8` — `gofiber/fiber` | **FALSE_POSITIVE** — old cache-key bug preserved | The parent of Copilot-agent commit `27d359e8` already uses a path-only default cache key and ignores query values. The candidate wraps/bounds key segments but preserves that omission. `050ff1ff`/`9a0d12c0` harden key construction and query handling. `ai_hunk_gate` and `but_for_gate` fail; this is not incomplete remediation. |
| 15 | `GHSA-5MWJ-V5JW-5C97` — `lobehub/lobehub` | **FALSE_POSITIVE** — client copy of old server bug | `e67bcb25` adds a Claude-coauthored CLI XOR-auth helper and related tests. The exploitable server-side `checkAuth` apiKey/XOR fallback already exists. `3327b293` removes the server fallback and also deletes the CLI copy. Removing the candidate does not eliminate the server bypass. `ai_hunk_gate` and `but_for_gate` fail. |

## Evidence paths and provenance

Primary input and contract:

- `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-1.jsonl` — SHA-256 `cb782f031b5a707bfb8d7b63cc1710f6ad0341096cf37bc76ed6b0031ad0be42`
- `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md` — SHA-256 `94ba89b0ec0bb6703e7c5fbc33e5b35eb313ca243ec18add357f51685dcc06d1`
- `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md` — SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- `docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md` — SHA-256 `70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f`
- `autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl` — verified L0 SHA-256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`

First-party advisory objects are under:

- `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/`

Candidate and fix evidence came from the complete local caches under:

- `/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/`
- `/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/`
- `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/`
- `/home/hanqing/.cache/cve-analyzer/repos/` where an alternate local clone supplied a parent/fix blob absent from a promisor cache

Every advisory fix reference was resolved locally. `GIT_NO_LAZY_FETCH=1` was used for Git inspection. No GitHub API or REST call was made, no explicit smart-HTTP fetch was run, and no network fetch succeeded.

The two non-false-positive rows have these exact replay anchors:

- **Babylon:** complete clone `/home/hanqing/.cache/cve-analyzer/repos/babylonlabs-io_babylon`; candidate parent `4bfae6d85240af95e4ab37d64c12f331e3c2f91a`; candidate `2bd9585607bd7b1c0905d21b92bcdb6d4c03bf36`; fix `e65c3a55a398a403103f1b089cf76f0d4befc7a0`; advisory object `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2025/12/GHSA-4rmq-mc2c-r495/GHSA-4rmq-mc2c-r495.json`. The candidate-parent diff creates `x/costaking/keeper/hooks_finality.go`; in `AfterBtcDelegationUnbonded`, the early-return predicate is `!isFpActiveInPrevSet || !isFpActiveInCurrSet`. The fix diff removes the current-set term. These exact diffs close commit-level origin and reversal, but the squash still does not attribute that member hunk to the generic Copilot trailer.
- **ZITADEL:** complete clone `/home/hanqing/.cache/cve-analyzer/repos/zitadel_zitadel`; candidate parent `e2a61a60029783f9a29bf7b71f2ac3d8fd39bb78`; candidate `8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f`; fix `0261536243e500dccfd8c7f547d592c822478327`; patch-equivalent released commit `288f064e3ca990fde195e9a7ab363616e4fccdf1`; advisory object `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-282g-fhmx-xf54/GHSA-282g-fhmx-xf54.json`. The parent already contains `UpdateHumanUser` in `internal/api/grpc/user/v2/user.go`, so the candidate is not the advisory's broad origin. Its additive diff creates the generic `UpdateUser` handling in `internal/api/grpc/user/v2/human.go` and forwards both email and phone `IsVerified` values. The advisory spans older branches (`2.43.0` to `3.4.7`, the v4 line from `4.0.0` to `4.11.1`, and a legacy pseudo-version range), while the countable proposal is restricted to the candidate-added v4 `UpdateUser` surface. The fix makes verified email or phone require write permission in shared command handling.

## Stored-label disagreements

The input packet stores routing evidence, not causal verdicts. Its `best.blame_lines` values therefore required independent interpretation:

- Zero blamed lines were not treated as negative evidence. Direct additive diffs recovered Babylon's exact vulnerable function and ZITADEL's new vulnerable route despite `blame_lines: 0`.
- Positive blamed lines did not automatically pass causality. The MCP, Gogs, Fiber, and LobeHub candidates touch the same file or transported line, but primary diffs show sibling behavior, refactor carriage, old-bug preservation, or a client/server scope mismatch.
- The packet-provided marker for `GHSA-J975-95F5-7WQH` was not transferred from a sibling same-file change to the advisory hunk.
- The Babylon packet's “atomic first parent” flag does not resolve member authorship inside a large backport/squash. That disagreement is preserved as `UNKNOWN`, not forced to `FAIL` or `FALSE_POSITIVE`.

## Original-vulnerability boundary

No row is labeled `AI_INCOMPLETE_REMEDIATION`, so no `original_vulnerability` block is emitted or invented.

The closest-looking rows do not meet the patch-delta rule:

- Sandbox Runtime's AI change adds Unix-socket/seccomp hardening but does not introduce or partially repair the later empty-`allowedDomains` mechanism; the relevant behavior already exists in its parent and the final patch addresses a different intervening branch of logic.
- Fiber's AI change preserves an older path-only cache key; it is not a security remediation that omitted the query case.
- Babylon is a feature/backport origin candidate, not an attempted remediation of a separately identified original advisory. Its unresolved issue is AI member attribution, not missing original-vulnerability metadata.
