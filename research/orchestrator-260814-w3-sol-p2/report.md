# Wave 2 adjudication report: `adjudication-2.jsonl`

## Verdict first

All 15 assigned rows were adjudicated against first-party advisory objects and candidate, parent, and minimum-fix Git evidence.

- **1 NARROW**: `GHSA-45Q4-X4R9-8FQJ` (Vikunja), restricted to the AI-added self-assignment email body that interpolates an unescaped doer display name. All seven gates pass at that scope. This is one countable worker proposal, not canonical admission.
- **1 UNKNOWN**: `GHSA-X2HW-PX52-WP4M` (Soroban SDK). The candidate adds the vulnerable BN254 `Fr` implementation and the fix canonically reduces it, but the 183-file squash has seven human coauthors plus one generic Copilot trailer. `ai_hunk_gate` and `topology_gate` remain `UNKNOWN`; the row is non-terminal.
- **13 FALSE_POSITIVE**: exact diffs show wrong edges, old-bug preservation, a copied weak PRNG, comments or formatting only, an unrelated sibling security fix, or an unreleased attempted guard. No false positive is inferred from absent evidence.
- **0 CONFIRM** and **0 AI_INCOMPLETE_REMEDIATION**.

The packet contributes **+1 proposal only**. L0 remains the immutable `canonical84` ledger: 84 strict released identities, status **HOLD**, and no support for a greater-than-200 claim.

There is a frozen provenance discrepancy: the canonical ledger recomputes to SHA-256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`, while `docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md` prints `a9b23a7ca39104f851b684a4089fa58f43887bb379895b68f6306c47d969ec06`. Neither frozen file was edited; this report uses the recomputed file hash and keeps the mismatch explicit.

## Seven-gate result

| Gate | PASS | FAIL | UNKNOWN | Boundary |
| --- | ---: | ---: | ---: | --- |
| `identity_gate` | 15 | 0 | 0 | Every advisory object is active, GitHub-reviewed, binds the repository and mechanism, and publishes affected/fixed package ranges plus first-party repository references. |
| `ai_hunk_gate` | 2 | 12 | 1 | Vikunja passes at the narrow self-assignment sink. OpenSSL passes hunk authorship because the refactor adds the weak-PRNG lines, but that does not establish causal novelty. Soroban's squash-member attribution remains unknown. |
| `topology_gate` | 14 | 0 | 1 | Candidate and fix ancestry is resolved except for Soroban's squash-member attribution. Copy, carrier, formatter, and sibling-path topology does not transfer causality. |
| `but_for_gate` | 2 | 13 | 0 | Vikunja and Soroban pass. Every false positive fails; notably, removing OpenSSL's refactor restores the same weak PRNG at its old path. |
| `fix_reversal_gate` | 15 | 0 | 0 | The minimum fixes identify and amend the advisory mechanism, including on rows where the proposed AI candidate is unrelated. |
| `release_gate` | 10 | 2 | 3 | Vikunja, Soroban, Ferret, and Ech0 have resolved candidate/fix release windows. OpenC3 and OpenSSL fail because their candidate and closure first publish together. Ruby JWT, Aegra, and compliance-trestle remain `UNKNOWN`; their false-positive verdicts are independently closed by causal gates. |
| `uniqueness_gate` | 15 | 0 | 0 | No assigned GHSA identity overlaps L0 `canonical84`; uniqueness does not rescue a failed causal edge. |

Fourteen rows are terminal. Soroban is the sole non-terminal row because two gates remain `UNKNOWN`.

`HIGH` confidence on a false positive means the proposed candidate edge is disproved. It does not claim that no other AI-authored origin exists outside this assigned candidate pair.

## Per-row adjudication

Gate order below is identity / AI hunk / topology / but-for / fix reversal / release / uniqueness.

| # | GHSA | Gate matrix |
| ---: | --- | --- |
| 1 | `GHSA-J6V5-G24H-VG4J` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` |
| 2 | `GHSA-4JVX-93H3-F45H` | `PASS / FAIL / PASS / FAIL / PASS / FAIL / PASS` |
| 3 | `GHSA-45Q4-X4R9-8FQJ` | `PASS / PASS / PASS / PASS / PASS / PASS / PASS` |
| 4 | `GHSA-VFGX-5Q85-58Q3` | `PASS / PASS / PASS / FAIL / PASS / FAIL / PASS` |
| 5 | `GHSA-4MPH-V827-F877` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` |
| 6 | `GHSA-X2HW-PX52-WP4M` | `PASS / UNKNOWN / UNKNOWN / PASS / PASS / PASS / PASS` |
| 7 | `GHSA-HQJG-PWW4-PCGQ` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` |
| 8 | `GHSA-3RMJ-9M5H-8FPV` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` |
| 9 | `GHSA-JMH7-G254-2CQ9` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` |
| 10 | `GHSA-C32J-VQHX-RX3X` | `PASS / FAIL / PASS / FAIL / PASS / UNKNOWN / PASS` |
| 11 | `GHSA-M98R-6667-4WQ7` | `PASS / FAIL / PASS / FAIL / PASS / UNKNOWN / PASS` |
| 12 | `GHSA-G3VG-VX23-3858` | `PASS / FAIL / PASS / FAIL / PASS / UNKNOWN / PASS` |
| 13 | `GHSA-FQ7H-9X26-6J22` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` |
| 14 | `GHSA-FPW6-HRG5-Q5X5` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` |
| 15 | `GHSA-QX5F-GHC2-7G5C` | `PASS / FAIL / PASS / FAIL / PASS / PASS / PASS` |

| # | Case and repository | Verdict / class | Candidate-to-fix evidence and decisive gates |
| ---: | --- | --- | --- |
| 1 | `GHSA-J6V5-G24H-VG4J` — `MontFerret/ferret` | **FALSE_POSITIVE** — modules refactor / wrong edge | `a252ad8e` (actual parent `2d44ff84`) changes engine/module lifecycle code and FS library tests, but not the vulnerable `pkg/stdlib/io/fs/write.go` or `read.go` implementations. `160ebad6` changes those implementations from direct `os.OpenFile`/`os.ReadFile` calls to the context-provided filesystem boundary. The candidate appears in `v2.0.0-alpha.1` and the fix in `v2.0.0-alpha.4`, so release passes; `ai_hunk_gate` and `but_for_gate` fail. |
| 2 | `GHSA-4JVX-93H3-F45H` — `OpenC3/cosmos` | **FALSE_POSITIVE** — unreleased attempted remediation | AI-marked `9957a9fa` (actual parent `67fb8405`) is an explicit security attempt: it adds a denylist rejecting `/`, `\\`, and `..`. `e6efccbd` later replaces that denylist with an allowlist. The v7 candidate and closure first occur together in fixed `v7.0.0-rc3`; the v6 equivalents (`79b02d99`, `f6027d39`, `6e27b09a`) likewise first occur together in fixed `v6.10.5`. There is no released residual state after the AI attempt, so the incomplete-remediation `release_gate` fails; the candidate is a fix component, not the advisory origin. |
| 3 | `GHSA-45Q4-X4R9-8FQJ` — `go-vikunja/vikunja` | **NARROW** — `AI_NEW_SURFACE_CONTRIBUTOR` | Copilot-authored `5f795bb5` (actual parent `d5a46310`) creates the self-assignment branch in `pkg/models/notifications.go`; its email body calls `Line(... n.Doer.GetName())` without Markdown escaping. Fix-parent blame assigns that exact branch and line to Copilot. `0f3730d0` wraps the doer name in `notifications.EscapeMarkdown` while closing the advisory's older notification sinks. The candidate is in signed `v2.2.2`, and the fix is an ancestor of signed `v2.3.0`. Removing the candidate eliminates this new self-assignment surface, so all seven gates pass only at the stated narrow scope. |
| 4 | `GHSA-VFGX-5Q85-58Q3` — `jahlives/openssl_encrypt` | **FALSE_POSITIVE** — copied old vulnerable code | `990c09c4` (actual parent `031f34e8`) moves the steganography implementation from `modules/steganography/` to `plugins/steganography/`. Its new `core/utils.py` contains the exact weak `random.seed(seed)` / `random.sample(...)` sequence, but the deleted old module already contains the same mechanism. `09e96e09` replaces it with HMAC-SHA256-based shuffling. `ai_hunk_gate` and copy topology pass, but `but_for_gate` fails because removing the refactor restores the same bug. Candidate and fix first appear together in `v1.4.0`, so `release_gate` fails as well. |
| 5 | `GHSA-4MPH-V827-F877` — `locutusjs/locutus` | **FALSE_POSITIVE** — untouched sibling function | AI-marked `042af9ca` hardens `parse_str` against an `includes()` tampering bypass for earlier `GHSA-RXRV-835Q-V5MH`. The current advisory explicitly concerns distinct `unserialize()` assignments in `src/php/var/unserialize.ts`, which the candidate does not touch. `345a6211` adds `setUnserializedProperty` and applies it at both current sinks. `ai_hunk_gate` and `but_for_gate` fail for this GHSA; a fix to `parse_str` is not incomplete remediation of untouched `unserialize`. |
| 6 | `GHSA-X2HW-PX52-WP4M` — `stellar/rs-soroban-sdk` | **UNKNOWN** — squash member attribution unresolved | `ecad5add` (actual parent `a60b7e8f`) creates `soroban-sdk/src/crypto/bn254.rs`, including unreduced `Fr(U256)` constructors and raw-representation `PartialEq`. `082424b3` routes construction through modulo-`r` reduction; candidate-only tags start at `v25.0.0`, and fixed tags at `v25.3.0`. Identity, commit-level but-for, reversal, release, and uniqueness pass. The 183-file squash has seven human coauthors and a generic Copilot trailer but no local member-to-hunk map, so `ai_hunk_gate` and `topology_gate` remain `UNKNOWN`. |
| 7 | `GHSA-HQJG-PWW4-PCGQ` — `google/clasp` | **FALSE_POSITIVE** — documentation-only same-file touch | Jules-marked `9c141469` (actual parent `1883e4d4`) adds JSDoc and inline comments to `src/core/files.ts`; it does not change path construction. `ba6bd666` adds `isInside()` and rejects remote filenames resolving outside the project content directory. `ai_hunk_gate` and `but_for_gate` fail. |
| 8 | `GHSA-3RMJ-9M5H-8FPV` — `withastro/astro` | **FALSE_POSITIVE** — old request-body bug preserved | `336b0033` (actual parent `7ff7b116`) changes server-island encryption and validation, but both parent and candidate still execute `await request.text()` followed by `JSON.parse()` with no body limit. `f9ee8685` adds `readBodyWithLimit` and the `serverIslandBodySizeLimit` manifest/config field. `ai_hunk_gate` and `but_for_gate` fail; this is not an incomplete body-limit remediation. |
| 9 | `GHSA-JMH7-G254-2CQ9` — `gradio-app/gradio` | **FALSE_POSITIVE** — release carrier / old proxy trust | `029034f7` (actual parent `e05eb8df`) is a 1,264-file Gradio 6 carrier. It preserves the pre-existing `proxy_urls` host trust and proxy route, changing adjacent token/context code. `fc7c01ea` permits only known `.hf.space` proxy hosts and rejects other hosts in `build_proxy_request`. Same-file proximity and one blamed line do not establish origin; `ai_hunk_gate` and `but_for_gate` fail. |
| 10 | `GHSA-C32J-VQHX-RX3X` — `jwt/ruby-jwt` | **FALSE_POSITIVE** — version/RSA compatibility edge | `3a31a200` (actual parent `8d21f952`) updates RSA OpenSSL compatibility, tests, changelog, and the gem version. It does not change `lib/jwt/jwa/hmac.rb`. `db560b76` adds the nil/empty HMAC-key rejection that closes the advisory. `ai_hunk_gate` and `but_for_gate` fail. |
| 11 | `GHSA-M98R-6667-4WQ7` — `aegra/aegra` | **FALSE_POSITIVE** — same-file wrong edge | `044d0273` (actual parent `717fc702`) removes dead imports/reexports from `api/runs.py` and removes a broad `except Exception` from `wait_for_run`; it does not create the missing ownership check. `e1b20422` imports `ThreadORM` and adds `user_id` ownership checks to all three affected run endpoints. Exact local parent diffs positively disprove the candidate edge, so `ai_hunk_gate` and `but_for_gate` fail. |
| 12 | `GHSA-G3VG-VX23-3858` — `oscal-compass/compliance-trestle` | **FALSE_POSITIVE** — formatter/build carrier | `f85944cf` (actual parent `70747217`) migrates the build to Hatch and mechanically reformats `trestle/core/remote/cache.py`; the vulnerable `path_parent` construction changes only slice whitespace and retains `..`. Minimum fix `89f4e53d` adds path validation, cache-boundary enforcement, and tests. `ai_hunk_gate` and `but_for_gate` fail. |
| 13 | `GHSA-FQ7H-9X26-6J22` — `external-secrets/external-secrets` | **FALSE_POSITIVE** — license-header carrier | `472acbb5` (actual parent `c4be01b8`) mechanically updates headers/formatting across 572 files. In both ExternalSecret validators, the only candidate changes are copyright year and indentation. `4ddd240a` adds `validatePrivilegedTemplate` to reject service-account and bootstrap-token secret combinations. `ai_hunk_gate` and `but_for_gate` fail. |
| 14 | `GHSA-FPW6-HRG5-Q5X5` — `lin-snow/Ech0` | **FALSE_POSITIVE** — SPDX-only carrier | `2a5b03a7` (actual parent `d5c361e8`) prepends SPDX/copyright headers; the logout, JTI blacklist, and token-deletion behavior remains unchanged. `eab62379` adds nil-expiry handling, persistent revocation, and deletion-time JTI blacklisting. The candidate appears in `v4.7.0` and the fix in `v4.7.3`, so release passes; `ai_hunk_gate` and `but_for_gate` fail. |
| 15 | `GHSA-QX5F-GHC2-7G5C` — `ethyca/fides` | **FALSE_POSITIVE** — old duplicate-approval path preserved | `ae74363d` (actual parent `32f1a958`) adds pre-approval webhook states and UI. Its parent already shows actions for `PrivacyRequestStatus.DUPLICATE` and the service already permits duplicate approval; the candidate only adds two pre-approval statuses. `e7a6527b` blocks approval when a duplicate is unverified and verification is required; `0e320b20` closes the related identity-verification DoS. `ai_hunk_gate` and `but_for_gate` fail for the identity-bypass origin. |

## Evidence and replay boundary

Primary inputs:

- `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-2.jsonl` — SHA-256 `27b72afa0995d061aa0e489a3342281a8135657a8ff9cb7170724aac25278d46`
- `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md` — SHA-256 `94ba89b0ec0bb6703e7c5fbc33e5b35eb313ca243ec18add357f51685dcc06d1`
- `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md` — SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- `docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md` — SHA-256 `70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f`
- `autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl` — recomputed SHA-256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`

First-party advisory objects are under `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/`. Candidate and fix evidence came from these complete local clones:

- `/home/hanqing/.cache/cve-analyzer/repos/github.com_montferret_ferret`
- `/home/hanqing/.cache/cve-analyzer/repos/openc3_cosmos`
- `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja`
- `/home/hanqing/.cache/cve-analyzer/repos/github.com_jahlives_openssl_encrypt`
- `/home/hanqing/.cache/cve-analyzer/repos/locutusjs_locutus`
- `/home/hanqing/.cache/cve-analyzer/repos/stellar_rs-soroban-sdk`
- `/home/hanqing/.cache/cve-analyzer/repos/google_clasp`
- `/home/hanqing/.cache/cve-analyzer/repos/withastro_astro`
- `/home/hanqing/.cache/cve-analyzer/repos/gradio-app_gradio`
- `/home/hanqing/.cache/cve-analyzer/repos/jwt_ruby-jwt`
- `/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/aegra__aegra`
- `/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/oscal-compass__compliance-trestle`
- `/home/hanqing/.cache/cve-analyzer/repos/external-secrets_external-secrets`
- `/home/hanqing/.cache/cve-analyzer/repos/github.com_lin-snow_ech0`
- `/home/hanqing/.cache/cve-analyzer/repos/ethyca_fides`

Promisor caches were always read with `GIT_NO_LAZY_FETCH=1`. The report worker made no network call and no GitHub API or REST call. The final machine record reports three bounded smart-HTTP fetches by the leader into temporary evidence repositories for Aegra, OpenSSL, and Vikunja. The Vikunja depth-500 repository proves `0f3730d0` is an ancestor of signed `v2.3.0` tag commit `28b53783`; this report also read the already-present Aegra and Vikunja repositories at `/tmp/ghsa-p2-aegra-evidence` and `/tmp/ghsa-p2-vikunja-evidence` where local promisor caches lacked individual objects.

## Stored routing fields and causal evidence

The packets contain no stored terminal adjudication labels, so there are no stored-label disagreements to report. Their routing hints still require qualification:

- Every packet's `best.parent` differs from the candidate commit's actual Git parent; those stored values correspond to later fix-side topology. This report uses the parent read from each candidate commit object and does not treat `atomic_first_parent` as a member-attribution result.
- `blame_lines: 0` is not negative evidence. Additive diff inspection recovers Soroban's newly created vulnerable BN254 file, but the generic squash trailer still cannot be assigned to that member hunk.
- Vikunja's one blamed line is useful only after the exact diff and fix-parent blame are read: it supports the narrow doer-name body sink, not broad authorship of all task-title notification sinks.
- Same-file or same-line proximity is rejected for Gradio, Astro, Aegra, and compliance-trestle because the candidate preserves, reformats, or changes behavior adjacent to the actual invariant.
- A security-themed AI commit is not automatically causal. OpenC3 is an unreleased fix attempt, and Locutus repairs a different function and earlier advisory.

## Original-vulnerability boundary

No row is labeled `AI_INCOMPLETE_REMEDIATION`, so no `original_vulnerability` block is emitted or invented.

The closest lookalikes fail the contract for concrete reasons:

- **OpenC3:** `9957a9fa` is a real AI-authored security attempt and `e6efccbd` amends its denylist, but no released artifact contains the attempted guard without the final closure. Both branches first publish the attempt and closure together in fixed releases.
- **Locutus:** `042af9ca` remediates earlier `GHSA-RXRV-835Q-V5MH` in `parse_str`. The current GHSA explicitly identifies untouched sibling function `unserialize`; `345a6211` repairs that separate sink. This is the contract's “fix surface A, later fix pre-existing surface B” exclusion.
- **OpenSSL:** the AI refactor copies a weak PRNG from the old module into the plugin path. It is a preservation/move, not an attempted security boundary with an omitted residual case.

## Remaining question and leader action

Only Soroban remains evidentially open. Admission would require first-party member evidence assigning the BN254 `Fr` hunk inside `ecad5add` to Copilot; the squash trailer and commit-level blame cannot supply that mapping. Until then the row must remain `UNKNOWN`, and the single Vikunja PASS remains a proposal pending independent leader replay.
