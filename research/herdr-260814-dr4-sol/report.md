# Direct-root adjudication: dr-slice-4

## Verdict

All 25 assigned rows are terminal `FALSE_POSITIVE` proposals; this lane proposes zero countable cases. Twenty are wrong causal edges, one Mattermost candidate is a human remediation rather than an origin, one Fiber AI hardening commit follows the actual minimum fix, and three Transformers candidates are post-fix feature members immediately before a release carrier.

The matrix uses gate order `identity / AI hunk / topology / but-for / fix reversal / release / uniqueness`. `UNKNOWN` is retained only where local evidence did not prove candidate containment in a vulnerable release.

## Row-by-row adjudication

| # | GHSA | Gates | Verdict and causal comparison |
|---:|---|---|---|
| 1 | `GHSA-8J3X-M868-CPW8` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Claude is credited only for analysis and test files for three named 2022 CVEs. The candidate changes PQS/GRO/MSI formats; `d4621d4` changes overlapping copy behavior in `src/zipstreamimpl.h`. |
| 2 | `GHSA-PP85-5J63-XPQ3` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. The same candidate never touches `gamessformat.cpp`; `95033d2` fixes the GAMESS use-after-free. Shared security and fuzz-harness files are routing only. |
| 3 | `GHSA-VJG6-GM8M-V5G6` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. The candidate and its AI-scoped fixtures name other CVEs and do not touch `mol2format.cpp`; `4110d59` fixes the MOL2 attribute/value bound. |
| 4 | `GHSA-227R-JM2G-7CP4` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human-authored `e50cd31` improves environment-value redaction. Its child `b39defa` changes the authorization default to `Full` for environment, heapdump, and threaddump. |
| 5 | `GHSA-4VV7-JJ25-4GH6` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human `e1d6d76` disables the extension's install command; `dc812db` sanitizes distinct `clientClassName` and `clientNamespaceName` fields. Copilot appears only on the child fix and cannot transfer backward. |
| 6 | `GHSA-4P3G-4HCJ-WPVX` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human `b4476c2` adds Relevant Digital response-bidder-code behavior. `494ac27` introduces outbound host validation across eleven adapters; same-adapter overlap is not host-sink authorship. |
| 7 | `GHSA-6XJ8-QV9J-XCJQ` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. AI-marked `8f4f7c8` adds gradient colors and never touches `segments/path.go` or the template function map. `88ddbe0` separates trusted/untrusted rendering and closes the path double-evaluation sink. |
| 8 | `GHSA-HM95-JX66-G2GH` | `PASS / FAIL / PASS / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (non_ai_remediation_not_root)`. Human-authored `fda403f` is the redirect-validation remediation; `39bd251` restores mobile redirection while retaining closure. Mattermost Build is release automation, not an AI author. |
| 9 | `GHSA-J828-28RJ-HFHP` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human DeepSeek MTP support changes model configuration and runners; the ReDoS fix changes lora, serving, parser, and benchmark regexes. Generic config overlap is incidental. |
| 10 | `GHSA-W6Q7-J642-7C25` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. The MTP feature never changes `pythonic_tool_parser.py`; `4fc1bf8` replaces the vulnerable nested regex. |
| 11 | `GHSA-56J4-446M-QRF6` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. Mergify's human-authored backport renames a testnet upgrade. `fe67aeb` enforces the fee denomination and wires the v2.2 upgrade; shared upgrade plumbing is not fee-transfer causality. |
| 12 | `GHSA-923M-GV2P-W5QP` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human `c807d9c` fixes signed-cookie salt namespaces; `1721035` strips whitespace in `has_vary_header`. Only pending release-note files overlap. |
| 13 | `GHSA-29JH-8CFQ-RR8X` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human `6082e59` rewrites eventstore owner semantics; `8e82ec1` adds a hardened outbound HTTP client and denylist. Setup overlap is migration routing. |
| 14 | `GHSA-G5H5-M4HM-XJRR` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. The eventstore candidate does not touch JWT IdP validation; `d184e97` adds audience configuration and enforcement. |
| 15 | `GHSA-P543-XPFM-54CP` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human `4795831` fixes a multipart regex ReDoS; `589127f` later bounds preamble accumulation. Same parser and tests do not make the regex patch the buffer origin. |
| 16 | `GHSA-W9PC-FMGC-VXVW` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. The regex hardening does not author the pre-existing in-memory `String` body for non-file fields; the later fix limits buffering. |
| 17 | `GHSA-WPV5-97WM-HP9C` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. The earlier regex syntax fix is distinct from unbounded accumulation while waiting for a terminating multipart header block. |
| 18 | `GHSA-35HP-HQMV-8QG8` | `PASS / FAIL / FAIL / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (ai_post_fix_hardening_not_root)`. Human `0758942` first replaces the path-only cache key with method/query/header/cookie dimensions. AI `047de64` subsequently hardens parsing and delimiters; `050ff1f` further refines delimiter escaping. The minimum fix predates the candidate. |
| 19 | `GHSA-489J-G2VX-39WF` | `PASS / FAIL / FAIL / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (post_fix_release_member)`. Semantic ReDoS fix `126abe3` predates the human Llama 4 merge; the candidate is merely the direct parent of the `0720e20` v4.51.0 release commit. |
| 20 | `GHSA-JJPH-296X-MRCR` | `PASS / FAIL / FAIL / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (post_fix_release_member)`. `126abe3` fixes `dynamic_module_utils.py` before the Llama 4 feature, which never touches that file. Release-carrier ancestry cannot reverse chronology. |
| 21 | `GHSA-Q2WP-RJMX-X6X9` | `PASS / FAIL / FAIL / FAIL / PASS / FAIL / PASS` | `FALSE_POSITIVE (post_fix_release_member)`. The configuration-file regex fix predates the Llama 4 feature; generic configuration and release overlap is not root authorship. |
| 22 | `GHSA-GPFC-MPH4-QM24` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. The candidate changes raw artifact-manager and process-tracker behavior. `21e7fd7` adds artifact permission declarations and server-side verification; Snyk automation is not a generative-AI marker. |
| 23 | `GHSA-M964-FJRH-XXQ2` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human browser-side auto-layout changes are disjoint from `RaftSyncMessageSerializer`; only bilingual changelogs overlap. |
| 24 | `GHSA-R995-Q44H-HR64` | `PASS / FAIL / PASS / FAIL / FAIL / UNKNOWN / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human `f9336e0` fixes chunk-extension smuggling; `ee60354` later rejects bare CR/LF/NUL in request and header lines. Same family and file are distinct parser invariants. |
| 25 | `GHSA-4565-R4X7-HG8J` | `PASS / FAIL / PASS / FAIL / FAIL / FAIL / PASS` | `FALSE_POSITIVE (wrong_edge)`. Human `11e19f2` validates mirror remote addresses against SSRF; `1fdc9cc` bounds collaborator access mode in database and route code. |

## Evidence and controls

- All 25 first-party advisory JSON objects were read from the local advisory-database clone at `a42c436870111aa3f221257c9d56126a93173ccc`.
- Candidate/fix messages, paths, ancestry, and available hunks came from local commit pools and read-only worker clones. Every assigned candidate is an ancestor of its assigned ref; the Fiber and Transformers minimum-fix ordering was checked separately.
- The canonical84 ledger was searched by identity and mechanism; none of these rows collides. Its observed SHA-256 is `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`.
- No row receives `AI_INCOMPLETE_REMEDIATION`, so no `original_vulnerability` block is applicable.
- No GitHub API was used, and no write was made outside this lane.
