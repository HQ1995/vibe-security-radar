# Wave-2 slice-01 kind-1 adjudication (grok-4.6 high)

Owner: autoresearch/herdr-260814-w2-unknown9-grok46-high/. Proposal only. Assigned slice-01.jsonl, 30 kind-1 directroot rows. No expansion. No GitHub API. Unclosed gates stay UNKNOWN with terminal=false. Missing evidence is not converted into FAIL except where local file-set authorship was independently disproved.

## Verdict-first

Reviewed 30/30. CONFIRM 0, NARROW 0, FALSE_POSITIVE 4, UNKNOWN 26. terminal_true=4 terminal_false=26. countable_proposal=0. Canonical ledger was not edited. Publication and greater-than-200 stay HOLD.

| # | Case | Repo | Verdict | Conf | Failing | Open | Notes |
| ---: | --- | --- | --- | --- | --- | --- | --- |
| 1 | GHSA-J6XF-JWRJ-V5QP | coder/coder | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Explicit relevant-hunk origin, but-for, fix-reversal, and release containment were not fully closed from local replay. |
| 2 | GHSA-9GQJ-5W7C-VX47 | anthropic-experimental/sandbox-runtime | UNKNOWN | MEDIUM | none | identity_gate, but_for_gate, fix_reversal_gate, release_gate | Claude-authored linux sandbox files overlap the empty-allowedDomains fix. but_for/fix_reversal/release not independently closed from hunk/tag replay. |
| 3 | GHSA-4RMQ-MC2C-R495 | babylonlabs-io/babylon | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Explicit relevant-hunk origin, but-for, fix-reversal, and release containment were not fully closed from local replay. |
| 4 | GHSA-G754-HX8W-X2G6 | quic-go/quic-go | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Explicit relevant-hunk origin, but-for, fix-reversal, and release containment were not fully closed from local replay. |
| 5 | GHSA-3CPP-FV95-MPR5 | shopware/shopware | FALSE_POSITIVE | HIGH | ai_hunk_gate, but_for_gate, fix_reversal_gate | identity_gate, release_gate | AI commit is snapshot tests for documents. Production SSRF sink is document Twig templates in the fix, which the AI commit did not author. |
| 6 | GHSA-8XQ3-W9FX-74RV | silverbucket/webfinger.js | FALSE_POSITIVE | HIGH | ai_hunk_gate, but_for_gate, fix_reversal_gate | identity_gate, release_gate | AI commit is testing infrastructure. Fix authors src/webfinger.ts SSRF sink; that file is not in the AI commit. |
| 7 | GHSA-J975-95F5-7WQH | modelcontextprotocol/python-sdk | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Candidate has no explicit AI trailer or bot identity. Missing marker stays UNKNOWN. |
| 8 | GHSA-3QHF-M339-9G5V | modelcontextprotocol/python-sdk | UNKNOWN | MEDIUM | none | identity_gate, but_for_gate, fix_reversal_gate, release_gate | Claude co-authored the blamed session.py refactor. Whether those blamed lines created the FastMCP validation-error DoS vs parent is not closed. |
| 9 | GHSA-24P2-J2JR-386W | psd-tools/psd-tools | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Candidate subject is docstring enhancement. Without a local diff proving code vs comments, this is not converted into FALSE_POSITIVE. |
| 10 | GHSA-WF93-3GHH-H389 | OpenListTeam/OpenList | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Copilot trailer is on a stream-cache feature that also touches TLS config files. Copilot is not proved as author of the insecure TLS default. |
| 11 | GHSA-282G-FHMX-XF54 | zitadel/zitadel | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Copilot trailer is on an 88-file user API feature. Not hunk-level proof for UpdateHumanUser self-verify. |
| 12 | GHSA-FC6G-2GCP-2QRQ | rustfs/rustfs | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Candidate author is dependabot. A Copilot substring on a dependency bump is not authorship of the SourceIp header logic. |
| 13 | GHSA-WVJ2-96WP-FQ3F | modelcontextprotocol/go-sdk | UNKNOWN | MEDIUM | none | identity_gate, but_for_gate, fix_reversal_gate, release_gate | Claude co-authored sampling/tools and touches blamed mcp/content.go. Case-insensitive JSON may pre-exist; but-for and release are not closed. |
| 14 | GHSA-89MR-XQFV-758M | gogs/gogs | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Claude candidate is a util-to-x package rename. Symlink-escape origin is not independently closed at hunk level, so this stays UNKNOWN. |
| 15 | GHSA-P2J4-C4G6-RPF5 | Basekick-Labs/arc | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Gemini added a user-SQL denylist and a later Gemini/security commit disables DuckDB external access. Residual vs omitted-case is not closed. |
| 16 | GHSA-268J-37XF-PP52 | gogs/gogs | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Claude decoupled API types and is blamed on api.go. Missing admin checks vs type movement is not proved. |
| 17 | GHSA-WV27-2VQP-J7G5 | gogs/gogs | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Same util-to-x rename SHA as GHSA-89MR, different mechanism. Shared SHA does not duplicate uniqueness. Origin remains unclosed. |
| 18 | GHSA-3W28-36P9-W929 | gogs/gogs | UNKNOWN | MEDIUM | none | identity_gate, but_for_gate, fix_reversal_gate, release_gate | Claude added a general data-URI image allowlist; the GHSA residual is the ipynb sanitizer. Sibling-path vs omitted-case is not closed. |
| 19 | GHSA-C39W-43GM-34H5 | gogs/gogs | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Same API-decouple SHA as GHSA-268J, different org-name traversal mechanism. Uniqueness PASS. Authorship of dropped validation is not proved. |
| 20 | GHSA-35HP-HQMV-8QG8 | gofiber/fiber | UNKNOWN | MEDIUM | none | identity_gate, but_for_gate, fix_reversal_gate, release_gate | copilot-swe-agent bot authored cache middleware review-feedback on blamed cache.go. Query-string key omission vs review-only edit is not closed. |
| 21 | GHSA-5MWJ-V5JW-5C97 | lobehub/lobehub | FALSE_POSITIVE | HIGH | ai_hunk_gate, but_for_gate, fix_reversal_gate | identity_gate, release_gate | Claude authored a CLI generate command. The auth-bypass fix is webapi middleware and xor helpers, not the CLI http client. |
| 22 | GHSA-J6V5-G24H-VG4J | MontFerret/ferret | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Copilot trailer is on Feat/modules. History files are engine hooks, not IO::FS::WRITE. Missing FS-write authorship stays UNKNOWN. |
| 23 | GHSA-4JVX-93H3-F45H | OpenC3/cosmos | UNKNOWN | HIGH | none | identity_gate, release_gate | Claude denylist for tool config names is amended by a Claude allowlist on the same four files. Local clone has no tags containing candidate or fix. |
| 24 | GHSA-45Q4-X4R9-8FQJ | go-vikunja/vikunja | UNKNOWN | MEDIUM | none | identity_gate, but_for_gate, fix_reversal_gate, release_gate | Copilot bot authored a self-assignment wording change in notifications.go. Grammar-only vs introducing interpolation is not closed. |
| 25 | GHSA-VFGX-5Q85-58Q3 | jahlives/openssl_encrypt | UNKNOWN | MEDIUM | none | identity_gate, but_for_gate, fix_reversal_gate, release_gate | Claude extracted steganography into a plugin tree. Moving a pre-existing non-crypto PRNG is not independently closed as origin, so this stays UNKNOWN. |
| 26 | GHSA-4MPH-V827-F877 | locutusjs/locutus | FALSE_POSITIVE | HIGH | ai_hunk_gate, but_for_gate, fix_reversal_gate | identity_gate, release_gate | Claude hardened parse_str against includes() bypass. This GHSA is unserialize __proto__ injection. parse_str is a sibling sink, not omitted-case incomplete remediation. |
| 27 | GHSA-X2HW-PX52-WP4M | stellar/rs-soroban-sdk | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Copilot trailer is on a 183-file bn254 feature. Not hunk-level proof that Copilot authored Fr construction without modular reduction. |
| 28 | GHSA-HQJG-PWW4-PCGQ | google/clasp | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Human-authored docs commit mentions Jules was unable to complete the task. That is not explicit hunk authorship of the files.ts path-traversal sink. |
| 29 | GHSA-3RMJ-9M5H-8FPV | withastro/astro | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Claude co-author is on a Merge main into next squash. Authorship of the missing server-island body limit cannot be transferred across that import. |
| 30 | GHSA-9R75-G2CR-3H76 | vercel/workflow | UNKNOWN | LOW | none | identity_gate, ai_hunk_gate, topology_gate, but_for_gate, fix_reversal_gate, release_gate | Claude added hook.dispose() on the hook/webhook files. The GHSA residual is user-specified createWebhook tokens. Same-surface token option vs dispose-only is not closed. |

## Conservation

30 assigned = 30 reviewed + 0 unreviewed. did_not_pad=true. equation 30=30+0 holds.

## Terminal rule

FALSE_POSITIVE rows 5, 6, 21, and 26 are terminal because local file-set mismatch independently disproves AI authorship of the advisory sink. Every other row keeps open gates as UNKNOWN and terminal=false. No CONFIRM or NARROW. Release tags were not independently closed for any row.

## Blockers

Release containment stays open on every row. Missing hunk/parent deltas stay UNKNOWN rather than FAIL except the four locally disproved file-set mismatches.
