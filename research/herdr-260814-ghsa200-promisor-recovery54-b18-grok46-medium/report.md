# Promisor-recovery54 batch 18: 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **0**. Assigned count is **18**. This packet recovers first-party fix objects that the frozen commit-first hard prefilter skipped as `no_resolvable_first_party_fix` because old partial or promisor clones lacked objects. After public HTML plus public git recovery, **17** rows are mining **NOT_SELECTED** and **1** row is **BLOCKED**. Seven gates were **NOT_OPENED** except identity **PASS** on recovered first-party advisories. No-hit and edge misses are not GHSA-wide NOT-AI. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Worker PASS is a proposal only and this packet emits none.

## Conservation

Frozen source skip `no_resolvable_first_party_fix`: **54**.
Assigned in given order: **18**.
Leftover outside this slice: **36**.
Equation: **54=18+36**.
Packet equation: **18=17 NOT_SELECTED + 1 BLOCKED**.
PASS=0. UNKNOWN=0. Causal REJECT=0. Whole-case REJECT=0.
Did not pad. Did not backfill. Did not replace. Did not silent-drop.

Assigned IDs occupy original-hits skip-set positions 19 through 36 (1-based) and match the leader list exactly.

## Method

Inputs are `original-hits.jsonl` and `candidate-pool.jsonl` from `herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh`. github/advisory-database at `a42c436870111aa3f221257c9d56126a93173ccc` and OSV HTML are routing only. Claim-grade identity is the same-GHSA repository security advisory HTML. Official product git was fetched without promisor or lazy fetch into one named cache lane under `/home/hanqing/.cache/ai-slop-ghsa200/`, never `/tmp` for clones, never inside the repository. GitHub API was not used. Credentials were not used. A SHA that does not resolve in the official product repository is not a fix. A squash subject `(#N)` is not atomic hunk authorship. Temporary clones are deleted before handoff. Replay does not re-clone.

## Count boundary

No worker proposal changes the count. Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim.

## Assignment outcomes

| n | ID | First-party host | Official fix recovery | Verdict |
| --- | --- | --- | --- | --- |
| 1 | GHSA-2HW3-H8QX-HQQP | OpenListTeam/OpenList | OpenList-Frontend `7b5ed20c608c` XSS markdown viewer | NOT_SELECTED |
| 2 | GHSA-3JRG-97F3-RQH9 | TYPO3/typo3 | TYPO3-CMS/core `b9a8bcb614ec` and setup `60572dd050d8` | NOT_SELECTED |
| 3 | GHSA-3XM7-QW7J-QC8V | ondata/ckan-mcp-server | `79c0c0677b08` on v0.4.85; kysely SHA rejected | NOT_SELECTED |
| 4 | GHSA-4J9M-H44M-2HV8 | SteeltoeOSS/security-advisories | Steeltoe `6cfee5cccddf` OAEP | NOT_SELECTED |
| 5 | GHSA-4WG4-P27P-5Q2R | pimcore/pimcore | web2print-tools `7714452a04b9` | NOT_SELECTED |
| 6 | GHSA-58F6-6RJ2-3V8R | SteeltoeOSS/security-advisories | Steeltoe `4cbc352fe89a` and `b7ca93c510aa` | NOT_SELECTED |
| 7 | GHSA-6FRX-J292-C844 | TYPO3/typo3 | TYPO3-CMS/core `a659cc8c0ae0` | NOT_SELECTED |
| 8 | GHSA-744G-7QM9-HJH9 | TYPO3/typo3 | TYPO3-CMS/backend `034f58902995` | NOT_SELECTED |
| 9 | GHSA-76HW-P97H-883F | wkentaro/gdown | `af569fc6ed30` extractall path traversal | NOT_SELECTED |
| 10 | GHSA-7FQC-P256-7PWJ | SteeltoeOSS/security-advisories | Steeltoe `04db2ace3b80` and `17b27b8be546` | NOT_SELECTED |
| 11 | GHSA-7MVR-C777-76HP | none | same-GHSA repository advisory HTML missing | BLOCKED |
| 12 | GHSA-88FW-V6X4-3F58 | spring-projects/security-advisories | spring-data-commons `96e9475b9632` and `a4f893b66c18` | NOT_SELECTED |
| 13 | GHSA-8MVX-P2R9-R375 | openclaw/openclaw | tag v2026.3.2 commit `345abf0b2058`; routing SHA not our ref | NOT_SELECTED |
| 14 | GHSA-9GFH-4FWJ-W3RJ | vaadin/framework | flow-components PR 7616 `052f7b321ed6` | NOT_SELECTED |
| 15 | GHSA-9HQ9-CR36-4WPJ | TYPO3/typo3 | TYPO3-CMS/core `c265beed6e2c` | NOT_SELECTED |
| 16 | GHSA-9J94-67JR-4CQJ | rack/rack-session | `c28c4a8c1861` session pool | NOT_SELECTED |
| 17 | GHSA-C7V7-RQFM-F44J | vaadin/platform | same flow-components PR 7616; shared SHA is routing only | NOT_SELECTED |
| 18 | GHSA-F5VJ-F2HX-8M93 | webpack/webpack-dev-server | PR 5698 `3dabcbf2c94e`; Server.js additive CSRF guard | NOT_SELECTED |

## Case notes

GHSA-2HW3-H8QX-HQQP. First-party advisory is on OpenListTeam/OpenList. The recovered fix object lives in OpenList-Frontend `7b5ed20c608c` (subject: fix XSS issue reported). Deleted hunks in the markdown preview file blame `045ce1dd6771`, a PR-style squash (`#141`). Squash trailer transfer is refused. Atomic AI hunk not proven. NOT_SELECTED.

GHSA-3JRG-97F3-RQH9. First-party advisory on TYPO3/typo3 names typo3.org SA-2025-013. Split-package commits `[SECURITY] Require step-up authentication for password change` resolve with full history. Blamed origins are human TYPO3 chores and bugfixes. NOT_SELECTED.

GHSA-3XM7-QW7J-QC8V. First-party advisory on ondata/ckan-mcp-server, patched 0.4.85. Routing commit `0a602bff2f44` is kysely-org/kysely and is not first-party causality. Official git tag `v0.4.85` contains `79c0c0677b08`, which adds `validateServerUrl()` with no deleted source hunks. An AI trailer on that security commit is fix authorship, not origin of the SPARQL sink. A prior AI SSRF patch on `makeCkanRequest` (v0.4.84) is a different sink and is not same-boundary incomplete-remediation proof for this GHSA. Additive miss. NOT_SELECTED. Residual recall remains open.

GHSA-4J9M-H44M-2HV8. GHSA is hosted on SteeltoeOSS/security-advisories. Official product fix is SteeltoeOSS/Steeltoe `6cfee5cccddf`. Deleted hunk in RsaKeyStoreDecryptor.cs blames a human API-review commit. NOT_SELECTED.

GHSA-4WG4-P27P-5Q2R. GHSA is hosted on pimcore/pimcore. Official fix is pimcore/web2print-tools `7714452a04b9` (PR 108). Blame maps to a human permission-unrelated task. NOT_SELECTED.

GHSA-58F6-6RJ2-3V8R. Steeltoe management-port Host-header bypass. Fixes `4cbc352fe89a` and `b7ca93c510aa` blame human management-port work. NOT_SELECTED.

GHSA-6FRX-J292-C844. TYPO3 SA-2025-016. Core commit `a659cc8c0ae0` `[SECURITY] Disallow changing system maintainer details` blames human DataHandler history. NOT_SELECTED.

GHSA-744G-7QM9-HJH9. TYPO3 SA-2025-015. Backend commit `034f58902995` `[SECURITY] Prevent MFA bypass` blames human authenticator history. NOT_SELECTED.

GHSA-76HW-P97H-883F. First-party wkentaro/gdown `af569fc6ed30`. Deleted extractall hunks are not atomic AI. NOT_SELECTED.

GHSA-7FQC-P256-7PWJ. Steeltoe JWKS cache. Fixes `04db2ace3b80` and `17b27b8be546` blame human authentication history. NOT_SELECTED.

GHSA-7MVR-C777-76HP. Global advisory HTML exists. Same-GHSA repository security advisory HTML is missing on microsoft/playwright and on SocketDev/security-research (404). Identity fail-closed. BLOCKED. This is not a GHSA-wide NOT-AI finding.

GHSA-88FW-V6X4-3F58. GHSA hosted on spring-projects/security-advisories. Product fixes in spring-data-commons `96e9475b9632` and `a4f893b66c18` (ConcurrentLruCache). Blamed mapping-context history is not atomic AI. NOT_SELECTED.

GHSA-8MVX-P2R9-R375. First-party openclaw/openclaw, patched >= 2026.3.2. Routing SHA `345abf0b2e0f43b0f229e96f252ebf56f1e5549e` is not advertised (`not our ref`). Tag `v2026.3.2` contains a different object `345abf0b2058464583d5b956ef5878e8db9dc242` with the DNS-pinning subject. Deleted hunks blame human refactors, including squash `#27430`. NOT_SELECTED.

GHSA-9GFH-4FWJ-W3RJ. First-party vaadin/framework names vaadin.com/security/cve-2025-9467, which names flow-components PR 7616. Member `052f7b321ed6` (`fix: interrupt all uploads`) blames the original human upload component. NOT_SELECTED.

GHSA-9HQ9-CR36-4WPJ. TYPO3 SA-2025-014. Core `c265beed6e2c` `[SECURITY] Enforce file extension and MIME-type consistency` blames human history. NOT_SELECTED.

GHSA-9J94-67JR-4CQJ. rack/rack-session `c28c4a8c1861`. Blame maps to a human revert. NOT_SELECTED.

GHSA-C7V7-RQFM-F44J. First-party vaadin/platform, same Vaadin CVE page and same PR 7616 as GHSA-9GFH. Shared repository or SHA is routing only and is not uniqueness evidence of a second PASS. Same deleted-hunk miss. NOT_SELECTED.

GHSA-F5VJ-F2HX-8M93. First-party webpack-dev-server names PR 5698. Recovered head `3dabcbf2c94e` adds same-origin checks in `lib/Server.js` with no deleted source hunks there. Hard-prefilter deleted-hunk miss. NOT_SELECTED.

## Uniqueness

Assigned IDs are absent from canonical84 and from prior selected.jsonl packets. No PASS row exists to collide with GHSA-9GFH / GHSA-C7V7 shared PR 7616.

## Handoff storage

Work clones used `/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-promisor-recovery54-b18-grok46-medium` only. `/tmp/ghsa200-promisor-recovery54-b18` was removed before large fetches. The cache lane is deleted before handoff. Replay must not depend on those clones.
