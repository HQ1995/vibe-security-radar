# Marker overflow25 (canonical85 exclusion)

Verdict first: **0 PASS**. Frozen **25**. REJECT **25**. UNKNOWN **0**. NARROW **0**. Assigned **25**, reviewed **25**, unreviewed **0**. Did not pad. Packet delta **0**. Canonical85 stays **85**. Publication and more-than-200 remain **HOLD**. Worker PASS is a proposal only and is not issued.

Overflow from the 50-row exact-marker prefilter is **54**. Canonical85 overlap **0**. Terminally reviewed after canonical85: **2** (`GHSA-3775-99MW-8RP4`, `GHSA-7VF8-2CR6-54MF` in herdr-260814-fresh-strict-grok46-xhigh). Remaining pool **52**. Exact atomic AI marker plus same-path source overlap qualified **35**. Freeze took the 25 strongest by overlap, then n_source, then case_id. Leftover qualified **10** were not padded in. Merge-from-fork carriers **17** were not atomic hunk authorship and did not qualify.

Equation: `54=0+2+52`; `52=35+17`; `35=25+10`; `25=25+0`. Holds.

## Method

Newest local advisory-database clone and existing repository caches were read-only. GIT_NO_LAZY_FETCH=1. No GitHub REST API. No owned clone was created.
A freeze row requires an exact recognized AI author or trailer on a single-parent non-carrier commit, plus at least one same-path source-file overlap with the listed fix (self if the listed SHA is the candidate, else other listed refs or later same-path commits).
Carrier branding (Merge commit from fork, PR subject, multi-parent) is not hunk authorship. Shared SHA is not uniqueness.
Eligible classes: direct root, AI-created surface, necessary contributor, AI incomplete remediation. KEEP requires all seven gates exact PASS. Unclosed gates stay UNKNOWN. failing_gates lists FAIL only.

## Exclusions

- Canonical85 STRICT_RELEASED_CASE overlap with overflow: none.
- Post-canonical85 terminal reviews intersecting overflow: GHSA-3775-99MW-8RP4 and GHSA-7VF8-2CR6-54MF (fresh-strict). Other post-c85 packets (legacy-unknown3, legacy-near4b, w3-p4 hostile red-team, fresh-remediation-unknowns) did not hit this overflow set.

## Frozen REJECT (25)

All 25 listed candidate SHAs are first-party GHSA fix commits with Claude or Copilot trailers. They close, backport, or mis-point at the advisory. They do not author the vulnerable origin hunk. Local clones have no tags containing those SHAs, so release_gate stays UNKNOWN. identity_gate PASS. uniqueness_gate PASS versus canonical85. topology_gate PASS (atomic, not carrier). ai_hunk_gate FAIL. but_for_gate FAIL. Direct root, new surface, and necessary contributor do not close. Incomplete rem was considered where a later same-path commit exists; the GHSA does not name a residual of an AI-added guard except as the original hole those closers address.

| Rank | ID | Verdict | Class | Overlap | Decisive failure |
| ---: | --- | --- | --- | ---: | --- |
| 1 | GHSA-FPW6-HRG5-Q5X5 | REJECT | AI_ON_CLOSER | 8 | Listed SHA eab62379 is the GHSA-named closer: make never-expire tokens revocable. |
| 2 | GHSA-VFGX-5Q85-58Q3 | REJECT | AI_ON_CLOSER | 8 | Listed SHA 09e96e09 is the closer that replaces random with HMAC-SHA256 CSPRNG. |
| 3 | GHSA-G9HG-QHMF-Q45M | REJECT | AI_ON_CLOSER | 5 | Advisory says 0.16.6 hardens URL handling. Listed SHA 650f3090 adds OAuth redirect validation. |
| 4 | GHSA-4JVX-93H3-F45H | REJECT | AI_ON_CLOSER | 4 | Advisory sink is save_tool_config in local_mode.rb (shared OPENC3_LOCAL_MODE_PATH). |
| 5 | GHSA-RJ4G-RQGH-RX9H | REJECT | AI_ON_CLOSER | 3 | Listed SHA cb8d7a99 strips email from public comment responses and names that closer. |
| 6 | GHSA-CFP9-W5V9-3Q4H | REJECT | HUMAN_SANDBOX_CLOSER_AI_SIBLING | 2 | Advisory names sandbox bridge-mount traversal. Listed human SHA dd9d9c1c (Peter Steinberger) enforces workspaceOnly for the sandbox image tool. |
| 7 | GHSA-HM5P-X4RQ-38W4 | REJECT | AI_ON_CLOSER | 2 | Listed SHA 0529bcd6 is the GHSA-named closer that rejects absolute URIs against base_uri. |
| 8 | GHSA-3V85-FQVH-7RXF | REJECT | AI_ON_CLOSER | 2 | Listed SHA fd320fe3 is the closer that blocks stored XSS in RSS generation. |
| 9 | GHSA-9GQJ-5W7C-VX47 | REJECT | AI_ON_CLOSER | 2 | Listed SHA bea2930c is the closer that makes empty allowedDomains block network. |
| 10 | GHSA-C65F-X25W-62JV | REJECT | AI_ON_CLOSER | 2 | Listed SHA 809416b7 changes CORS default from wildcard to empty list and names the GHSA. |
| 11 | GHSA-H3M5-P59H-X88P | REJECT | AI_ON_CLOSER | 2 | Listed SHA e78a3666 adds --password-file/--password-fd and deprecates --password. |
| 12 | GHSA-P64J-F4X9-WQ66 | REJECT | AI_ON_CLOSER | 2 | Listed SHA a7e8b8e8 is the closer for exact redirect URI matching. Body names GHSA-p64j. |
| 13 | GHSA-RCHF-XWX2-HM93 | REJECT | AI_ON_CLOSER | 2 | Listed SHA 2bdcb24d is the closer titled Fix ReDoS vulnerability in HTML parsing. |
| 14 | GHSA-RGJ7-VG8V-J4WR | REJECT | SHARED_SHA_WRONG_MECHANISM | 2 | Advisory is PUT /api/echo/like/:id with no auth. Listed SHA a7e8b8e8 is the OAuth redirect closer of GHSA-P64J. |
| 15 | GHSA-RVV3-G6HJ-G44X | REJECT | AI_ON_CLOSER | 2 | Listed SHA 0afaf1e9 applies default MaxDepth of 64 and names this GHSA in the subject. |
| 16 | GHSA-J88V-2CHJ-QFWX | REJECT | AI_ON_CLOSER | 1 | Listed SHA 60644f84 fixes the sanitizer. Claude trailer is on that closer. |
| 17 | GHSA-PJ6Q-4VQ4-R8CG | REJECT | AI_ON_CLOSER | 1 | Listed SHA cecc2c19 rate-limits and makes likes idempotent on the public endpoint. |
| 18 | GHSA-2VHW-Q7VH-7XV2 | REJECT | AI_ON_CLOSER | 1 | Listed SHA 7aa8787f stops leaking str(e) from the readiness handler and names the GHSA. |
| 19 | GHSA-4HWX-XCC5-2HFC | REJECT | COPILOT_AUTOFIX_CLOSER | 1 | Listed SHA 74c354c4 is Copilot Autofix: Potential fix for code scanning alert no. 130. |
| 20 | GHSA-4RH7-JWG9-M28M | REJECT | AI_ON_CLOSER | 1 | Listed SHA 4b2adb05 moves refresh tokens to POST body and names the GHSA. |
| 21 | GHSA-5CXW-W2XG-2M8H | REJECT | AI_ON_CLOSER | 1 | Advisory text: we added platform to the unsafe-import blocklist at 351ed4d4. |
| 22 | GHSA-8FFJ-4HX4-9PGF | REJECT | AI_ON_CLOSER | 1 | Listed SHA 728f2e54 rejects none and pins jwt_algorithm. Subject names this GHSA. |
| 23 | GHSA-8H88-GXP3-J7PG | REJECT | AI_ON_CLOSER | 1 | Listed SHA f4a1ba66 verifies key-bundle signatures on deserialization and names the GHSA. |
| 24 | GHSA-8MC6-XJPR-H98X | REJECT | AI_ON_CLOSER | 1 | Listed SHA 091d26d2 blocks SSRF in peer info fetch and AddConnect URL validation. |
| 25 | GHSA-F7PM-6HR8-7GGM | REJECT | AI_BACKPORT_CLOSER | 1 | Listed SHA 535cc3c2 subject: merge up CVE fix from 5.2.x - full origin validation in CheckAllowedOrigins. |

### Notable rows

- GHSA-P64J and GHSA-RGJ7 share candidate SHA `a7e8b8e8`. Shared SHA is not uniqueness. P64J is the OAuth redirect closer. RGJ7's advisory is the unauthenticated like endpoint; the listed SHA is the wrong hunk.
- GHSA-4JVX: Claude denylist `9957a9fa` is an ancestor of Claude allowlist `e6efccbd` on ToolConfigModel. The GHSA sink is pre-existing `save_tool_config` in local_mode.rb. Incomplete-rem patch-delta does not close.
- GHSA-CFP9: human `dd9d9c1c` sandbox closer is an ancestor of Claude `14baadda` localRoots sibling.
- GHSA-F7PM: Claude `535cc3c2` is a 5.2.x merge-up of the CVE closer.
- GHSA-4HWX: Copilot Autofix closer of a code-scanning prototype-pollution alert.

## Leftover qualified (not frozen, not padded)

GHSA-FC86-6RV6-2JPM, GHSA-GFWX-W7GR-FVH7, GHSA-H45M-MGCP-Q388, GHSA-HVC7-763R-4F3H, GHSA-J48Q-4C78-RHF9, GHSA-Q7F2-RV22-2XGR, GHSA-QMGC-5H2G-MVRW, GHSA-R48F-3986-4F9C, GHSA-R7CG-QJJM-XHQQ, GHSA-VVJJ-XCJG-GR5G.

## Not qualified (carrier branding)

GHSA-4GGG-H7PH-26QR, GHSA-9R75-G2CR-3H76, GHSA-VQQR-RMPC-HHG2, GHSA-HWR4-MQ23-WCV5, GHSA-XCHC-CQWG-G76Q, GHSA-W48Q-CV73-MX4W, GHSA-33MH-2634-FWR2, GHSA-JCC8-G2Q4-9FXQ, GHSA-P4GQ-3VXJ-F4JQ, GHSA-QXX2-7H4C-83F4, GHSA-7GCC-R8M5-44QM, GHSA-699M-4V95-RMPM, GHSA-75HX-XJ24-MQRW, GHSA-6JM8-X3G6-R33J, GHSA-CW39-R4H6-8J3X, GHSA-W5G8-5849-VJ76, GHSA-W8WV-VFPC-HW2W.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 85. Only leader-reviewed rows with all seven gates PASS enter that bound after independent hostile red-team. This packet did not edit canonical85 and does not support a greater-than-200 claim.

Owned temporary clones and raw pages were not created. Canonical ledger was not edited. No commit or push.
