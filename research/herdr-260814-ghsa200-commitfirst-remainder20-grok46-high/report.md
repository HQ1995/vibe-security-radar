# Commit-first remainder 20

**Status: TERMINAL REJECT.** Worker PASS is a proposal only. This packet emits none. Canonical strict count remains **84**. Publication and a more-than-200 claim remain **HOLD**. packet_delta=0.

## Freeze selector limitation

The freeze selector admitted **post-fix and path-only** hits. Qualification was first-party GHSA identity, a referenced or nearby atomic AI marker, and a real delta on an advisory-affected or fix path. It did **not** require the atomic AI commit to be an ancestor of the exact first-party fix or carrier, and it did not require the AI hunk to be proven in the affected release.

Deep facts: 13 first-party fix-probe entries; **12 are not ancestors** of the named fix; **1 extra referenced SHA is unusable** (wrong-repo object absent from the clone). The other 10 frozen rows lack a usable fix relation in the frozen GHSA object. Independent seven-gate review REJECTS all 20.

This packet does **not** claim these 20 exhausted pre-fix remainder candidates. Probe stats stopped after the cap with 1973 unprobed remainder rows. Later shards GJ, GN, KN, and OZ were unprobed after the AF cap. A continuation lane must require, before freeze, that the atomic AI commit is an ancestor of the exact first-party fix or carrier, or is otherwise proven present in the affected release.

## Freeze record

Frozen github/advisory-database HEAD `a42c436870111aa3f221257c9d56126a93173ccc`. Candidate files are the 2026-08-13 commit-first shard scan artifacts (AF review-queue and ai-commits, GJ origin-rank, GN intersections and scans, KN ranking, OZ shard_novel and ai_mine). Paths and SHA-256 are in `work/candidate-files.json` and `work/freeze.json`.

Candidate pool 5980 unique remainder rows in shard order AF, GJ, GN, KN, OZ. Exclusion snapshot 2459 IDs from canonical84 strict 84, terminal 2026-08-13/2026-08-14 selected/cases packets, source-shard seven-gate reviewed IDs, and frozen assigned IDs in active threegate/hard/unknown4b lanes. Live outcomes were not consumed. Frozen IDs stay conserved: no substitution and no padding.

Conservation: assigned 20 = reviewed 20 + unreviewed 0. Shard verdict labels were not trusted.

## Verdicts

All 20 rows are REJECT. File-overlap remainder is routing. identity_gate PASS as first-party GHSA objects. ai_hunk_gate FAIL: the atomic AI hunk is not the named vulnerable mechanism. topology_gate PASS: single-parent commits, no trailer transfer. but_for, fix_reversal, release, and incomplete-remediation patch-delta FAIL. uniqueness_gate PASS versus canonical84. Shared SHA or repository does not prove duplicate or causality.

### 01 GHSA-3Q26-F695-PP76 REJECT

Reviewed GHSA names unsanitized child_process.exec in gitInit/gitAdd tools. Copilot 1134dd1e only edits gitLog/logic.ts. Basename logic.ts is not the named exec sink. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 02 GHSA-8GQP-HR9G-PG62 REJECT

Reviewed GHSA names unrestricted Java class access in Nashorn ScriptEvaluator. Claude 51d35007 later normalizes FORK_JOIN_DYNAMIC objects (issue 616). Official fix e9816501 adds --no-java. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 03 GHSA-CVX7-X8PJ-X2GW REJECT

Reviewed GHSA names unbounded concurrent DoQ streams and goroutines. Official fix efaed02c (v1.12.2) limits streams. Claude 9fac0b6e later bounds stream read timeout on server_quic.go and first appears in v1.14.5. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 04 GHSA-49XW-HW94-FMV2 REJECT

Reviewed GHSA names Menu permission RCE via htdocs/admin/menus/edit.php and user/document.php. Claude 354eadef is clean code on htdocs/public/project/index.php. Basename index.php is a collision. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 05 GHSA-7XWP-2CPP-P8R7 REJECT

Reviewed GHSA names long-lived JWT tokens that survive logout in http/auth.go. Claude 847d08bd is a later security dump for archive traversal, login DoS, and symlink escape. That is AI-on-fix of sibling disclosures. reject_class AI_ON_FIX_SIBLING. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 06 GHSA-GJV4-GHM7-Q58Q REJECT

Reviewed GHSA names unsanitized execSync in kubectl tools. Claude 1119609a bumps the MCP SDK and touches kubectl-scale.ts. Official fix ab165f5a migrates to execFileSync. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix no_with_unusable_extra_ref. uniqueness_gate PASS versus canonical84.

### 07 GHSA-H45X-QHG2-Q375 REJECT

Reviewed GHSA names deep-scanline ZIPS forged unpacked size in OpenEXRCore. Official fix 916cc729 (v3.3.3). Cursor 783b6542 later rejects short zlib inflates on internal_zip.c and is not an ancestor of that fix. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 08 GHSA-RJ53-J6JW-7F7G REJECT

Reviewed GHSA names validator-set mutation at epoch boundary via cosmos-sdk module.go. Copilot 085cfeea fixes incentive reward-tracker overflow in x/incentive/module.go. Basename module.go is a collision. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 09 GHSA-6JCC-XGCR-Q3H4 REJECT

Reviewed GHSA names inbox authentication bypass: activities processed before verifying the signing key. Official fix 14a2f8c6. Codex 12243f49 later catches onUnverifiedActivity errors in handler.ts and first appears in 2.1.0. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 10 GHSA-95V9-HV42-PWRJ REJECT

Reviewed GHSA names missing 0 <= S < order checks in EdDSA/ECDSA Verify. Official fix 0ba6730f (v0.14.0). Copilot b53af634 later adds recursive groth16/EdDSA flags and first appears in v0.15.0. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 11 GHSA-H5RC-J5F5-3GCM REJECT

Reviewed GHSA names missing overflow checks on SSH channel window adjust. Official fix 0eb5e406 (v0.54.1). Copilot 32fd46f1 later reduces write-path copies in encrypted.rs and first appears in v0.61.0. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 12 GHSA-34W8-MCWR-VG29 REJECT

Reviewed GHSA names unsanitized execSync in emptyFolder(directoryPath) in lib/utils.js, range 3.5.0 to 3.7.5. Claude ef6c3a9d later adds dropzone attachFile and first appears in 4.0.0-rc.4. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 13 GHSA-3GCM-F6QX-FF7P REJECT

Reviewed GHSA names CustomMCP mcpServerConfig parsing RCE in CustomMCP.ts. Claude 28aba537 only moves filterNodeByClient in packages/server/src/services/nodes/index.ts. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 14 GHSA-4HJH-WCWX-XVWJ REJECT

Reviewed GHSA names data: URL payloads ignoring maxContentLength in the Node http adapter. Official fixes 945435fc / a1b1d3f0. Claude 6bb12c19 later strips custom auth headers on cross-origin redirects in http.js and first appears in v1.18.0. reject_class AI_ON_FIX_SIBLING. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 15 GHSA-HR92-4Q35-4J3M REJECT

Reviewed GHSA names SSRF in /api/v1/fetch-links via packages/components/src/utils.ts. Gemini 1449e80d extends AWS Bedrock in a different utils.ts. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 16 GHSA-VH3F-QPPR-J97F REJECT

Reviewed GHSA names unsanitized URL protocols in createLink.openLink (XSS). Official fix 7f221485 (3.3.2). Claude 396ef270 later delegates camera permission in Link.ts and first appears in 3.9.8. reject_class AI_ON_FIX_SIBLING. ai_ancestor_of_first_party_fix no. uniqueness_gate PASS versus canonical84.

### 17 GHSA-35G6-RRW3-V6XC REJECT

Reviewed GHSA names unrestricted file upload / web shell via storageUtils and createAttachment. Gemini de3a9182 later adds session-id type checks on packages/server/src/utils/index.ts. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 18 GHSA-3G72-CHJ4-2228 REJECT

Reviewed GHSA names operations API WebSocket secret leakage in lxd/operations.go. Copilot c440a8b5 only restyles error strings in lxd-agent/operations.go. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 19 GHSA-472F-VMF2-PR3H REJECT

Reviewed GHSA names path traversal in validLogFileName in lxd/instance_logs.go. Copilot 87325e21 only restyles error strings in shared/util.go. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

### 20 GHSA-7232-97C6-J525 REJECT

Reviewed GHSA names cmdline spoofing in findContainerForPID in lxd/api_devlxd.go. Copilot 2657df62 restyles error strings across 289 files including api_devlxd.go and devlxd.go. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. ai_ancestor_of_first_party_fix missing_fix_relation. uniqueness_gate PASS versus canonical84.

## Claim boundary

Worker PASS is a proposal only. This packet has zero PASS. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported.
