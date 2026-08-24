# Promisor recovery 54, shard C18

**Status: TERMINAL REJECT / UNKNOWN.** Worker PASS is a proposal only. This packet emits none. Canonical strict count remains **84**. Publication and a more-than-200 claim remain **HOLD**. packet_delta=0.

Assigned IDs 1-18 from the frozen 54-row `no_resolvable_first_party_fix` set, in the given order. Conservation: assigned 18 = reviewed 18 + unreviewed 0. Equation 18=17 REJECT_CANDIDATE_EDGE + 1 UNKNOWN. No padding, backfill, replacement, or silent drop.

Old skip existed because partial/promisor clones lacked objects, and several routing SHAs lived in a different repository than the GHSA host. Recovery used public git plus the same-GHSA repository security advisory HTML. The github/advisory-database object and OSV were routing only. Anonymous GitHub API was not used.

A recovered first-party fix that blames to a human (or that cannot prove an atomic AI hunk) rejects only that edge. It is not GHSA-wide NOT-AI.

Temporary clones lived under `/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-promisor-recovery54-c18-grok46-low` and are deleted before handoff. `/tmp` was not retained for clones. Replay does not clone.

## Verdicts

### 01 GHSA-G3QJ-J598-CXMQ REJECT_CANDIDATE_EDGE

HTML host webauthn-open-source/fido2-lib, patched >= 3.5.8. HTML commit is kriszyp/cbor-extract, not first-party. Public git has no 3.5.8 tag. Commit `6cf4734c` bumps 3.5.7 to 3.5.8 and cbor-x ~1.6.0 to ~1.6.3. Author James Cullum. identity_gate PASS. ai_hunk_gate FAIL. uniqueness_gate PASS versus canonical84.

### 02 GHSA-H4PH-CRVJ-9H92 REJECT_CANDIDATE_EDGE

HTML host pimcore/pimcore. Mechanism is SQL injection in TranslationController.php date filter. Atomic SQL fix `b5b987c7` is an ancestor of tag v2.3.6. Deleted hunks blame to human commits with no AI trailer. Tag v2.3.6 itself is unserialize Dashboard `80e57a23` with Copilot Autofix on the fix; that trailer does not transfer to the SQL origin. identity_gate PASS. ai_hunk_gate FAIL.

### 03 GHSA-HHG7-C65M-H7FF REJECT_CANDIDATE_EDGE

HTML host symfony/symfony, patched 6.4.40. HTML SHA `26a598fc` is rejected by public upload-pack. Atomic member on v6.4.40 is `487728e7e1` by Nicolas Grekas. Two-parent merge `4aa4e685b3` is not atomic hunk authorship. identity_gate PASS. ai_hunk_gate FAIL.

### 04 GHSA-HQRP-M84V-2M2F REJECT_CANDIDATE_EDGE

HTML patched 2.2.3 and 1.7.16. Official fix `98095949` SettingsController predefined-property permission, JiaJia Ji. One blame hunk timed out; missing origin is not AI. identity_gate PASS. ai_hunk_gate FAIL.

### 05 GHSA-J8PH-6FXJ-G533 REJECT_CANDIDATE_EDGE

HTML host SteeltoeOSS/security-advisories, patched 4.2.0. Product repo SteeltoeOSS/Steeltoe. `c34a7399` Eureka DataCenterInfo poisoning is an ancestor of 4.2.0. Tim Hess. Origin Dave Tillman. identity_gate PASS. ai_hunk_gate FAIL.

### 06 GHSA-M28W-2PQF-7QGJ REJECT_CANDIDATE_EDGE

HTML patched 5.2.6 and PR 5699. Atomic fix `f21ed0f44a` Sebastian Beltran. Origin Nitin Kumar. identity_gate PASS. ai_hunk_gate FAIL.

### 07 GHSA-M4W9-GCH5-C2G4 REJECT_CANDIDATE_EDGE

HTML commit `8fc995e953`, patched 1.0.0, Tony Gies. Origins lack AI trailers. identity_gate PASS. ai_hunk_gate FAIL.

### 08 GHSA-MQPW-46FH-299H REJECT_CANDIDATE_EDGE

HTML patched >= 2026.2.2. Routing 40-char SHA is not a public object (prefix collision). Public atomic fix `efe2a464af9fcaa2` Armin Ronacher, ancestor of v2026.2.2. Origin cpojer. identity_gate PASS. ai_hunk_gate FAIL.

### 09 GHSA-MWXV-35WR-4VVJ REJECT_CANDIDATE_EDGE

HTML patched >= 2026.2.26. Routing 40-char SHA is not a public object. Public atomic fix `258d615c4d9529` Peter Steinberger, plugin route auth canonicalization. identity_gate PASS. ai_hunk_gate FAIL.

### 10 GHSA-MX8G-39Q3-5C79 REJECT_CANDIDATE_EDGE

HTML patched 5.2.5 and PR 4316. vue-cli commit is not first-party. Atomic webpack fix `93e89961` Andrew Hyndman is an ancestor of v5.2.5. identity_gate PASS. ai_hunk_gate FAIL.

### 11 GHSA-P4XX-M758-3HPX REJECT_CANDIDATE_EDGE

HTML host TYPO3/typo3, patched 12.4.31 and 13.4.12. SHA is not in TYPO3/typo3. It is in TYPO3-CMS/webhooks as `0df8b8adae`, Benjamin Franzke, bulletin TYPO3-CORE-SA-2025-012. identity_gate PASS. ai_hunk_gate FAIL.

### 12 GHSA-P8GP-2W28-MHWG REJECT_CANDIDATE_EDGE

HTML host SignalK/signalk-server, patched >=1.5.0 of set-system-time. Atomic fix `75b11eae` KE Gustafsson is insertion-only validation. Parent still interpolates into `sh -c`. Parent blame blob was missing; origin unproven, not AI. identity_gate PASS. ai_hunk_gate FAIL.

### 13 GHSA-PH86-P8F6-F9R2 REJECT_CANDIDATE_EDGE

HTML SHA `ccb3f724` rejected by public upload-pack. Atomic member `59ef4840` Alexandre Daubois on patched 5.4/6.4 line. Merge `c609fbeb82` is two-parent. identity_gate PASS. ai_hunk_gate FAIL.

### 14 GHSA-Q62H-354G-5R85 REJECT_CANDIDATE_EDGE

HTML patched 4.2.0. `e50cd31a` env sanitizer, Tim Hess and Bart Koelman, ancestor of 4.2.0. Origin Hananiel Sarella. identity_gate PASS. ai_hunk_gate FAIL.

### 15 GHSA-QPMX-3RFJ-7RHV REJECT_CANDIDATE_EDGE

HTML SHA `dc2dbd29` rejected by public upload-pack. Atomic member `a1c42cbe51` Alexandre Daubois. Merge `693aeaeb24` is two-parent. identity_gate PASS. ai_hunk_gate FAIL.

### 16 GHSA-RXRH-4J9H-XGG9 REJECT_CANDIDATE_EDGE

HTML patched 4.2.0. `8dd97cc6` temporary TLS files, Bart Koelman, ancestor of 4.2.0. identity_gate PASS. ai_hunk_gate FAIL.

### 17 GHSA-V856-2RF8-9F28 REJECT_CANDIDATE_EDGE

HTML patched 3.0.2 and 2.4.5. Atomic `6414f01a` Darcy Mason, single parent. Origins scaramallion File-set work, no AI trailer. identity_gate PASS. ai_hunk_gate FAIL.

### 18 GHSA-WCHH-9X6H-7F6P UNKNOWN

HTML patched versions None. It points at matrix-nio PR 555. No first-party matrix-commander security reversal was recovered. Fail closed. Not GHSA-wide NOT-AI.

## Claim boundary

Worker PASS is a proposal only. This packet has zero PASS. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported.
