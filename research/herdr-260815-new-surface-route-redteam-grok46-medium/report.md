# Independent red-team of reverse new-surface ROUTE 22

**Status: TERMINAL.** Surviving ROUTE IDs: none. KEEP_ROUTE 0, REJECT_ROUTE 22, UNKNOWN 0. Countable PASS 0. Packet delta 0. Canonical94 remains **94 HOLD**. This packet does not call a PASS and does not edit the canonical ledger.

Independent review of all 22 ROUTE rows emitted by `autoresearch/herdr-260815-new-surface-reverse80-grok46-high`. Source report exact_new_surface=0 with MATCHER_FAIL 15, NO_CLOSER_SURFACE_OVERLAP 6, NO_NEW_SURFACE 1. Verified 22 of 22 against `cases.jsonl`, exact git objects, canonical94, and the seven-gate CONTRACT. A ROUTE stays KEEP_ROUTE only if identity, atomic AI hunk, topology, but-for contribution, full fix reversal, released vulnerable artifact, and uniqueness are all PASS or narrowly plausible without any fatal FAIL. New surface requires an exact AI-added endpoint, caller, plugin, transport, file format, or privileged path whose removal eliminates the advisory path. None of the 22 meet that bar.

Conservation: assigned=22, reviewed=22, unreviewed=0. Equation `22=22+0`. Red-team equation `22=0+22+0` (KEEP_ROUTE+REJECT_ROUTE+UNKNOWN). Did not pad. Did not sample.

## Freeze

Frozen github/advisory-database HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 github-reviewed tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` at read-only `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`, summary SHA256 `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b`, status HOLD, strict 94.

Source packet hashes: assignment.jsonl `51ee418b222265cff667674b0a9d3fb8cd8c7a8b518de637533c87923b7ed0c2`, cases.jsonl `73bc756be68a318ecd5825a9604de29663f08113e509440e38f1874475a3a8bc`, report.md `800b5c53a12929489d1e5f413af3ddacd4b2be9268d4f136aca5c9af50575595`, replay.zsh `55459be2d17f64acd8e0c3482d6a0e303e52340b36050d1cae63d7ca833d6f71`, result.json `d23678631e3214a7bdf991a30a8aae392b7830e93852d63f7d9288cd83740065`.

Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`. Shared caches read-only. No clone retained. No credentials. No commit or push.

## Method

For each assigned identity: read the frozen GHSA object; confirm github-reviewed, not withdrawn, first-party `/security/advisories/` URL, and same-repo 40-hex closer; replay `rev-list --parents -n 1` and `merge-base --is-ancestor` on the named clone; run `source_matcher.matches_for_commit`; compare candidate `diff-tree --name-status` to every `minimum_fix_set` path; require an added endpoint, caller, plugin, transport, file format, or privileged path whose removal would drop the advisory path; check uniqueness against canonical94 strict 94. Cheap ancestry grep, PR branding, squash-carrier trailers, OSV introduced, and community prose are not causal proof. Shared SHA is not identity dedupe.

## Aggregate

Source matcher live-replay: true 7, false 15, matching the source `matcher` field on every row. Exact added-surface overlap with any closer path: **0**. Filename overlap exists only on GHSA-92CP-5422-2MW7 (`README.md`, `redis_test.go`) and is not an attack surface. Canonical94 overlap: 0. Exact new-surface hits: 0. KEEP_ROUTE requires all seven gates closed or narrowly plausible; every row has at least one fatal FAIL.

## Per identity (all REJECT_ROUTE)

1. GHSA-2CWW-FGMG-4JQC keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Candidate `6f91e2c540d9` parent `720c5c6576cc` closer `d9f0c84b7975`. Subject Update messages_pt_BR.properties. Trailer `marisvaldocopilot8` is not source_matcher. File is `messages_pt_BR.properties` only. Closer edits LDAP/admin permission Java. Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

2. GHSA-4VC8-PG5C-VG4X keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closer `f9708037383a` (user-profile duplicate email/username). Path overlap empty. Release tags do not separate a vulnerable artifact from the closer. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.

3. GHSA-5PXH-89CX-4668 OpenMage/magento-lts. REJECT_ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Candidate `b1c2dca6328b` parent `7e5a1414b77f` closer `d307e5bf7572`. Copilot Autofix matcher PASS on a one-hunk TinyMCE `setup.js` regex. Advisory is stored XSS in theme config (`Package.php`, `system.xml`, admin head templates). No added surface. Removing the regex change does not remove theme XSS. identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.

4. GHSA-69FP-7C8P-CRJR keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closer `2191cc26ae6d` (token/cookie request parser). Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

5. GHSA-7PQ6-V88G-WF3W getsentry/sentry. REJECT_ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Candidate `0458514d5584` parent `68b9c135a314` closer `6db508f7949d`. Copilot Autofix matcher PASS on `src/sentry/api/helpers/group_index/update.py`. Advisory is SAML SSO impersonation; closer is `src/sentry/auth/helper.py`. Path overlap empty. New helper functions here are not the SAML surface. identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

6. GHSA-8QW9-GF7W-42X5 streamlit/streamlit. REJECT_ROUTE. class MATCHER_FAIL. Candidate `2b2886eebc30` parent `675e5e6f1d6e` closer `bd0a8996c4c7`. Vendors `pympler.asizeof`. Trailer `simon@anthropic.com` is not source_matcher. Added vendor files are not the static/component request handlers the closer edits. Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=UNKNOWN uniqueness=PASS.

7. GHSA-92CP-5422-2MW7 redis/go-redis. REJECT_ROUTE. class NO_NEW_SURFACE. Candidate `ebe11d06ca95` parent `5314a571322c` closer `d236865b0cfa`. Copilot matcher PASS on a 60-file CI commit (`feat: Enable CI for Redis CE 8.0`). Added path is `.github/workflows/codeql-analysis.yml` only. Closer overlap is `README.md` and `redis_test.go`. Advisory is CLIENT SETINFO timeout ordering. Carrier-sized commit cannot transfer hunk authorship. identity=PASS ai_hunk=PASS topology=FAIL but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.

8. GHSA-C25H-C27Q-5QPV keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closers `0d0530046b9c`, `1f56a9e48bf9`, `bde8568d4174` (LDAP connection representation). Candidate is ancestor of the first two, not of `bde8568d4174`. Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

9. GHSA-CQ42-VHV7-XR7P keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closer `f9708037383a`. Same pairing failure as row 2 on a distinct GHSA identity. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.

10. GHSA-F3GH-529W-V32X zitadel/zitadel. REJECT_ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Candidate `1ee7a1ab7ca3` parent `48ffc902cc90` closer `d9d8339813f1`. Copilot matcher PASS on eventstore push/transaction internals. Advisory is Admin API IDOR for LDAP; closer edits `proto/zitadel/admin.proto` only. Path overlap empty. identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

11. GHSA-F4V7-3MWW-9GC2 keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closer `7a76858fe4aa`. Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

12. GHSA-FWHR-88QX-H9G7 rails/rails. REJECT_ROUTE. class MATCHER_FAIL. Candidate `74264f44675f` parent `02c1b7ac48eb` closer `35858f1d9d57`. Trailer `Co-authored-by: ChatGPT` without an email is not coauthor_trailer-v4. Files are ActiveModel::SecurePassword. Closer is Action Pack security headers. Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

13. GHSA-G6QQ-C9F9-2772 keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closers `071032a108bd` and `36defd5f33b2`. Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

14. GHSA-HMG4-WWM5-P999 umbraco/Umbraco-CMS. REJECT_ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Candidate `669c585ac4c7` parent `16d8ad8115c3` closers `559c6c9f312d`, `839b6816f2ae`. Copilot matcher PASS on client-ID validation in UserService/ClientCredentials controllers. Advisory is management-API user enumeration timing. Closer edits BackOfficeController/SecuritySettings. Path overlap empty. This is a later security attempt on a different boundary, not a new advisory surface. identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

15. GHSA-HW58-3793-42GG keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closer `99ca24c83272` (truststore). Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

16. GHSA-JJHX-JHVP-74WQ rails/rails. REJECT_ROUTE. class MATCHER_FAIL. Same SecurePassword SHA versus closer `b4d3bfb5ed8a` (Action Pack MIME type). Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

17. GHSA-M6Q9-P373-G5Q8 keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closers `9d9817e15a07` and `e3598a53678a` (login-status iframe). Candidate is ancestor of the first, not of `e3598a53678a`. Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

18. GHSA-PRJP-H48F-JGF6 rails/rails. REJECT_ROUTE. class MATCHER_FAIL. Same SecurePassword SHA versus closer `e215bf3360e6` (Action Text attachment). Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

19. GHSA-Q62R-8PPJ-XVF4 umbraco/Umbraco-CMS. REJECT_ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Candidate `26907f202fb1` parent `85176d1bf6bf` closers `06a2a500b358`, `d3c1443b14b1`. Copilot matcher PASS on `context-provider.ts` (do not destroy instance). Advisory is authenticated path traversal on temporary files. Closer edits TemporaryFileService. Candidate is ancestor of `06a2a500b358`, not of `d3c1443b14b1`. Path overlap empty. identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.

20. GHSA-RXFF-VR5R-8CJ5 streamlit/streamlit. REJECT_ROUTE. class MATCHER_FAIL. Same pympler vendor SHA versus closer `3a639859cfdf` (app_static_file_handler). Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=UNKNOWN uniqueness=PASS.

21. GHSA-W3G8-R9GW-QRH8 keycloak/keycloak. REJECT_ROUTE. class MATCHER_FAIL. Same i18n SHA versus closer `93b2a7327b25` (reserved-char / realm admin). Path overlap empty. identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

22. GHSA-WV8V-RMW2-25WC umbraco/Umbraco-CMS. REJECT_ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Same client-ID SHA as row 14 versus closer `d4f8754f9338` (backoffice localization/auth XSS). Path overlap empty. identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

## Shared SHA note

Candidate `6f91e2c540d917867e9c139842a2c2a117a26c79` is reused across 10 Keycloak identities. Shared SHA is routing only. It is a Portuguese admin-ui properties update, not ten new surfaces.

## Claim boundary

Worker PASS is a proposal only. This packet admits nothing, emits no PASS, and does not KEEP any ROUTE. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported. Canonical94 remains 94 HOLD.

## Replay

`zsh autoresearch/herdr-260815-new-surface-route-redteam-grok46-medium/replay.zsh`

Two consecutive runs must be byte-identical with empty stderr. Surviving ROUTE IDs printed: none.
