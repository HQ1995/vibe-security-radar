# Recover no_local_clone5 (canonical94)

Terminal: 5=5+0 reviewed. PASS=0. Canonical94 stays 94 HOLD. Worker PASS is proposal-only and this packet emits none. Greater-than-200 remains unsupported.

## Freeze

CONTRACT.md sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger sha256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` strict 94.
Source routing packet `autoresearch/herdr-260814-nextqueue-v2-grok46-low` result sha256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` committer 2026-08-14T03:33:36+00:00 (read-only cache). Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Temporary clones of pontedilana/php-weasyprint and shivammathur/setup-php were fetched without credentials and deleted after inspection. Shared caches were not mutated. No GitHub API.

## Bucket reconstruction (before analysis)

Pinned source `no_local_clone` count is 5. Recomputed with the same frozen advisory HEAD and filters, using terminal inventory packets with mtime before the source result (files_parsed=584 cases=267 adj=34 results=283 rows_parsed=12504 verdict_ids=7932):
reviewed 34389 = withdrawn 910 + no_repository 4053 + no_same_repo_fix 10631 + outside_coverage_window 9533 + terminal_verdict 7692 + no_first_party_repo_advisory 691 + canonical91_in_reviewed 76 + structural 803.
Check: 34389 = 34389. Holds.
structural 803 = no_local_clone 5 + fix_object_missing 38 + no_pre_fix_ai_marker 729 + ai_hit 31.
Check: 803 = 803. Holds.
Exact no_local_clone identities (did not pad, did not substitute):
1. GHSA-5WXR-W449-57CM repo=shivammathur/setup-php
2. GHSA-F5GC-QXF8-MH9G repo=pontedilana/php-weasyprint
3. GHSA-2FMJ-P74R-3WJM repo=pontedilana/php-weasyprint
4. GHSA-5G9F-CWWG-4P8G repo=pontedilana/php-weasyprint
5. GHSA-X8G9-H984-PC36 repo=pontedilana/php-weasyprint
Subtract canonical94 strict 94: overlap empty. Subtract current terminal REJECT/accepted identity: none (clonemissing84 NOT_SELECTED on four php-weasyprint rows is not REJECT). Remaining 5. Equation 5=5+0. Holds.

Routing, shared SHA, same-repo fix, AI-on-fix, squash trailer transfer, old-bug preservation, sibling fields, and merely risk-reducing incomplete hardening are not proof. NA/NARROW/UNKNOWN/BLOCKED is not PASS.

## Verdicts

### GHSA-5WXR-W449-57CM REJECT

Identity PASS: first-party GHSA-5wxr-w449-57cm, repo shivammathur/setup-php, CWE-532, GitHub Actions package shivammathur/setup-php. Advisory sha256 `f6b8f31aa95def695ae7a65bbed4427e5c47ddb2ad1403ce292ee21797970042`.
Mechanism: pinned affected Composer semver causes setup-php to write GITHUB_TOKEN into Composer github-oauth, which Composer then exposes.
Closer `7748c243803a56671412f9f7c745769e9573c6d4` parent `7729e411ecfb7faae003a4d831236c0e012f1aa3` is atomic Shivam Mathur, no AI marker.
Blame of the github-oauth write is human `89b2566bb0cc8cd6c3a32a35e34d80af75ce6a25` / `dcec1cf0b40e511c12ad649687f89eca882ae37b`.
Pre-fix Copilot SWE-agent commits add mago and other tools. tools.ts overlap is addPackage name punctuation, later reverted. Sibling tools / sibling fields. ai_hunk FAIL, but_for FAIL.
Tag `2.37.0` peel `accd6127cb78bee3e8082180cb391013d204ef9f` lacks the closer. Tag `2.37.1` peel `7c071dfe9dc99bdf297fa79cb49ea005b9fcadbc` contains it. Copilot SHAs are in both tags, so release_gate FAIL for AI containment of this mechanism.

### GHSA-F5GC-QXF8-MH9G REJECT

Identity PASS: first-party GHSA-f5gc-qxf8-mh9g, CWE-78, packagist pontedilana/php-weasyprint. Advisory sha256 `b93ea24973c757a7b5e40e2960d46e8817ea8649e5cdb785cf6cac6b91514c21`.
Mechanism: `is_executable(escapeshellarg($binary))` is dead, so raw `$binary` reaches Process::fromShellCommandline.
Whole-repo source_matcher scan is empty. Closer `9e86a2b317237fc5728f712f5037164530117f7e` parent `79ee8eb2eef1098660ca6b0ac032483cdd41c033` is atomic Manuel Dalla Lana.
Blame: `185979e4a8f02ff28aa1e6767d87cef97db3c52e` and `d7b9f292b1ca772e9c5397bfafb060daea1e49e2` (AbstractGenerator); Pdf copy `40f45aa350a7a90d02cefc9839b82db047ccb330`. Inherited snappy mirror. ai_hunk FAIL.
Tag `2.5.0` peel `c2b51fed0bf442c3bf0292b879a09944d436f2a0` vulnerable. Tag `2.5.1` peel `48f702a58f8861aea3262cddb2298b3d434204b0` fixed. Packagist p2 sha256 `9d5e775c69d3ad41ffbd47d782f0a2ed14453a4d78701c68eb8dfca60ae8c4ed` dist references match. No AI contribution. release_gate FAIL.

### GHSA-2FMJ-P74R-3WJM REJECT

Identity PASS: first-party GHSA-2fmj-p74r-3wjm, CWE-502. Advisory sha256 `b4d0b5d7ee9b80514c60c14a0f062e3f80085de477efe56e34a46144fd51f88d`.
Mechanism: case-sensitive `strpos($filename, 'phar://')` bypass via PHAR:// on PHP < 8.
Prior guard `eb8accc026f3cdfc05bafe9850d1e5f83ef35c80` is human 2023 CVE-2023-28115 countermeasure. Closer `d1aa487722b5a3cab9b222b85fdb5608a5a550c3` parent `6d328ffd3bcb800c7c2e8a594b1bff0c099c9391` is human scheme allow-list.
AI_INCOMPLETE_REMEDIATION fails: the attempted security boundary is not AI-authored. Whole-repo matcher empty. ai_hunk FAIL.
Tag `2.5.1` contains the human residual. Tag `2.6.0` peel `41fab3fb87a41dcb6c6587ef36e2e87017deb8fb` contains the closer.

### GHSA-5G9F-CWWG-4P8G REJECT

Identity PASS: first-party GHSA-5g9f-cwwg-4p8g, CWE-73. Advisory sha256 `c828c6e40312a650958a7d6735afa69773a0c34fa12d9a4b1e79d0a4ea7fdfe6`.
Mechanism: public `$temporaryFiles` unlinked without temp-folder containment.
Closer `6d328ffd3bcb800c7c2e8a594b1bff0c099c9391` parent `9582dcf119a405276cf55e9e10bc577a887792cb` is atomic human. Blame of the property is `185979e4a8f02ff28aa1e6767d87cef97db3c52e` 2021. Whole-repo matcher empty. ai_hunk FAIL.
Tag `2.5.1` vulnerable. Tag `2.6.0` fixed.

### GHSA-X8G9-H984-PC36 REJECT

Identity PASS: first-party GHSA-x8g9-h984-pc36, CWE-918. Advisory sha256 `720a341475a465fd677c522fbbeb0295f01a3a918f89971ca573b146bac05198`.
Mechanism: `isOptionUrl` uses FILTER_VALIDATE_URL; attachment values are fetched with file_get_contents on any scheme.
Closer `9582dcf119a405276cf55e9e10bc577a887792cb` parent `7499bfec2616e372f4befe82e27eee1ab29d6e17` is atomic human. Fetch blame `c2d6f74f89cd5868f65ba7803ca71c881efd5980` 2023. Whole-repo matcher empty. ai_hunk FAIL.
Tag `2.5.1` vulnerable. Tag `2.6.0` fixed.

## Conservation

assigned 5 = reviewed 5 + unreviewed 0. Equation 5=5+0. Holds. Did not pad. Did not substitute a different five. PASS_PROPOSAL=0. Canonical94 untouched. Prefer zero PASS over one false positive.

Stop. No ledger, site, scripts, or other-packet edits. No credentials. No GitHub API. Temp clones removed.
