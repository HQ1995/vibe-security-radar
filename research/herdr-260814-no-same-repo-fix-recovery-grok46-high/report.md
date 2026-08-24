# No-same-repo-fix recovery (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Fix-recovery, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. Temporary PR fetches were discarded. Anonymous public git only. No credentials.

## Exclusive bucket reconstruction

Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet itself, this packet, `.leader-quarantine-260814`, and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Reviewed identities 34389. Not withdrawn, has a GitHub repository from a matching first-party advisory URL or bare homepage or OSV range repo, and no same-repo 40-hex commit URL under strict terminator regex `https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)`.
Minus nextqueue-era list terminals and canonical94 overlap `GHSA-V52W-28XH-V562` yields exclusive no_same_repo_fix 10631.
no_same_repo_fix_ids sha256 `47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5`.
Canonical94 overlap with the 10631: 0 (V52W already removed while forming the named bucket). Later terminal identities after the nextqueue freeze overlapping the 10631: 51. Remaining 10580.

Selector: remaining 10580 with a first-party repository advisory URL plus a same-repository PR, compare/patch, release, or patched-version reference, ranked by local clone, published on or after 2025-05-01, low PR fanout, signal order PR then compare/patch then release then patched-version, then uppercase GHSA ID. Inspect prefix 40. Did not pad. Did not infer causality from OSV ranges.

## Conservation

named bucket 10631 = later_terminals 51 + remaining 10580.
remaining 10580 = inspected 40 + unreviewed 10540. Equation 10580=40+10540. Holds.
assigned 40 = REJECT_ROUTING 40 + ROUTE 0 + unreviewed_on_prefix 0. Equation 40=40+0. Holds. Did not pad.
PASS=0. ROUTE 0. selected 0. rejected 40. unreviewed remainder of bucket 10540.

## Inspected prefix (40)

01. GHSA-26F5-8H2X-34XH repo=h3js/h3 closer=59a06f1976a4 src=pr_head np=2 files=0 nontest=0 members=1 REJECT_ROUTING merge_update_not_mechanism
02. GHSA-27GC-WJ6X-9W55 repo=keycloak/keycloak closer=3a471782dc9e src=pr_head np=1 files=11 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
03. GHSA-27GP-8389-HM4W repo=keycloak/keycloak closer=5f2bcddab877 src=pr_merge np=2 files=0 nontest=0 members=50 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
04. GHSA-2G7H-7RQR-9P4R repo=go-vikunja/vikunja closer=f6329f6c1958 src=pr_head np=1 files=6 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
05. GHSA-2Q4C-3MRW-63C3 repo=kopia/kopia closer=03cdb2bb1378 src=pr_head np=1 files=3 nontest=1 members=0 REJECT_ROUTING comment_only_hunk
06. GHSA-32G3-35G9-WC9G repo=kerberosmansour/hulumi closer=89239e40c468 src=pr_head np=1 files=8 nontest=1 members=0 REJECT_ROUTING ai_on_fix
07. GHSA-33QF-Q99X-WPM8 repo=home-assistant-ecosystem/home-assistant-cli closer=fca1bd7a8d44 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
08. GHSA-36RR-WW3J-VRJV repo=keras-team/keras closer=028c199b2331 src=pr_head np=1 files=10 nontest=7 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
09. GHSA-3H23-RRPC-3P87 repo=JasonLovesDoggo/caddy-defender closer=a85c489824d2 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
10. GHSA-3JP4-MHH4-GCGR repo=kimai/kimai closer=400ecc8d511b src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
11. GHSA-3W5P-95MH-GQ75 repo=ncalc/ncalc closer=4b031c51bbc4 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
12. GHSA-52FW-7FW2-FMV5 repo=grokability/snipe-it closer=ed931d497a6a src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
13. GHSA-53WG-R69P-V3R7 repo=graphql-hive/graphql-modules closer=0749090abe9d src=pr_head np=1 files=12 nontest=9 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
14. GHSA-56MX-8G9F-5CRF repo=lxc/incus closer=3abdc12cf6a8 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
15. GHSA-57HQ-95W6-V4FC repo=heartcombo/devise closer=3be4fa3158ba src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
16. GHSA-5QHX-GWFJ-6JQR repo=gogs/gogs closer=b6afcdb2e8d2 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
17. GHSA-6326-W46W-PPJW repo=kedro-org/kedro closer=f1c68826b60b src=pr_head np=1 files=6 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
18. GHSA-6C37-7W4P-JG9V repo=NationalSecurityAgency/emissary closer=76c4aaf234fe src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
19. GHSA-6GGM-PWR9-R5H2 repo=leanprover/vscode-lean4 closer=14b7a105c89d src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
20. GHSA-79PH-745M-6WXQ repo=langflow-ai/langflow closer=65229b6022b4 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
21. GHSA-7CWM-FPFH-RRCH repo=metal3-io/ironic-standalone-operator closer=fc0edf3efe72 src=pr_head np=1 files=9 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
22. GHSA-7QMG-GRCP-QF25 repo=geoserver/geoserver closer=3b36fbd6b2ec src=pr_head np=1 files=6 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
23. GHSA-8C4J-F57C-35CF repo=langflow-ai/langflow closer=f36e6e08e1c4 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
24. GHSA-8QW8-RQ86-9PC2 repo=go-gitea/gitea closer=1195eccda410 src=pr_head np=2 files=0 nontest=0 members=1 REJECT_ROUTING sibling_file
25. GHSA-98M9-HRRM-R99R repo=lostisland/faraday closer=f893d209e1f9 src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING ai_on_fix
26. GHSA-9PHM-9P8F-HW5M repo=nitrojs/nitro closer=9bd19a9762fd src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
27. GHSA-CCV6-R384-XP75 repo=langflow-ai/langflow closer=107e405e0adc src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
28. GHSA-CJ8G-PRCM-MFG5 repo=kerberosmansour/hulumi closer=89239e40c468 src=pr_head np=1 files=8 nontest=1 members=0 REJECT_ROUTING ai_on_fix
29. GHSA-FX6J-W5W5-H468 repo=nuxt/nuxt closer=e534a4b1b766 src=pr_head np=1 files=3 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
30. GHSA-G5MQ-PRX7-C588 repo=motioneye-project/motioneye closer=3f0ae0ffd971 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
31. GHSA-G759-4PXW-6692 repo=kerberosmansour/hulumi closer=89239e40c468 src=pr_head np=1 files=8 nontest=1 members=0 REJECT_ROUTING ai_on_fix
32. GHSA-G82G-M9VX-VHJG repo=kimai/kimai closer=dea37faa8d26 src=pr_head np=1 files=8 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
33. GHSA-G8WJ-3CR3-6W7V repo=nuxt/nuxt closer=f1c98e2af212 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
34. GHSA-GGMG-CQG6-J45G repo=getsentry/sentry closer=7694efa76c63 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
35. GHSA-GJ2H-2FPW-FHV9 repo=nuxt/ui closer=a80e3189425f src=pr_head np=1 files=5 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
36. GHSA-GPHH-9Q3H-JGPP repo=masci/banks closer=65e591559484 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING ai_on_fix
37. GHSA-H97M-27FX-42RX repo=matrix-org/matrix-rust-sdk closer=96516305565e src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
38. GHSA-HG3F-28RG-4JXJ repo=nuxt/nuxt closer=3167288b7b7a src=pr_head np=1 files=4 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
39. GHSA-HM92-R4W5-C3MJ repo=nodejs/undici closer=94571035d9e4 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING ai_on_fix
40. GHSA-HXF2-GM22-7VCM repo=NationalSecurityAgency/emissary closer=e1f03418fa12 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk

PR heads, merge refs, and release tags were resolved with anonymous git ls-remote. Hulumi GHSA-32G3, GHSA-CJ8G, and GHSA-G759 share closer `89239e40c4689f3613894bb8fa951a54d9cd59ed`; shared SHA is not identity dedupe.

## Routing rule

ROUTE requires a named exact closer object and a recognized atomic source_matcher hit before that closer on a plausible same-mechanism non-test hunk. Reject AI-on-fix, carrier-only trailers, sibling file, old bug, comment-only overlap, and test-only closers. Inspected prefix 40 produced 0 ROUTE rows. No PASS proposal.

## Blockers

- Inspected prefix 40 produced 0 ROUTE rows. No PASS proposal.
- Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
- Recovered PR/release objects without a pre-closer same-mechanism AI hunk are not seven-gate proof.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
