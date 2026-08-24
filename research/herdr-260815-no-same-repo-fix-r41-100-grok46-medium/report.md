# No-same-repo-fix recovery ranks 41-100 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Fix-recovery, not admission.
Inspected ranks 41-100 of the frozen exclusive recoverable ranking. Disjoint from the recovery packet top40.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
Prior recovery packet result SHA256 `6620de70c68eaecde0c82dd90bd2f637b866e2d94cbc04f70ef18b80c646567a` assignment `d010ec80426427db98b6879d97cafe15f8c00fac6d068e7ba113d105ae1e75f2` cases `9fa66581ea396208942c58323359fa7ea22c79cb7bf27ef19cfbedd5f5254318` report `a772ed3e00daae1000341e2ada8ed768e1f21f7e8ea8435d278633c18709fea3` replay `72b2e0a0af11ee6a15cd974375acbe5fcfc06b755838104f65549bc37bab455c`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
no_same_repo_fix_ids sha256 `47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5`.
Ranked recoverable prefix-100 sha256 `88866e71e48231c1d32403a4b5dd3681158854b08742df100838afb2da2a6155`.
Ranks 41-100 sha256 `bac53b8a765cec6f29192f970ab8ab237e003af435d2c7911ce2ff940e72b2ce`.
Shared caches were read-only. Temporary PR fetches were discarded. Anonymous public git only. No credentials.

## Exclusive bucket reconstruction

Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet, the 260814 recovery packet, this packet, `.leader-quarantine-260814`, herdr-260815 packets, and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Reviewed identities 34389. Not withdrawn, has a GitHub repository from a matching first-party advisory URL or bare homepage or OSV range repo, and no same-repo 40-hex commit URL under strict terminator regex `https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)`.
Minus nextqueue-era list terminals and canonical94 overlap `GHSA-V52W-28XH-V562` yields exclusive no_same_repo_fix 10631.
Canonical94 overlap with the 10631: 0. Later terminal identities after the nextqueue freeze overlapping the 10631: 51. Remaining 10580.
Selector: remaining 10580 with a first-party repository advisory URL plus a same-repository PR, compare/patch, release, or patched-version reference, ranked by local clone, published on or after 2025-05-01, low PR fanout, signal order PR then compare/patch then release then patched-version, then uppercase GHSA ID. Inspect slice 41-100. Did not pad. Did not infer causality from OSV ranges.
Ranks 41-100 are 60 unique IDs and disjoint from the recovery packet top40.

## Conservation

named bucket 10631 = inspected prefix-100 + remainder 10531. Equation 10631=100+10531. Holds.
10531 = later_terminals 51 + remaining after prefix-100 10480. Holds.
remaining 10580 = prefix-100 + unreviewed 10480. Holds.
assigned 60 = REJECT_ROUTING 60 + ROUTE 0 + unreviewed_on_slice 0. Equation 60=60+0. Holds. Did not pad.
PASS=0. ROUTE 0. selected 0. rejected 60. unreviewed remainder of bucket 10531.

## Inspected slice (ranks 41-100)

41. GHSA-J477-6VPG-6C8X repo=juju/juju closer=df706bbea024 src=pr_head np=1 files=3 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
42. GHSA-JG4P-7FHP-P32P repo=hapijs/content closer=72b24fdd7b45 src=pr_head np=1 files=3 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
43. GHSA-M549-QQ94-FVHG repo=InternLM/lmdeploy closer=20b334ff44a4 src=pr_head np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
44. GHSA-MRQ8-RJMW-WPQ3 repo=gofiber/fiber closer=696783064e1a src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
45. GHSA-P4GQ-832X-FM9V repo=nltk/nltk closer=c7cf2b973322 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING sibling_file
46. GHSA-PX3P-VGH9-M57C repo=nocobase/nocobase closer=83c25b518bc5 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
47. GHSA-Q28V-664F-Q6WJ repo=indico/indico closer=f8583557a3da src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
48. GHSA-QH78-RVG3-CV54 repo=go-vikunja/vikunja closer=d5dd913fdc02 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
49. GHSA-QWQC-P3Q8-WCG9 repo=langflow-ai/langflow closer=bb1ab2cd3b1e src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
50. GHSA-RGGM-JJMC-3394 repo=kyverno/kyverno closer=34481146530b src=pr_head np=1 files=4 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
51. GHSA-RH42-6RJ2-XWMC repo=kimai/kimai closer=400ecc8d511b src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
52. GHSA-RHGJ-6G2C-FRMM repo=kerberosmansour/hulumi closer=89239e40c468 src=pr_head np=1 files=8 nontest=1 members=0 REJECT_ROUTING ai_on_fix
53. GHSA-WFQ4-36M3-9G42 repo=matrix-org/matrix-rust-sdk closer=b8bc629ec974 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
54. GHSA-WQ34-7F4G-953V repo=MarimerLLC/csla closer=313c47ac88c4 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
55. GHSA-WQCW-G35J-J578 repo=kubewarden/kubewarden-controller closer=92f2322802e9 src=pr_head np=1 files=4 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
56. GHSA-WRF9-R3H7-7X5V repo=go-gitea/gitea closer=08fa5bd21601 src=pr_head np=2 files=20 nontest=11 members=1 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
57. GHSA-X223-P2GF-V735 repo=langflow-ai/langflow closer=5b4cd0e4138d src=pr_head np=1 files=4 nontest=2 members=0 REJECT_ROUTING ai_on_fix
58. GHSA-X4R9-GMW3-HXWW repo=geoserver/geoserver closer=ea7a3522c76d src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
59. GHSA-XHPR-465J-7P9Q repo=keycloak/keycloak closer=b5d6c8c40217 src=pr_head np=1 files=14 nontest=8 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
60. GHSA-XJW9-4GW8-4RQX repo=microsoft/semantic-kernel closer=2f1ff2f77436 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
61. GHSA-XM3X-9CFW-JHX4 repo=nl-portal/nl-portal-backend-libraries closer=64dfa01cd813 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
62. GHSA-349C-2H2F-MXF6 repo=laravel/passport closer=1b1b96703cbd src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
63. GHSA-3G6G-GQ4R-XJM9 repo=NationalSecurityAgency/emissary closer=2ca745d5bb6a src=pr_head np=2 files=34 nontest=18 members=1 REJECT_ROUTING merge_update_not_mechanism
64. GHSA-4766-X535-JW3R repo=kgateway-dev/kgateway closer=a87f0a73758e src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
65. GHSA-4RV8-5CMM-2R22 repo=jmpsec/osctrl closer=8997ba99ee5e src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
66. GHSA-4VQ8-7JFC-9CVP repo=moby/moby closer=c3fa7c17794f src=pr_head np=1 files=3 nontest=2 members=0 REJECT_ROUTING test_only_closer
67. GHSA-5PMX-7R6R-WFQQ repo=kgateway-dev/kgateway closer=a87f0a73758e src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
68. GHSA-5W89-W975-HF9Q repo=nitrojs/nitro closer=f92e68473616 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
69. GHSA-7HW8-6Q6R-4276 repo=langflow-ai/langflow closer=cff06a951bd8 src=pr_head np=2 files=63 nontest=24 members=1 REJECT_ROUTING merge_update_not_mechanism
70. GHSA-7M55-2HR4-PW78 repo=juju/juju closer=1b36a2db66a2 src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
71. GHSA-9VC9-4JV3-RF86 repo=kerberosmansour/hulumi closer=89239e40c468 src=pr_head np=1 files=8 nontest=1 members=0 REJECT_ROUTING ai_on_fix
72. GHSA-RCHW-322G-F7RM repo=jmpsec/osctrl closer=8997ba99ee5e src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
73. GHSA-W5FQ-8965-C969 repo=juju/juju closer=1b36a2db66a2 src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
74. GHSA-W6VG-JG77-2QG6 repo=ml-explore/mlx closer=6675f6fb7ec7 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
75. GHSA-WJW6-95H5-4JPX repo=nautobot/nautobot closer=e7b7090fbf93 src=pr_head np=1 files=3 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
76. GHSA-2P76-GC46-5FVC repo=geonetwork/core-geonetwork closer=2be40410defa src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
77. GHSA-49PM-43HF-6XFQ repo=metal3-io/ip-address-manager closer=b63433086f06 src=pr_head np=1 files=3 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
78. GHSA-CRMM-HGP2-WGRP repo=laravel/framework closer=0565084ef4c4 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
79. GHSA-HFC8-W5F4-3X6M repo=metal3-io/ironic-standalone-operator closer=d6586f398e6c src=pr_head np=1 files=9 nontest=8 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
80. GHSA-M23H-6MWM-39M8 repo=Kong/kubernetes-ingress-controller closer=683853f84d3d src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
81. GHSA-CFW5-68C4-FFQP repo=mikro-orm/mikro-orm closer=444dc7af9a64 src=pr_head np=1 files=4 nontest=3 members=0 REJECT_ROUTING ai_on_fix
82. GHSA-G23J-2VWM-5C25 repo=LearningCircuit/local-deep-research closer=c2a47a83b309 src=release_tag np=1 files=4 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
83. GHSA-RF84-WR5G-M3RP repo=metal3-io/cluster-api-provider-metal3 closer=a02c279d86d9 src=pr_head np=1 files=6 nontest=6 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
84. GHSA-23Q2-54QV-RQ5X repo=getkirby/kirby closer=274dca6df93d src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
85. GHSA-2434-3X6Q-8R99 repo=n8n-io/n8n closer=a4d0dfce2940 src=release_tag np=1 files=28 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
86. GHSA-2763-CJ5R-C79M repo=MervinPraison/PraisonAI closer=42807f1740ac src=release_tag np=1 files=17 nontest=9 members=0 REJECT_ROUTING sibling_file
87. GHSA-2FCR-JFVC-VGG2 repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
88. GHSA-2G3W-CPC4-CHR4 repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=6 members=0 REJECT_ROUTING sibling_file
89. GHSA-2G4X-FQ3J-CGQ4 repo=hahwul/dalfox closer=1dcb01cbb196 src=release_tag np=1 files=3 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
90. GHSA-2H7V-4372-F6X2 repo=getkirby/kirby closer=d952dfc0a890 src=release_tag np=1 files=27 nontest=21 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
91. GHSA-2JF5-6WWV-VHXX repo=inngest/inngest-js closer=82a0341cbec2 src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
92. GHSA-2MR3-M5Q5-WGP6 repo=gofiber/fiber closer=3c24ebefe500 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
93. GHSA-2WM4-VWP6-V7XC repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
94. GHSA-2XGM-WC4G-5JVG repo=n8n-io/n8n closer=0dac8a2785e7 src=release_tag np=1 files=50 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
95. GHSA-2XGV-5CV2-47VV repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=6 members=0 REJECT_ROUTING sibling_file
96. GHSA-2XW4-V2WX-HQQ9 repo=getkirby/kirby closer=2b37e83368ea src=release_tag np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
97. GHSA-3244-J874-RHC2 repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
98. GHSA-33Q9-F52J-GC75 repo=n8n-io/n8n closer=a4d0dfce2940 src=release_tag np=1 files=28 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
99. GHSA-35Q8-9MJ6-WJMF repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
100. GHSA-35WR-X7V6-9FV2 repo=hahwul/dalfox closer=1dcb01cbb196 src=release_tag np=1 files=3 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk

PR heads, merge refs, and release tags were resolved with anonymous git ls-remote. Shared closer SHAs across hulumi, kgateway, juju, osctrl, n8n, gitea, dalfox, and PraisonAI rows are not identity dedupe.

## Routing rule

ROUTE requires a named exact closer object and a recognized atomic source_matcher hit before that closer on a plausible same-mechanism non-test hunk, plus landed topology and a vulnerable released artifact. Reject AI-on-fix, carrier-only trailers, sibling file, old bug, comment-only overlap, test-only closers, filename overlap, issue/PR branding, squash trailer transfer, OSV introduced, and nearby history. Inspected slice 60 produced 0 ROUTE rows. No PASS proposal.

## Blockers

- Inspected ranks 41-100 produced 0 ROUTE rows. No PASS proposal.
- Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
- Recovered PR/release objects without a pre-closer same-mechanism AI hunk are not seven-gate proof.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
