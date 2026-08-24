# No-pre-fix PR-member recall repair ranks 61-120 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Authoritative inventory result SHA256 `cecb1710279e2df3e7635d3ee91e0d85f25e453528ea18aa29299380ff6dbbd9` replay `87ddd177ec134e756666d5f0ff0bb662038a8f91a87a1482e5ce9ed35d5672c7`.
Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only.

## Exclusive bucket reconstruction

Same reconstruction as the inventory packet. Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet itself and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Exclusive walk on 34389 reviewed identities: withdrawn, no GitHub repository, no exact same-repo 40-hex commit, published before 2025-05-01, terminal verdict, no first-party repo-advisory URL, then local clone and fix object.
Structural remainder 803 = no_local_clone 5 + fix_object_missing 38 + object-present 760.
Object-present 760 minus nextqueue ai_hit 31 (queued 20 + leftover 11) = exclusive no_pre_fix_ai_marker 729.
no_pre_fix_ids sha256 `ffeceb62c6fa243e5865020390ba5de297d01ce3fc0ac1c9754f46d2739c63b1`.
Canonical94 overlap with the 729: 0. Later terminal identities after the nextqueue freeze overlapping the 729: 0. Remaining 729.

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 61-120. Ranks 1-60 were inventory REJECT_ROUTING and are disjoint. Keyword-only rank was not used.

## Inspected ranks 61-120 (60)

61. GHSA-F633-865Q-2MHH repo=mantisbt/mantisbt fix=44f490bcf20f np=1 files=1 code=1 members=2 REJECT_ROUTING
62. GHSA-F9VC-VF3R-PQQQ repo=goharbor/harbor fix=76c2c5f7cfd9 np=1 files=1 code=1 members=0 REJECT_ROUTING
63. GHSA-FH48-F69W-7VMP repo=mantisbt/mantisbt fix=80990f431531 np=1 files=1 code=1 members=22 REJECT_ROUTING
64. GHSA-FH55-Q5PJ-PXGW repo=ImageMagick/ImageMagick fix=5f0bcf986b8b np=1 files=1 code=1 members=0 REJECT_ROUTING
65. GHSA-FHQ3-2GF3-8F3J repo=MISP/misp-modules fix=01a522f2772f np=1 files=1 code=1 members=11 REJECT_ROUTING
66. GHSA-FMWG-QCQH-M992 repo=gotenberg/gotenberg fix=cfb48d9af48c np=1 files=1 code=1 members=0 REJECT_ROUTING
67. GHSA-FQX6-693C-F55G repo=librenms/librenms fix=3bea263e0244 np=1 files=1 code=1 members=0 REJECT_ROUTING
68. GHSA-FRC6-PWGR-C28W repo=librenms/librenms fix=706a77085f4d np=1 files=1 code=1 members=0 REJECT_ROUTING
69. GHSA-FVJF-68WH-RWP2 repo=mantisbt/mantisbt fix=df22697ae497 np=1 files=1 code=1 members=2 REJECT_ROUTING
70. GHSA-FW82-87P8-V6HP repo=getkirby/kirby fix=90acf7ed6d8d np=1 files=1 code=1 members=43 REJECT_ROUTING
71. GHSA-FWQW-2X5X-W566 repo=ImageMagick/ImageMagick fix=257200cb21de np=1 files=1 code=1 members=0 REJECT_ROUTING
72. GHSA-FWVM-GGF6-2P4X repo=ImageMagick/ImageMagick fix=ccdc01180276 np=1 files=1 code=1 members=0 REJECT_ROUTING
73. GHSA-G2PR-QXJG-7R2W repo=ImageMagick/ImageMagick fix=93ad259ce4f6 np=1 files=1 code=1 members=0 REJECT_ROUTING
74. GHSA-G582-8VWR-68H2 repo=mantisbt/mantisbt fix=4fe94f45fa2b np=1 files=1 code=1 members=19 REJECT_ROUTING
75. GHSA-G5PQ-48MJ-JVW8 repo=nicolargo/glances fix=d6808be66728 np=1 files=1 code=1 members=12 REJECT_ROUTING
76. GHSA-G9XJ-752Q-XH63 repo=go-vikunja/vikunja fix=363aa6642352 np=1 files=1 code=1 members=0 REJECT_ROUTING
77. GHSA-GGW7-9675-6V4V repo=mantisbt/mantisbt fix=0a93267deba4 np=1 files=1 code=1 members=2 REJECT_ROUTING
78. GHSA-GM37-QX7W-P258 repo=ImageMagick/ImageMagick fix=30ce0e8efbd7 np=1 files=1 code=1 members=0 REJECT_ROUTING
79. GHSA-GQ96-8W38-HHJ2 repo=librenms/librenms fix=ec89714d929e np=1 files=1 code=1 members=0 REJECT_ROUTING
80. GHSA-GRH9-37G7-53MJ repo=h44z/wg-portal fix=e62db0d62eba np=1 files=1 code=1 members=0 REJECT_ROUTING
81. GHSA-GVVW-8J96-8G5R repo=microsoft/msquic fix=1e6e999b1994 np=1 files=1 code=1 members=0 REJECT_ROUTING
82. GHSA-GWR3-X37H-H84V repo=ImageMagick/ImageMagick fix=c448c6920a98 np=1 files=1 code=1 members=0 REJECT_ROUTING
83. GHSA-GXCX-QJQP-8VJW repo=ImageMagick/ImageMagick fix=1e88fca11c7b np=1 files=1 code=1 members=0 REJECT_ROUTING
84. GHSA-H4X5-GVX6-3RWC repo=mantisbt/mantisbt fix=b262b4d2835b np=1 files=1 code=1 members=2 REJECT_ROUTING
85. GHSA-H5GX-45RJ-2H5J repo=kerberos-io/agent fix=51f1a52e170f np=1 files=1 code=1 members=19 REJECT_ROUTING
86. GHSA-H7RH-XFPJ-HPCM repo=minio/minio-java fix=f7a98d06b25e np=1 files=1 code=1 members=0 REJECT_ROUTING
87. GHSA-HM4X-R5HC-794F repo=ImageMagick/ImageMagick fix=29d82726c7ec np=1 files=1 code=1 members=0 REJECT_ROUTING
88. GHSA-J8G6-5GQC-MQ36 repo=neuron-core/neuron-ai fix=72735d0ea133 np=1 files=1 code=1 members=7 REJECT_ROUTING
89. GHSA-J96M-MJP6-99XR repo=ImageMagick/ImageMagick fix=c5b23cbf2119 np=1 files=1 code=1 members=0 REJECT_ROUTING
90. GHSA-JMR4-P576-V565 repo=knadh/listmonk fix=74dc5a01cfbb np=1 files=1 code=1 members=0 REJECT_ROUTING
91. GHSA-JVGR-9PH5-M8V4 repo=ImageMagick/ImageMagick fix=1c7767fc5f82 np=1 files=1 code=1 members=0 REJECT_ROUTING
92. GHSA-JVXV-2JJP-JXC3 repo=LemmyNet/lemmy fix=f47a03f56d17 np=1 files=1 code=1 members=0 REJECT_ROUTING
93. GHSA-M27R-M6RX-MHM4 repo=laravel/reverb fix=9ec26f8ffbb7 np=1 files=1 code=1 members=0 REJECT_ROUTING
94. GHSA-M3Q2-P4FW-W38M repo=nuxt/nuxt fix=4b054e9d95f8 np=1 files=1 code=1 members=0 REJECT_ROUTING
95. GHSA-M435-9V6R-V5F6 repo=MobSF/Mobile-Security-Framework-MobSF fix=f22c584aa7d4 np=1 files=1 code=1 members=0 REJECT_ROUTING
96. GHSA-M4G2-2Q66-VC9V repo=go-vikunja/vikunja fix=dd0b82f00a8c np=1 files=1 code=1 members=0 REJECT_ROUTING
97. GHSA-M5GR-86J6-99JP repo=gramps-project/gramps-web-api fix=3ed4342711e3 np=1 files=1 code=1 members=0 REJECT_ROUTING
98. GHSA-M68R-V472-JGQ9 repo=jupyterhub/jupyterhub fix=9c5ec277d3cd np=1 files=1 code=1 members=11 REJECT_ROUTING
99. GHSA-M7JM-9GC2-MPF2 repo=NaturalIntelligence/fast-xml-parser fix=943ef0eb1b2d np=1 files=1 code=1 members=0 REJECT_ROUTING
100. GHSA-M7PH-9558-MRX3 repo=mantisbt/mantisbt fix=2d3a55376054 np=1 files=1 code=1 members=13 REJECT_ROUTING
101. GHSA-MGX6-5CF9-RR43 repo=keras-team/keras fix=7360d4f0d764 np=1 files=1 code=1 members=0 REJECT_ROUTING
102. GHSA-MMG9-6M6J-JQQX repo=harttle/liquidjs fix=abc058be0f33 np=1 files=1 code=1 members=0 REJECT_ROUTING
103. GHSA-MPH4-Q2VM-W2PW repo=kubernetes-sigs/aws-efs-csi-driver fix=51806c22c575 np=1 files=1 code=1 members=13 REJECT_ROUTING
104. GHSA-MXVV-97WH-CFMM repo=ImageMagick/ImageMagick fix=2c55221f4d38 np=1 files=1 code=1 members=0 REJECT_ROUTING
105. GHSA-P33R-FQW2-RQMM repo=ImageMagick/ImageMagick fix=332c1566acc2 np=1 files=1 code=1 members=0 REJECT_ROUTING
106. GHSA-P6FR-RXQ7-XCG8 repo=mantisbt/mantisbt fix=26647b2e68ba np=1 files=1 code=1 members=13 REJECT_ROUTING
107. GHSA-P7FW-VJJM-2RWP repo=lxc/incus fix=254dfd2483ab np=1 files=1 code=1 members=27 REJECT_ROUTING
108. GHSA-PCVX-PH33-R5VV repo=ImageMagick/ImageMagick fix=cca607366fb3 np=1 files=1 code=1 members=0 REJECT_ROUTING
109. GHSA-PHCG-H58R-GMCQ repo=lf-edge/eve fix=d9383a7ee4e1 np=1 files=1 code=1 members=0 REJECT_ROUTING
110. GHSA-PHRQ-PC6R-F6GH repo=mantisbt/mantisbt fix=b349e5c890ee np=1 files=1 code=1 members=2 REJECT_ROUTING
111. GHSA-PJXJ-PCHX-4C3M repo=ImageMagick/ImageMagick fix=47ca7210515f np=1 files=1 code=1 members=0 REJECT_ROUTING
112. GHSA-PQGJ-2P96-RX85 repo=ImageMagick/ImageMagick fix=332c1566acc2 np=1 files=1 code=1 members=0 REJECT_ROUTING
113. GHSA-PWG5-6JFC-CRVH repo=ImageMagick/ImageMagick fix=3d653bea2df0 np=1 files=1 code=1 members=0 REJECT_ROUTING
114. GHSA-Q4Q8-7F2J-9H9F repo=lxc/incus fix=f74199f9983e np=1 files=1 code=1 members=31 REJECT_ROUTING
115. GHSA-Q7R4-HC83-HF2Q repo=gotenberg/gotenberg fix=405f1069c026 np=1 files=1 code=1 members=0 REJECT_ROUTING
116. GHSA-Q9VP-3WCG-8P4X repo=lxc/incus fix=ef006240ac24 np=1 files=1 code=1 members=31 REJECT_ROUTING
117. GHSA-QH3H-J545-H8C9 repo=ImageMagick/ImageMagick fix=66dc8f51c11b np=1 files=1 code=1 members=0 REJECT_ROUTING
118. GHSA-QJ6W-V29Q-4RGX repo=mantisbt/mantisbt fix=5fec0f448b7a np=1 files=1 code=1 members=2 REJECT_ROUTING
119. GHSA-QMWH-9M9C-H36M repo=gotenberg/gotenberg fix=15050a311b73 np=1 files=1 code=1 members=0 REJECT_ROUTING
120. GHSA-QPGX-JFCQ-R59F repo=ImageMagick/ImageMagick fix=0377e60b3c0d np=1 files=1 code=1 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor member did not qualify. 20 rows had local PR members from nearby merges; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path.

## Conservation

bucket 729 = inspected through rank 120 (60+60) + unreviewed 609. Equation 729=120+609. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from ranks 1-60.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
