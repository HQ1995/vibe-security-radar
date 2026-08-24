# No-same-repo-fix recovery ranks 101-160 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Fix-recovery, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. Anonymous public git only. No credentials. Temporary listing used ls-remote only.

## Exclusive bucket reconstruction

Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet itself, the ranks-1-40 recovery packet, this packet, `.leader-quarantine-260814`, and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Reviewed identities 34389. Not withdrawn, has a GitHub repository from a matching first-party advisory URL or bare homepage or OSV range repo, and no same-repo 40-hex commit URL under strict terminator regex `https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)`.
Minus nextqueue-era list terminals and canonical94 overlap `GHSA-V52W-28XH-V562` yields exclusive no_same_repo_fix 10631.
no_same_repo_fix_ids sha256 `47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5`.
Canonical94 overlap with the 10631: 0 (V52W already removed while forming the named bucket). Later terminal identities after the nextqueue freeze overlapping the 10631: 51. Remaining 10580.

Selector: remaining 10580 with a first-party repository advisory URL plus a same-repository PR, compare/patch, release, or patched-version reference, ranked by local clone, published on or after 2025-05-01, low PR fanout, signal order PR then compare/patch then release then patched-version, then uppercase GHSA ID.
This packet inspects ranks 101-160 of that recoverable ranking (60 identities). Ranks 1-40 match the frozen recovery packet. Ranks 101-160 are unique and disjoint from ranks 1-100 by ranking identity. Did not pad. Did not infer causality from OSV ranges.

## Conservation

named bucket 10631 = ranking_prefix_160 + unreviewed 10471. Equation 10631=160+10471. Holds.
assigned 60 = REJECT_ROUTING 60 + ROUTE 0 + unreviewed_on_slice 0. Equation 60=60+0. Holds. Did not pad.
PASS=0. ROUTE 0. selected 0. rejected 60. unreviewed remainder of named bucket 10471.

## Disjointness

Ranks 1-100 n=100 unique. Ranks 101-160 n=60 unique. Intersection empty. Shared release SHAs across sibling advisories are not identity dedupe.

## Inspected ranks 101-160 (60)

101. GHSA-37CX-329C-33X3 repo=go-git/go-git closer=48a1ae05eec4 src=release_tag np=2 files=0 nontest=0 members=0 REJECT_ROUTING merge_update_not_mechanism
102. GHSA-37J7-56XC-C468 repo=idno/idno closer=f9c8cca6ffa2 src=release_tag np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_mechanism_code_on_closer
103. GHSA-37W4-HWHX-4RC4 repo=jupyterlab/jupyterlab closer=f51404192bf6 src=release_tag np=1 files=134 nontest=128 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
104. GHSA-387M-J3P9-3PHP repo=nocodb/nocodb closer=391834484b11 src=release_tag np=2 files=0 nontest=0 members=0 REJECT_ROUTING merge_update_not_mechanism
105. GHSA-39CP-6679-8XV2 repo=getkirby/kirby closer=d952dfc0a890 src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
106. GHSA-39VQ-49QM-R2MC repo=getkirby/kirby closer=2b37e83368ea src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
107. GHSA-3C4R-6P77-XWR7 repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=13 members=0 REJECT_ROUTING nearby_history_ai_not_mechanism
108. GHSA-3G8R-4PFX-JMFH repo=netty/netty closer=fca0764703b3 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
109. GHSA-3J3Q-WP9X-585P repo=kcp-dev/kcp closer=42f2e029c322 src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
110. GHSA-3JFP-46X4-XGFJ repo=lsegal/yard closer=b13dddc40246 src=release_tag np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
111. GHSA-3QP7-7MW8-WX86 repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
112. GHSA-3R34-VQ8M-39GH repo=Netflix/lemur closer=f59087a51b98 src=release_tag np=2 files=0 nontest=0 members=0 REJECT_ROUTING merge_update_not_mechanism
113. GHSA-3R5C-2XXX-H872 repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
114. GHSA-3RFQ-4WPF-QQW3 repo=micronaut-projects/micronaut-core closer=324db9bc8fd0 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_mechanism_code_on_closer
115. GHSA-3VFF-HJQV-M7H8 repo=jupyterhub/jupyterhub closer=a1ebcba4755c src=release_tag np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
116. GHSA-3VWC-QWHC-3MJ7 repo=nicolargo/glances closer=988cad684745 src=release_tag np=1 files=6 nontest=6 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
117. GHSA-3XC2-H5R3-WV3R repo=kimai/kimai closer=d456cd3ce2ec src=release_tag np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_mechanism_code_on_closer
118. GHSA-3XC5-WRHM-F963 repo=go-git/go-git closer=ea3e7ec9dfc5 src=release_tag np=2 files=0 nontest=0 members=0 REJECT_ROUTING merge_update_not_mechanism
119. GHSA-4269-MCFH-CP7Q repo=indico/indico closer=12652ce3d8a9 src=release_tag np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
120. GHSA-45RP-9P97-H852 repo=nocodb/nocodb closer=391834484b11 src=release_tag np=2 files=0 nontest=0 members=0 REJECT_ROUTING merge_update_not_mechanism
121. GHSA-473P-56XX-VG67 repo=kiwitcms/Kiwi closer=e77a0ccc5625 src=release_tag np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
122. GHSA-4C99-QJ7H-P3VG repo=jupyter/nbconvert closer=78ed30837a60 src=release_tag np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
123. GHSA-4H9Q-P5J4-XVVH repo=lin-snow/Ech0 closer=ac5648296972 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
124. GHSA-4HGG-C4RR-6H7F repo=gravitl/netmaker closer=6b7d33fa7749 src=release_tag np=1 files=10 nontest=10 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
125. GHSA-4MJ9-PF4R-CQRC repo=learningequality/kolibri closer=39ab253d6be8 src=release_tag np=2 files=0 nontest=0 members=0 REJECT_ROUTING merge_update_not_mechanism
126. GHSA-4MP9-239F-G9HG repo=netty/netty closer=fca0764703b3 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
127. GHSA-4PH2-F6PF-79WV repo=MervinPraison/PraisonAI closer=d80bff2d9aee src=release_tag np=1 files=20 nontest=20 members=0 REJECT_ROUTING filename_overlap_not_exact_hunk
128. GHSA-4RX4-4R3X-6534 repo=MervinPraison/PraisonAI closer=d80bff2d9aee src=release_tag np=1 files=20 nontest=20 members=0 REJECT_ROUTING filename_overlap_not_exact_hunk
129. GHSA-4V4H-M2QQ-PPGW repo=getkirby/kirby closer=274dca6df93d src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
130. GHSA-4W6R-5C2J-QF5F repo=nocodb/nocodb closer=4e6037f9fa1e src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
131. GHSA-4XJF-493Q-98P3 repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
132. GHSA-525J-95GF-766F repo=gtsteffaniak/filebrowser closer=09713b32a5f6 src=release_tag np=1 files=5 nontest=5 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
133. GHSA-5375-PQ7M-F5R2 repo=grpc/grpc-node closer=2c99fbddc969 src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
134. GHSA-54VG-PFH7-JQ95 repo=Netflix/lemur closer=4afd730de39f src=release_tag np=2 files=0 nontest=0 members=0 REJECT_ROUTING merge_update_not_mechanism
135. GHSA-555P-6GRF-MH7F repo=jelmer/dulwich closer=073f4dfa9840 src=release_tag np=1 files=4 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
136. GHSA-558V-64GR-WGG4 repo=netty/netty closer=fca0764703b3 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
137. GHSA-563Q-J3CM-6JXM repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
138. GHSA-5CVP-P7P4-MCX9 repo=markmhendrickson/neotoma closer=df63d59c8838 src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
139. GHSA-5F5R-95PG-XRPM repo=henrygd/beszel closer=6e3fd9083430 src=release_tag np=1 files=4 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
140. GHSA-5FHX-9Q32-Q257 repo=getkirby/kirby closer=2b37e83368ea src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
141. GHSA-5GM9-622F-QCG5 repo=librenms/librenms closer=49cf73a0b823 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING nearby_history_ai_not_mechanism
142. GHSA-5H3G-PX23-W6VW repo=mvt-project/mvt closer=1c971bd6a9e6 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
143. GHSA-5PVG-856G-CP85 repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
144. GHSA-5VH4-RGV7-P9G4 repo=gotenberg/gotenberg closer=db51f9026d13 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_mechanism_code_on_closer
145. GHSA-5W86-C3RQ-VJJ7 repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
146. GHSA-5X3R-WRVG-RP6Q repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
147. GHSA-5XRH-QMMQ-W6CH repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
148. GHSA-6269-CQXG-MHHV repo=lepture/mistune closer=067f90861088 src=release_tag np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
149. GHSA-652Q-GVQ3-74QV repo=n8n-io/n8n closer=ff05cd3be8c4 src=release_tag np=1 files=20 nontest=20 members=0 REJECT_ROUTING no_mechanism_code_on_closer
150. GHSA-676X-F7GG-47VC repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
151. GHSA-67WX-R9XR-X75X repo=lxc/incus closer=6255b3956027 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
152. GHSA-693F-PF34-72C5 repo=MervinPraison/PraisonAI closer=d80bff2d9aee src=release_tag np=1 files=20 nontest=20 members=0 REJECT_ROUTING filename_overlap_not_exact_hunk
153. GHSA-69HX-63PV-F8F4 repo=lin-snow/Ech0 closer=b934467d26b9 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
154. GHSA-6CQP-G7GG-8HR5 repo=netty/netty closer=fca0764703b3 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
155. GHSA-6GHJ-FRRJ-JJJ3 repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
156. GHSA-6GQR-MX34-WH8R repo=getkirby/kirby closer=d952dfc0a890 src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
157. GHSA-6JV9-X5W9-2CCM repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=47 members=0 REJECT_ROUTING no_mechanism_code_on_closer
158. GHSA-6XCX-7QMG-VJFQ repo=nocodb/nocodb closer=4e6037f9fa1e src=release_tag np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
159. GHSA-7545-FCXQ-7J24 repo=gitpython-developers/GitPython closer=5a15361e0e12 src=release_tag np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_mechanism_code_on_closer
160. GHSA-75QM-GP28-RCQ9 repo=n8n-io/n8n closer=a4d0dfce2940 src=release_tag np=1 files=28 nontest=28 members=0 REJECT_ROUTING no_mechanism_code_on_closer

Release tags were resolved with anonymous git ls-remote. Netty, NocoDB, Kirby, Gitea, and PraisonAI share closer SHAs across sibling advisories; shared SHA is not identity dedupe. Twelve tag objects are named on the remote but absent from the local clone; those rows reject for missing landed topology in the read-only clone.

## Routing rule

ROUTE requires a named exact closer object and a recognized atomic source_matcher hit before that closer on a plausible same-mechanism non-test hunk. Reject AI-on-fix, carrier-only trailers, sibling file, old bug, comment-only overlap, test-only closers, filename overlap, nearby history, and unfetched local objects. Inspected ranks 101-160 produced 0 ROUTE rows. No PASS proposal.

## Blockers

- Inspected ranks 101-160 produced 0 ROUTE rows. No PASS proposal.
- Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
- Recovered release objects without a pre-closer same-mechanism AI hunk are not seven-gate proof.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
