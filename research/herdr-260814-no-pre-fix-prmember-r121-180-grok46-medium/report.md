# No-pre-fix PR-member recall repair ranks 121-180 (canonical94)

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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 121-180. Ranks 1-60 and 61-120 were prior REJECT_ROUTING and are disjoint. Keyword-only rank was not used.

## Inspected ranks 121-180 (60)

121. GHSA-QPPM-G56G-FPVP repo=hotwired/turbo fix=899df356e9f4 np=1 files=1 code=1 members=0 REJECT_ROUTING
122. GHSA-QRFH-CC86-VC8C repo=Leantime/leantime fix=3f8b2c634611 np=1 files=1 code=1 members=0 REJECT_ROUTING
123. GHSA-QWVM-WQQ8-8J69 repo=MANTRA-Chain/mantrachain fix=30d36c46e982 np=1 files=1 code=1 members=0 REJECT_ROUTING
124. GHSA-QXRW-F6FH-34R7 repo=LemmyNet/lemmy fix=4afff1699d08 np=1 files=1 code=1 members=0 REJECT_ROUTING
125. GHSA-R42M-953Q-6VJX repo=grokability/snipe-it fix=28f493d84d05 np=1 files=1 code=1 members=0 REJECT_ROUTING
126. GHSA-R83H-CRWP-3VM7 repo=ImageMagick/ImageMagick fix=5facfecf1abb np=1 files=1 code=1 members=0 REJECT_ROUTING
127. GHSA-R99P-5442-Q2X2 repo=ImageMagick/ImageMagick fix=e87695b32279 np=1 files=1 code=1 members=0 REJECT_ROUTING
128. GHSA-RCVQ-M9J9-6F4G repo=hapijs/inert fix=a65e5b271b5c np=1 files=1 code=1 members=0 REJECT_ROUTING
129. GHSA-RJV5-9PX2-FQW6 repo=gogs/gogs fix=961a79e8f9f2 np=1 files=1 code=1 members=0 REJECT_ROUTING
130. GHSA-RQ7W-G337-39QQ repo=nuxt/nuxt fix=55c75b78c989 np=1 files=1 code=1 members=0 REJECT_ROUTING
131. GHSA-V4W8-49PV-MF72 repo=gunthercox/ChatterBot fix=de89fe648139 np=1 files=1 code=1 members=0 REJECT_ROUTING
132. GHSA-V67W-737X-V2C9 repo=ImageMagick/ImageMagick fix=d27b840a61b3 np=1 files=1 code=1 members=0 REJECT_ROUTING
133. GHSA-V7G2-M8C5-MF84 repo=ImageMagick/ImageMagick fix=1a51eb9af00c np=1 files=1 code=1 members=0 REJECT_ROUTING
134. GHSA-V84X-QVHG-F36R repo=mantisbt/mantisbt fix=78c0af63d1fe np=1 files=1 code=1 members=0 REJECT_ROUTING
135. GHSA-V994-63CG-9WJ3 repo=ImageMagick/ImageMagick fix=880057ce34f6 np=1 files=1 code=1 members=0 REJECT_ROUTING
136. GHSA-VCRW-4XVV-JH49 repo=mantisbt/mantisbt fix=297773fbb238 np=1 files=1 code=1 members=4 REJECT_ROUTING
137. GHSA-VG76-XMHG-J5X3 repo=lxc/incus fix=4bca6332e822 np=1 files=1 code=1 members=0 REJECT_ROUTING
138. GHSA-VHQJ-F5CJ-9X8H repo=ImageMagick/ImageMagick fix=ffe589df5ff8 np=1 files=1 code=1 members=0 REJECT_ROUTING
139. GHSA-VJ76-C3G6-QR5V repo=mafintosh/tar-fs fix=0bd54cdf06da np=1 files=1 code=1 members=0 REJECT_ROUTING
140. GHSA-VMHF-C436-HXJ4 repo=jupyterlab/jupyterlab fix=4e61e07d0a91 np=1 files=1 code=1 members=0 REJECT_ROUTING
141. GHSA-VPXV-R9PG-7GPR repo=ImageMagick/ImageMagick fix=c9c87dbaba56 np=1 files=1 code=1 members=0 REJECT_ROUTING
142. GHSA-W332-Q679-J88P repo=honojs/hono fix=cf9a78db4d0a np=1 files=1 code=1 members=0 REJECT_ROUTING
143. GHSA-W469-HJ2F-JPR5 repo=harness/harness fix=21c5ce42ae13 np=1 files=1 code=1 members=0 REJECT_ROUTING
144. GHSA-W8MW-FRC6-R7M8 repo=ImageMagick/ImageMagick fix=7cfae4da24a9 np=1 files=1 code=1 members=0 REJECT_ROUTING
145. GHSA-WG3G-GVX5-2PMV repo=ImageMagick/ImageMagick fix=0349df6d43d6 np=1 files=1 code=1 members=0 REJECT_ROUTING
146. GHSA-WGXP-Q8XQ-WPP9 repo=ImageMagick/ImageMagick fix=436e5d2589e3 np=1 files=1 code=1 members=0 REJECT_ROUTING
147. GHSA-X275-H9J4-7P4H repo=getkirby/kirby fix=95a51480a426 np=1 files=1 code=1 members=5 REJECT_ROUTING
148. GHSA-X3C7-22C8-PRG7 repo=handcraftedinthealps/goodby-csv fix=acd14c6ed851 np=1 files=1 code=1 members=0 REJECT_ROUTING
149. GHSA-X46R-MF5G-XPR6 repo=nicolargo/glances fix=39161f0d6fd7 np=1 files=1 code=1 members=0 REJECT_ROUTING
150. GHSA-X9H5-R9V2-VCWW repo=ImageMagick/ImageMagick fix=4c72003e9e54 np=1 files=1 code=1 members=0 REJECT_ROUTING
151. GHSA-XC79-566C-J4QX repo=microstack-tech/parallax fix=f759e9090aaf np=1 files=1 code=1 members=0 REJECT_ROUTING
152. GHSA-XG82-2HRV-HF64 repo=grokability/snipe-it fix=676a9958895a np=1 files=1 code=1 members=0 REJECT_ROUTING
153. GHSA-XGM3-V4R9-WFGM repo=ImageMagick/ImageMagick fix=a253d1b124eb np=1 files=1 code=1 members=0 REJECT_ROUTING
154. GHSA-XM59-RQC7-HHVF repo=jupyter/nbconvert fix=c9ac1d104045 np=1 files=1 code=1 members=0 REJECT_ROUTING
155. GHSA-XPG8-7M6M-JF56 repo=ImageMagick/ImageMagick fix=9db96365ecab np=1 files=1 code=1 members=0 REJECT_ROUTING
156. GHSA-22CC-P3C6-WPVM repo=h3js/h3 fix=7791538e15ca np=1 files=2 code=2 members=0 REJECT_ROUTING
157. GHSA-2HCP-GJRF-7FHC repo=micronaut-projects/micronaut-core fix=1e2ba2c14386 np=1 files=2 code=2 members=24 REJECT_ROUTING
158. GHSA-2HM2-HC3V-44H9 repo=lepture/mistune fix=c4093c4742ed np=1 files=2 code=2 members=0 REJECT_ROUTING
159. GHSA-2P2X-HPG8-CQP2 repo=litestar-org/litestar fix=eb87703b309e np=1 files=2 code=2 members=0 REJECT_ROUTING
160. GHSA-33P9-3P43-82VQ repo=jupyter/jupyter_core fix=5e8965600add np=1 files=2 code=2 members=0 REJECT_ROUTING
161. GHSA-34X7-HFP2-RC4V repo=isaacs/node-tar fix=f4a7aa9bc3d7 np=1 files=2 code=2 members=0 REJECT_ROUTING
162. GHSA-36HH-X5P5-JGC8 repo=hapijs/content fix=3850079550c1 np=1 files=2 code=2 members=0 REJECT_ROUTING
163. GHSA-378J-3JFJ-8R9F repo=ipld/go-ipld-prime fix=e43bf4a27055 np=1 files=2 code=2 members=0 REJECT_ROUTING
164. GHSA-395F-4HP3-45GV repo=ljharb/shell-quote fix=7ff5488599d0 np=1 files=2 code=2 members=0 REJECT_ROUTING
165. GHSA-3C9M-GQ32-G4JX repo=neuvector/scanner fix=c2f0f9268468 np=1 files=2 code=2 members=0 REJECT_ROUTING
166. GHSA-3HRH-PFW6-9M5X repo=honojs/hono fix=905aedbc2066 np=1 files=2 code=2 members=0 REJECT_ROUTING
167. GHSA-3JMG-P96M-M328 repo=gtsteffaniak/filebrowser fix=1802e1281135 np=1 files=2 code=1 members=0 REJECT_ROUTING
168. GHSA-3JVJ-V6W2-H948 repo=LemmyNet/lemmy fix=1f06693b7080 np=1 files=2 code=2 members=0 REJECT_ROUTING
169. GHSA-3JXR-9VMJ-R5CP repo=juliangruber/brace-expansion fix=835d6be91201 np=1 files=2 code=2 members=0 REJECT_ROUTING
170. GHSA-3M5V-4XP5-GJG2 repo=graphiti-api/graphiti fix=ddb5ad2b6933 np=1 files=2 code=2 members=0 REJECT_ROUTING
171. GHSA-3P24-9X7V-7789 repo=NationalSecurityAgency/emissary fix=1faf33f2494c np=1 files=2 code=2 members=0 REJECT_ROUTING
172. GHSA-3QMC-CJ7Q-62HV repo=litestar-org/litestar fix=6930a20ceb54 np=1 files=2 code=2 members=0 REJECT_ROUTING
173. GHSA-3V7F-55P6-F55P repo=micromatch/picomatch fix=4516eb521f13 np=1 files=2 code=2 members=0 REJECT_ROUTING
174. GHSA-453R-G2PG-CXXQ repo=lxc/incus fix=d81d49e746e1 np=1 files=2 code=2 members=0 REJECT_ROUTING
175. GHSA-49MX-FJ45-Q3P6 repo=n8n-io/n8n fix=2c4c29531997 np=1 files=2 code=2 members=0 REJECT_ROUTING
176. GHSA-49PC-8936-WVFP repo=lettermint/lettermint-node fix=24a17acbc242 np=1 files=2 code=2 members=0 REJECT_ROUTING
177. GHSA-4GRM-H2QV-H6W6 repo=netty/netty fix=75127cab731e np=1 files=2 code=2 members=0 REJECT_ROUTING
178. GHSA-4J5M-WC25-PVH7 repo=msiemens/onenote.rs fix=c9267b2c96e2 np=1 files=2 code=1 members=0 REJECT_ROUTING
179. GHSA-4MRV-5P47-P938 repo=msgpack/msgpack-ruby fix=5627d71606b5 np=1 files=2 code=2 members=1 REJECT_ROUTING
180. GHSA-4PJ9-G833-QX53 repo=lettre/lettre fix=f5efffc88360 np=1 files=2 code=2 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor member did not qualify. 4 rows had local PR members from containing-merge or first-party pull topology; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path. Later same-path markers that were not ancestors of the closer were REJECT_ROUTING.

## Conservation

bucket 729 = inspected through rank 180 (60+60+60) + unreviewed 549. Equation 729=180+549. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from ranks 1-60 and 61-120.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
