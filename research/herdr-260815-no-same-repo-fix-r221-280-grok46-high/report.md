# No-same-repo-fix recovery ranks 221-280 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Fix-recovery, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
Ranking freeze herdr-260814-no-same-repo-fix-recovery-grok46-high result SHA256 `6620de70c68eaecde0c82dd90bd2f637b866e2d94cbc04f70ef18b80c646567a`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. Temporary tag fetches were discarded. Anonymous public git only. No credentials.

## Exclusive bucket reconstruction

Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet itself, this packet, `.leader-quarantine-260814`, and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Reviewed identities 34389. Not withdrawn, has a GitHub repository from a matching first-party advisory URL or bare homepage or OSV range repo, and no same-repo 40-hex commit URL under strict terminator regex `https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)`.
Minus nextqueue-era list terminals and canonical94 overlap `GHSA-V52W-28XH-V562` yields exclusive no_same_repo_fix 10631.
no_same_repo_fix_ids sha256 `47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5`.
Canonical94 overlap with the 10631: 0 (V52W already removed while forming the named bucket). Later terminal identities after the nextqueue freeze overlapping the 10631: 51. Remaining 10580.

Selector: remaining 10580 with a first-party repository advisory URL plus a same-repository PR, compare/patch, release, or patched-version reference, ranked by local clone, published on or after 2025-05-01, low PR fanout, signal order PR then compare/patch then release then patched-version, then uppercase GHSA ID. Inspect ranks 221-280. Did not pad. Did not infer causality from OSV ranges.
Reconstructed ranks 1-220 are disjoint from this slice (overlap 0). Uniqueness of the 60 IDs holds. Prefix 40 from the ranking freeze matches the prior recovery packet.

## Conservation

named bucket 10631 = inspected through rank 280 + unreviewed remainder 10351. Equation 10631=280+10351. Holds.
assigned 60 = REJECT_ROUTING 60 + ROUTE 0 + unreviewed_on_slice 0. Equation 60=60+0. Holds. Did not pad.
PASS=0. ROUTE 0. selected 0. rejected 60. unreviewed remainder of bucket 10351.

## Inspected ranks 221-280 (60)

221. GHSA-CP3Q-VRJ2-GHHH repo=go-gitea/gitea closer=b969123b7fac src=release_tag_peel np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
222. GHSA-CP79-9MWR-WR49 repo=lin-snow/Ech0 closer=ac5648296972 src=release_tag_peel np=1 files=1 nontest=1 members=0 REJECT_ROUTING nearby_history
223. GHSA-CQ4Q-CV5G-R8Q5 repo=netty/netty closer=a41f7b289ce1 src=release_tag_peel np=1 files=62 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
224. GHSA-CXV7-GMMP-228P repo=nocodb/nocodb closer=4e6037f9fa1e src=release_tag np=2 files=6 nontest=5 members=6 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
225. GHSA-CXX3-HR75-4Q96 repo=getarcaneapp/arcane closer=e67b56c021f3 src=release_tag_peel np=1 files=3 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
226. GHSA-F292-66H9-FPMF repo=MervinPraison/PraisonAI closer=ed3a689f8c78 src=release_tag np=1 files=11 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
227. GHSA-F2H6-7XFR-XM8W repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=6 members=0 REJECT_ROUTING nearby_history
228. GHSA-FCRH-FQXH-6FX6 repo=idno/idno closer=f9c8cca6ffa2 src=release_tag np=1 files=3 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
229. GHSA-FF24-4PRJ-GPMJ repo=getarcaneapp/arcane closer=7eca47ced3c3 src=release_tag_peel np=1 files=3 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
230. GHSA-FFP3-3562-8CV3 repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=6 members=0 REJECT_ROUTING nearby_history
231. GHSA-FGW5-HP8F-XFHC repo=istio/istio closer=db606cedf03c src=release_tag_peel np=1 files=3 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
232. GHSA-FPG6-X68Q-5793 repo=n8n-io/n8n closer=7786117e9766 src=release_tag np=1 files=35 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
233. GHSA-FPX8-73GF-7X73 repo=makeplane/plane closer=c3a9f997899f src=release_tag np=1 files=6 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
234. GHSA-FRPW-3H2Q-4JJ6 repo=go-gitea/gitea closer=b969123b7fac src=release_tag_peel np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
235. GHSA-FVH2-GM75-J4J7 repo=nubo-db/dynoxide closer=2c01525aaf4c src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
236. GHSA-FVXX-GGMX-3CJG repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=6 members=0 REJECT_ROUTING nearby_history
237. GHSA-FW38-PC54-JVX9 repo=klever-io/klever-go closer=785b77ccb271 src=release_tag_peel np=1 files=3 nontest=1 members=0 REJECT_ROUTING sibling_file
238. GHSA-FWG7-53P4-G33C repo=lin-snow/Ech0 closer=b934467d26b9 src=release_tag_peel np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
239. GHSA-FWJ8-62R8-8P8M repo=lxc/incus closer=6255b3956027 src=release_tag_peel np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
240. GHSA-G3R5-9H93-4J2C repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
241. GHSA-G628-R368-6VH7 repo=geoserver/geoserver closer=3802dca765d9 src=release_tag np=1 files=279 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
242. GHSA-G72G-R7M4-9X4G repo=nocodb/nocodb closer=93adcf0cdc77 src=release_tag np=2 files=6 nontest=6 members=5 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
243. GHSA-G77H-45RF-HCX4 repo=mattiasw/ExifReader closer=0ea9d58c48fb src=release_tag_peel np=1 files=2 nontest=0 members=0 REJECT_ROUTING nearby_history
244. GHSA-G7HG-VRCF-MVMR repo=netty/netty closer=fca0764703b3 src=release_tag_peel np=1 files=47 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
245. GHSA-G8R9-G2V8-JV6F repo=github/copilot-cli closer=7aa08b3594ad src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
246. GHSA-G985-WJH9-QXXC repo=MervinPraison/PraisonAI closer=961f5046c9e8 src=release_tag np=1 files=27 nontest=7 members=0 REJECT_ROUTING nearby_history
247. GHSA-GCJF-9MGH-3P7G repo=netty/netty closer=fca0764703b3 src=release_tag_peel np=1 files=47 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
248. GHSA-GF2Q-C269-PQGC repo=harttle/liquidjs closer=c20c0af02d33 src=release_tag np=1 files=3 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
249. GHSA-GFHV-VQV2-4544 repo=jelmer/dulwich closer=073f4dfa9840 src=release_tag np=1 files=4 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
250. GHSA-GH4J-GQV2-49F6 repo=NaturalIntelligence/fast-xml-parser closer=7cb49e51cd06 src=release_tag_peel np=1 files=8 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
251. GHSA-GJ48-438W-JH9V repo=mozilla/bleach closer=f0355a7af005 src=release_tag_peel np=1 files=1 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
252. GHSA-GJRG-MPP7-G774 repo=miurahr/py7zr closer=e278bc05cc93 src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
253. GHSA-GM2X-2G9H-CCM8 repo=go-git/go-git closer=5e23dfd02db9 src=release_tag np=2 files=6 nontest=3 members=1 REJECT_ROUTING sibling_file
254. GHSA-GQ66-9CW5-J5JM repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
255. GHSA-H2QV-FJ59-J46J repo=netty/netty closer=f05f765d8146 src=release_tag_peel np=1 files=47 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
256. GHSA-H2X6-G7Q6-344V repo=go-gitea/gitea closer=b969123b7fac src=release_tag_peel np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
257. GHSA-H44J-F5R5-PH73 repo=n8n-io/n8n closer=a4d0dfce2940 src=release_tag np=1 files=28 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
258. GHSA-H4GH-22QQ-72R7 repo=miurahr/py7zr closer=e278bc05cc93 src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
259. GHSA-H56G-4QW7-2MXG repo=go-gitea/gitea closer=b969123b7fac src=release_tag_peel np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
260. GHSA-H5FH-7HWR-97MW repo=kimai/kimai closer=ebb54e9c0c5c src=release_tag np=1 files=17 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
261. GHSA-HF2G-6J7H-98WG repo=klever-io/klever-go closer=785b77ccb271 src=release_tag_peel np=1 files=3 nontest=1 members=0 REJECT_ROUTING sibling_file
262. GHSA-HJ85-PH9Q-78JG repo=nocodb/nocodb closer=93adcf0cdc77 src=release_tag np=2 files=6 nontest=6 members=5 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
263. GHSA-HM2H-WWWH-G49X repo=lin-snow/Ech0 closer=b934467d26b9 src=release_tag_peel np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
264. GHSA-HMJ5-JM8H-H9FH repo=kiwitcms/Kiwi closer=e77a0ccc5625 src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
265. GHSA-HMQR-WJMJ-376C repo=gravitl/netmaker closer=6b7d33fa7749 src=release_tag np=1 files=10 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
266. GHSA-HQXQ-HWQF-WG83 repo=monetr/monetr closer=0c7ce43bd564 src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
267. GHSA-HRR4-3WGR-68X3 repo=navidrome/navidrome closer=0c8f2a559c9b src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
268. GHSA-HVCG-QMG6-JM4C repo=netty/netty closer=f05f765d8146 src=release_tag_peel np=1 files=47 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
269. GHSA-HWC4-GMRW-5222 repo=gotenberg/gotenberg closer=190cad0ee254 src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
270. GHSA-HWG5-X759-7WJG repo=MervinPraison/PraisonAI closer=ed3a689f8c78 src=release_tag np=1 files=11 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
271. GHSA-HWMJ-QG4V-CVG9 repo=n8n-io/n8n closer=2320517c9a1e src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING comment_only_hunk
272. GHSA-HWRQ-8WXH-Q4XV repo=julien040/anyquery closer=66d5e684cd0a src=release_tag np=2 files=226 nontest=63 members=1 REJECT_ROUTING sibling_file
273. GHSA-J274-39QW-32C9 repo=getgrav/grav closer=58acfee40e64 src=release_tag_peel np=1 files=19 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
274. GHSA-J884-Q54Q-MMX3 repo=koxudaxi/datamodel-code-generator closer=a321547e8b94 src=release_tag np=1 files=3 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
275. GHSA-J9RX-RPPG-6HH4 repo=julien040/anyquery closer=66d5e684cd0a src=release_tag np=2 files=226 nontest=63 members=1 REJECT_ROUTING sibling_file
276. GHSA-JCJW-58RV-C452 repo=getkirby/kirby closer=d952dfc0a890 src=release_tag np=1 files=27 nontest=21 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
277. GHSA-JF2Q-463C-6F52 repo=mvt-project/androidqf closer=472203c2395f src=release_tag_peel np=2 files=6 nontest=5 members=3 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
278. GHSA-JF3G-4GWG-4H66 repo=nocodb/nocodb closer=93adcf0cdc77 src=release_tag np=2 files=6 nontest=6 members=5 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
279. GHSA-JFXC-V5G9-38XR repo=MervinPraison/PraisonAI closer=d80bff2d9aee src=release_tag np=1 files=20 nontest=13 members=0 REJECT_ROUTING nearby_history
280. GHSA-JHF3-XXHW-2WPP repo=go-git/go-git closer=5e23dfd02db9 src=release_tag np=2 files=6 nontest=3 members=1 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk

PR heads were absent on this slice. Release tags were resolved with anonymous git ls-remote. Shared tag SHAs are not identity dedupe.

## Routing rule

ROUTE requires a named exact closer object and a recognized atomic source_matcher hit before that closer on a plausible same-mechanism non-test hunk, plus landed topology and a released vulnerable artifact. Reject AI-on-fix, carrier-only trailers, sibling file, old bug, comment-only overlap, test-only closers, filename overlap, nearby history, PR branding, squash trailer transfer, and OSV introduced events. Inspected ranks 221-280 produced 0 ROUTE rows. No PASS proposal.

## Blockers

- Inspected ranks 221-280 produced 0 ROUTE rows. No PASS proposal.
- Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
- Recovered release/tag objects without a pre-closer same-mechanism AI hunk are not seven-gate proof.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
