# No-pre-fix PR-member recall repair ranks 241-300 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Authoritative inventory result SHA256 `cecb1710279e2df3e7635d3ee91e0d85f25e453528ea18aa29299380ff6dbbd9` replay `87ddd177ec134e756666d5f0ff0bb662038a8f91a87a1482e5ce9ed35d5672c7`.
Corroborating ranks 61-120 result SHA256 `81b693b0307fe800212cd7d1c00d0f1a06e59e1d86f6a576a214cf99789d5838` replay `f632fbaec5e58a89dc824077f871a2524fe3ce6d3424718387bc4590b9408f32`.
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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 241-300. Ranks 1-60, 61-120, and 121-180 are prior REJECT_ROUTING and are disjoint. Rank gap 181-240 is held for other slices and is disjoint. Keyword-only rank was not used.

## Inspected ranks 241-300 (60)

241. GHSA-J6F6-JP3P-53MW repo=juju/juju fix=22cdcf6b54c2 np=1 files=2 code=2 members=64 REJECT_ROUTING
242. GHSA-J92C-7V7G-GJ3F repo=mganss/HtmlSanitizer fix=0ac53dca30dd np=1 files=2 code=2 members=11 REJECT_ROUTING
243. GHSA-JC7G-X28F-3V3H repo=knadh/listmonk fix=d27d2c32cf3a np=1 files=2 code=2 members=0 REJECT_ROUTING
244. GHSA-JF9P-2FV9-2JP2 repo=jzeuzs/thread-amount fix=28860d4a3828 np=1 files=2 code=2 members=0 REJECT_ROUTING
245. GHSA-JMXC-HHWX-GVV3 repo=LemmyNet/lemmy fix=637151121a8e np=1 files=2 code=2 members=0 REJECT_ROUTING
246. GHSA-JP2Q-39XQ-3W4G repo=NaturalIntelligence/fast-xml-parser fix=239b64aa1fc5 np=1 files=2 code=2 members=0 REJECT_ROUTING
247. GHSA-JPV7-P47H-F43J repo=mbuesch/letmein fix=43207cd77580 np=1 files=2 code=2 members=1 REJECT_ROUTING
248. GHSA-JQX4-9GPQ-RPPM repo=misskey-dev/summaly fix=dfe6451012aa np=1 files=2 code=2 members=0 REJECT_ROUTING
249. GHSA-M6RX-7PVW-2F73 repo=Gitlawb/openclaude fix=7002cb302b78 np=1 files=2 code=2 members=0 REJECT_ROUTING
250. GHSA-MCV8-8M8X-48PG repo=gohugoio/hugo fix=479fe6c65493 np=1 files=2 code=2 members=1 REJECT_ROUTING
251. GHSA-MJQF-28PH-426H repo=kube-logging/logging-operator fix=cf437d7f1e05 np=1 files=2 code=2 members=29 REJECT_ROUTING
252. GHSA-MMPX-JH39-WRV6 repo=gtsteffaniak/filebrowser fix=6bfc3974192e np=1 files=2 code=1 members=0 REJECT_ROUTING
253. GHSA-MP2G-9VG9-F4CG repo=h3js/h3 fix=618ccf4f37b8 np=1 files=2 code=2 members=0 REJECT_ROUTING
254. GHSA-MP7C-M3RH-R56V repo=matrix-org/matrix-js-sdk fix=43c72d5bf5e2 np=1 files=2 code=2 members=9 REJECT_ROUTING
255. GHSA-MQQF-5WVP-8FH8 repo=go-chi/chi fix=6eb35881c0e4 np=1 files=2 code=2 members=0 REJECT_ROUTING
256. GHSA-P27M-HP98-6637 repo=ImageMagick/ImageMagick fix=6f431d445f3d np=1 files=2 code=2 members=0 REJECT_ROUTING
257. GHSA-P44Q-VQPR-4XMG repo=miguelgrinberg/Flask-HTTPAuth fix=b15ffe9e50e1 np=1 files=2 code=2 members=0 REJECT_ROUTING
258. GHSA-P849-8HWH-84J9 repo=nocobase/nocobase fix=68d64e3fcfb8 np=1 files=2 code=2 members=0 REJECT_ROUTING
259. GHSA-PR9R-GXGP-9RM8 repo=n8n-io/n8n fix=43c52a8b4f84 np=1 files=2 code=2 members=1 REJECT_ROUTING
260. GHSA-PRJ3-CCX8-P6X4 repo=netty/netty fix=be53dc3c9acd np=1 files=2 code=2 members=0 REJECT_ROUTING
261. GHSA-PXQ6-2PRW-CHJ9 repo=moby/moby fix=f4d6f25bf0c3 np=1 files=2 code=2 members=120 REJECT_ROUTING
262. GHSA-Q7JF-GF43-6X6P repo=honojs/hono fix=d9b8b4b73b4f np=1 files=2 code=2 members=3 REJECT_ROUTING
263. GHSA-QJX8-664M-686J repo=js-cookie/js-cookie fix=eb3c40e89731 np=1 files=2 code=1 members=0 REJECT_ROUTING
264. GHSA-QRVQ-68C2-7GRW repo=nats-io/nats-server fix=f77fb7c4535e np=1 files=2 code=2 members=16 REJECT_ROUTING
265. GHSA-QVQR-5CV7-WH35 repo=modelcontextprotocol/ruby-sdk fix=db40143402d6 np=1 files=2 code=2 members=15 REJECT_ROUTING
266. GHSA-QX2Q-88MX-VHG7 repo=gofiber/fiber fix=e115c08b8f05 np=1 files=2 code=2 members=0 REJECT_ROUTING
267. GHSA-R354-F388-2FHH repo=honojs/hono fix=edbf6eea8e6c np=1 files=2 code=2 members=0 REJECT_ROUTING
268. GHSA-R5FR-RJXR-66JC repo=lodash/lodash fix=3469357cff39 np=1 files=2 code=2 members=0 REJECT_ROUTING
269. GHSA-R5P3-955P-5GGQ repo=kyverno/kyverno fix=cbd7d4ca24de np=1 files=2 code=2 members=0 REJECT_ROUTING
270. GHSA-R5RP-J6WH-RVV4 repo=honojs/hono fix=cc067c855924 np=1 files=2 code=2 members=0 REJECT_ROUTING
271. GHSA-R64V-82FH-XC63 repo=juju/juju fix=402ff008dcc2 np=1 files=2 code=2 members=27 REJECT_ROUTING
272. GHSA-R6FJ-869H-4F6Q repo=netty/netty-incubator-codec-ohttp fix=28f977f29359 np=1 files=2 code=2 members=4 REJECT_ROUTING
273. GHSA-RCMH-QJQH-P98V repo=nodemailer/nodemailer fix=b61b9c0cfd68 np=1 files=2 code=2 members=4 REJECT_ROUTING
274. GHSA-RFJG-6M84-CRJ2 repo=go-vikunja/vikunja fix=5c2195f9fca9 np=1 files=2 code=2 members=0 REJECT_ROUTING
275. GHSA-RMP5-5JJ7-GMVF repo=mantisbt/mantisbt fix=de7bdeec36de np=1 files=2 code=2 members=2 REJECT_ROUTING
276. GHSA-RWM7-X88C-3G2P repo=netty/netty fix=0ec3d97fab37 np=1 files=2 code=2 members=0 REJECT_ROUTING
277. GHSA-V722-JCV5-W7MC repo=nats-io/nats-server fix=b5b63cfc35a5 np=1 files=2 code=2 members=18 REJECT_ROUTING
278. GHSA-V8VM-CQH8-Q87Q repo=nocobase/nocobase fix=4aecb60d151a np=1 files=2 code=2 members=0 REJECT_ROUTING
279. GHSA-VHJM-W67Q-G75C repo=hapijs/wreck fix=a5b6fac9c684 np=1 files=2 code=2 members=0 REJECT_ROUTING
280. GHSA-VMHH-8RXQ-FP9G repo=ImageMagick/ImageMagick fix=229fa96a988a np=1 files=2 code=2 members=0 REJECT_ROUTING
281. GHSA-VRW8-FXC6-2R93 repo=go-chi/chi fix=1be7ad938cc9 np=1 files=2 code=2 members=0 REJECT_ROUTING
282. GHSA-VVP7-H4FJ-M28W repo=gtsteffaniak/filebrowser fix=f3f4bbe80cb5 np=1 files=2 code=1 members=6 REJECT_ROUTING
283. GHSA-VXQ6-8CWM-WJ99 repo=librenms/librenms fix=8ade3d827d31 np=1 files=2 code=2 members=0 REJECT_ROUTING
284. GHSA-VXQX-RH46-Q2PG repo=litestar-org/litestar fix=85db6183a76f np=1 files=2 code=2 members=0 REJECT_ROUTING
285. GHSA-W4G9-MXGG-J532 repo=nezhahq/nezha fix=d06d539d34c1 np=1 files=2 code=2 members=119 REJECT_ROUTING
286. GHSA-W7FW-MJWX-W883 repo=ljharb/qs fix=f6a7abff1f13 np=1 files=2 code=2 members=0 REJECT_ROUTING
287. GHSA-W7RV-GFP4-J9J3 repo=mixxorz/slippers fix=16cc4ef4fa8a np=1 files=2 code=2 members=0 REJECT_ROUTING
288. GHSA-W96V-GF22-CRWP repo=n8n-io/n8n fix=11f8597d4ad6 np=1 files=2 code=2 members=0 REJECT_ROUTING
289. GHSA-WF42-42FG-FG84 repo=nestjs/nest fix=cbdf737cd6e7 np=1 files=2 code=2 members=20 REJECT_ROUTING
290. GHSA-WHMM-QJ9R-WVR2 repo=gotd/td fix=9d5d1f31ea50 np=1 files=2 code=2 members=17 REJECT_ROUTING
291. GHSA-WMMM-F939-6G9C repo=honojs/hono fix=9aff14bd727f np=1 files=2 code=2 members=0 REJECT_ROUTING
292. GHSA-WP53-J4WJ-2CFG repo=Kludex/python-multipart fix=9433f4bbc965 np=1 files=2 code=2 members=0 REJECT_ROUTING
293. GHSA-WWRJ-3HVJ-PRPM repo=misskey-dev/misskey fix=5512898463fa np=1 files=2 code=1 members=0 REJECT_ROUTING
294. GHSA-WXQ4-CC2Q-338Q repo=mar10/wsgidav fix=f894ed8656d7 np=1 files=2 code=1 members=0 REJECT_ROUTING
295. GHSA-X426-X7CC-3FPC repo=hapijs/wreck fix=b93323b63ad3 np=1 files=2 code=2 members=0 REJECT_ROUTING
296. GHSA-X445-F3H2-J279 repo=nextauthjs/next-auth fix=9f7a97fade9b np=1 files=2 code=2 members=0 REJECT_ROUTING
297. GHSA-X667-R589-43M7 repo=grokability/snipe-it fix=8bc7d50e35d9 np=1 files=2 code=2 members=120 REJECT_ROUTING
298. GHSA-XGM2-5F3F-MVVC repo=honojs/hono fix=aa921770d09b np=1 files=2 code=2 members=0 REJECT_ROUTING
299. GHSA-XH87-MX6M-69F3 repo=honojs/hono fix=41adbf56e252 np=1 files=2 code=2 members=11 REJECT_ROUTING
300. GHSA-XH92-RQRQ-227V repo=mastra-ai/mastra fix=7f2b528ba82d np=1 files=2 code=1 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor member did not qualify. 22 rows had local PR members from nearby merges or containing-merge; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path. File history on mechanism paths produced no recognized source_matcher ancestor bound to closer reversal. Two rows had test/docs-only markers and stayed REJECT_ROUTING.

## Conservation

bucket 729 = inspected through rank 300 + unreviewed 429. Equation 729=300+429. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from ranks 1-120, the 121-180 slice, and rank gap 181-240.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
