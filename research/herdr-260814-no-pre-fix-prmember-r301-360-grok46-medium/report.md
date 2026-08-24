# No-pre-fix PR-member recall repair ranks 301-360 (canonical94)

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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 301-360. Ranks 1-60, 61-120, and 121-180 were prior REJECT_ROUTING and are disjoint. Ranks 181-240 and 241-300 are active and remain disjoint. Keyword-only rank was not used.

## Inspected ranks 301-360 (60)

301. GHSA-XJ56-P8MM-QMXJ repo=hiyouga/LLaMA-Factory fix=bb7bf51554d4 np=1 files=2 code=2 members=0 REJECT_ROUTING
302. GHSA-XMF8-CVQR-RFGJ repo=nextauthjs/next-auth fix=e707770f00c5 np=1 files=2 code=2 members=0 REJECT_ROUTING
303. GHSA-2933-Q333-QG83 repo=i18next/i18next-fs-backend fix=3ab0448087da np=1 files=3 code=2 members=0 REJECT_ROUTING
304. GHSA-32HF-8JW3-V4QQ repo=netty/netty-incubator-codec-ohttp fix=7ad38d5cc282 np=1 files=3 code=3 members=4 REJECT_ROUTING
305. GHSA-37QJ-FRW5-HHJH repo=NaturalIntelligence/fast-xml-parser fix=4e387f61c4a5 np=1 files=3 code=3 members=0 REJECT_ROUTING
306. GHSA-3M4Q-JMJ6-R34Q repo=keras-team/keras fix=8a37f9dadd8e np=1 files=3 code=3 members=0 REJECT_ROUTING
307. GHSA-3M86-C9X3-VWM9 repo=Graylog2/graylog2-server fix=6936bd16a783 np=1 files=3 code=2 members=0 REJECT_ROUTING
308. GHSA-43W5-MMXV-CPVH repo=micronaut-projects/micronaut-core fix=1afe509677c5 np=1 files=3 code=2 members=0 REJECT_ROUTING
309. GHSA-4894-XQV6-VRFQ repo=mindsdb/mindsdb fix=87a44bdb2b97 np=1 files=3 code=2 members=0 REJECT_ROUTING
310. GHSA-4WCM-7HJF-6XW5 repo=ninofiliu/interactive-git-checkout fix=8dd832dd302a np=1 files=3 code=3 members=1 REJECT_ROUTING
311. GHSA-52JP-GJ8W-J6XH repo=modelcontextprotocol/ruby-sdk fix=afb968c468c1 np=1 files=3 code=2 members=16 REJECT_ROUTING
312. GHSA-58CW-G322-P94V repo=lepture/mistune fix=a3cb6e565530 np=1 files=3 code=3 members=11 REJECT_ROUTING
313. GHSA-5P9G-J988-PCWV repo=modelcontextprotocol/ruby-sdk fix=35466605319a np=1 files=3 code=2 members=15 REJECT_ROUTING
314. GHSA-5RMX-256W-8MJ9 repo=h44z/wg-portal fix=fe4485037a25 np=1 files=3 code=3 members=85 REJECT_ROUTING
315. GHSA-65MP-FQ8V-56JR repo=jugmac00/flask-reuploaded fix=d64c6b2f71cb np=1 files=3 code=2 members=0 REJECT_ROUTING
316. GHSA-7C4V-FWGW-9RF7 repo=nuxt/nuxt fix=00f71bb6517a np=1 files=3 code=3 members=0 REJECT_ROUTING
317. GHSA-7CJH-XX4R-QH3F repo=getsentry/sentry-java fix=8bfa9cceab40 np=1 files=3 code=2 members=3 REJECT_ROUTING
318. GHSA-83G3-92JG-28CX repo=isaacs/node-tar fix=2cb1120bcefe np=1 files=3 code=3 members=0 REJECT_ROUTING
319. GHSA-89G2-XW5C-V95P repo=icip-cas/PPTAgent fix=418491a9a1c0 np=1 files=3 code=3 members=0 REJECT_ROUTING
320. GHSA-9277-MP7X-85JF repo=jelmer/dulwich fix=e3331b3b3a12 np=1 files=3 code=2 members=14 REJECT_ROUTING
321. GHSA-9299-C6M4-MJHC repo=jetty/jetty.project fix=8259eabbc70a np=1 files=3 code=3 members=12 REJECT_ROUTING
322. GHSA-95FJ-3W7G-4R27 repo=nuclio/nuclio fix=5352d7e16cf9 np=1 files=3 code=3 members=0 REJECT_ROUTING
323. GHSA-9MV7-3C64-MMQW repo=ietf-tools/xml2rfc fix=73fb1c91fc62 np=1 files=3 code=3 members=0 REJECT_ROUTING
324. GHSA-9P4W-FQ8M-2HP7 repo=nyariv/SandboxJS fix=75c8009db32e np=1 files=3 code=1 members=5 REJECT_ROUTING
325. GHSA-9PPJ-QMQM-Q256 repo=isaacs/node-tar fix=f48b5fa3b798 np=1 files=3 code=2 members=0 REJECT_ROUTING
326. GHSA-C4P6-QG4M-9JMR repo=kedacore/keda fix=15c5677f65f8 np=1 files=3 code=3 members=0 REJECT_ROUTING
327. GHSA-C534-2W9C-X7FM repo=kite-org/kite fix=08116eed557f np=1 files=3 code=3 members=0 REJECT_ROUTING
328. GHSA-C89F-8G7G-59WJ repo=librenms/librenms fix=ebe6c79bf4ce np=1 files=3 code=3 members=0 REJECT_ROUTING
329. GHSA-CFMV-H8FX-85M7 repo=ietf-tools/xml2rfc fix=f2b245bc0aee np=1 files=3 code=3 members=0 REJECT_ROUTING
330. GHSA-CFVJ-7RX7-FC7C repo=openclaw/openclaw fix=17ede52a4be3 np=1 files=3 code=2 members=0 REJECT_ROUTING
331. GHSA-CH7Q-53V8-73PC repo=goauthentik/authentik fix=6672e6aaa41e np=1 files=3 code=2 members=0 REJECT_ROUTING
332. GHSA-CPM7-CFPX-3HVP repo=NationalSecurityAgency/emissary fix=e2078417464b np=1 files=3 code=2 members=0 REJECT_ROUTING
333. GHSA-CXRH-J4JR-QWG3 repo=nodejs/undici fix=f317618ec287 np=1 files=3 code=3 members=0 REJECT_ROUTING
334. GHSA-F238-RGGP-82M3 repo=navidrome/navidrome fix=e5438552c63f np=1 files=3 code=3 members=0 REJECT_ROUTING
335. GHSA-F886-M6HF-6M8V repo=juliangruber/brace-expansion fix=311ac0d54994 np=1 files=3 code=1 members=4 REJECT_ROUTING
336. GHSA-FHP4-PR5J-46M5 repo=julianhille/MuhammaraJS fix=a98c07780241 np=1 files=3 code=2 members=7 REJECT_ROUTING
337. GHSA-G97X-GVCM-X72H repo=lepture/mistune fix=a3cb6e565530 np=1 files=3 code=3 members=11 REJECT_ROUTING
338. GHSA-GGP9-C99X-54GP repo=kubevirt/kubevirt fix=231dc69723f3 np=1 files=3 code=3 members=29 REJECT_ROUTING
339. GHSA-HF5P-Q87M-CRJ7 repo=junrar/junrar fix=d77e9a83eb72 np=1 files=3 code=2 members=0 REJECT_ROUTING
340. GHSA-HJQC-JX6G-RWP9 repo=keras-team/keras fix=47fcb397ee4c np=1 files=3 code=3 members=0 REJECT_ROUTING
341. GHSA-HM36-FFRH-C77C repo=litestar-org/litestar fix=42a89e043e50 np=1 files=3 code=2 members=0 REJECT_ROUTING
342. GHSA-HRCW-XC63-G29M repo=icip-cas/PPTAgent fix=418491a9a1c0 np=1 files=3 code=3 members=0 REJECT_ROUTING
343. GHSA-J273-M5QQ-6825 repo=junrar/junrar fix=947ff1d33f00 np=1 files=3 code=2 members=0 REJECT_ROUTING
344. GHSA-J49H-6577-5XWQ repo=gmrtd/gmrtd fix=54469a95e5a2 np=1 files=3 code=3 members=0 REJECT_ROUTING
345. GHSA-JJ6P-3M75-G2P3 repo=matrix-org/matrix-rust-sdk fix=4ea0418abefa np=1 files=3 code=2 members=0 REJECT_ROUTING
346. GHSA-JQ43-27X9-3V86 repo=netty/netty fix=1782e8c2060a np=1 files=3 code=3 members=0 REJECT_ROUTING
347. GHSA-M732-5P4W-X69G repo=honojs/hono fix=45ba3bf9e3df np=1 files=3 code=3 members=3 REJECT_ROUTING
348. GHSA-MC68-Q9JW-2H3V repo=openclaw/openclaw fix=771f23d36b95 np=1 files=3 code=2 members=132 REJECT_ROUTING
349. GHSA-MH29-5H37-FV8M repo=nodeca/js-yaml fix=383665ff4248 np=1 files=3 code=2 members=0 REJECT_ROUTING
350. GHSA-MXXR-JV3V-6PGC repo=jlowin/fastmcp fix=2a20f54617a3 np=1 files=3 code=3 members=14 REJECT_ROUTING
351. GHSA-PXHG-7XR2-W7XG repo=icip-cas/PPTAgent fix=418491a9a1c0 np=1 files=3 code=3 members=0 REJECT_ROUTING
352. GHSA-Q5JF-9VFQ-H4H7 repo=helm/helm fix=05fa37973dc9 np=1 files=3 code=3 members=0 REJECT_ROUTING
353. GHSA-Q5QW-H33P-QVWR repo=honojs/hono fix=6a0607a929d8 np=1 files=3 code=3 members=11 REJECT_ROUTING
354. GHSA-QC2Q-QHF3-235M repo=nearform/get-jwks fix=1706a177a80a np=1 files=3 code=3 members=0 REJECT_ROUTING
355. GHSA-QFFP-2RHF-9H96 repo=isaacs/node-tar fix=7bc755dd85e6 np=1 files=3 code=3 members=0 REJECT_ROUTING
356. GHSA-QW6Q-3PGR-5CWQ repo=kubevirt/kubevirt fix=09eafa068ec0 np=1 files=3 code=2 members=24 REJECT_ROUTING
357. GHSA-R5MX-6WC6-7H9W repo=mickhansen/dottie.js fix=7e8fa1345a4b np=1 files=3 code=3 members=0 REJECT_ROUTING
358. GHSA-RHH3-JPG6-66XH repo=mermaid-js/mermaid fix=59b22fad2b3b np=1 files=3 code=2 members=130 REJECT_ROUTING
359. GHSA-RJR6-RCGV-9M7M repo=modelcontextprotocol/ruby-sdk fix=ba543083a759 np=1 files=3 code=2 members=16 REJECT_ROUTING
360. GHSA-RM2Q-F7JV-3CFP repo=indico/indico fix=0adb70f0ed66 np=1 files=3 code=3 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor member did not qualify. 21 rows had local PR members from containing-merge or nearby-merge topology; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path. 4 rows had a recognized source_matcher on history or members, all rejected as carrier trailer, sibling, test/docs/lockfile, or no mechanism-path overlap. Later same-path markers that were not ancestors of the closer were REJECT_ROUTING.

## Conservation

bucket 729 = inspected through rank 360 (60+60+60+60+60+60) + unreviewed 369. Equation 729=360+369. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from ranks 1-60, 61-120, 121-180, and from active ranks 181-240 and 241-300.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
