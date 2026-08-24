# No-pre-fix PR-member recall repair ranks 361-420 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Authoritative inventory result SHA256 `cecb1710279e2df3e7635d3ee91e0d85f25e453528ea18aa29299380ff6dbbd9` replay `87ddd177ec134e756666d5f0ff0bb662038a8f91a87a1482e5ce9ed35d5672c7`.
Corroborating ranks 61-120 result SHA256 `81b693b0307fe800212cd7d1c00d0f1a06e59e1d86f6a576a214cf99789d5838`.
Corroborating ranks 121-180 result SHA256 `9d8df176577c9d306cc30c26bc930d868d3c1a179b1657ecaf6591b8953d500b`.
Corroborating ranks 181-240 result SHA256 `e067fffaf6399ee7785acb1d4fdfa0e0294de586e38df5e715a0d6ba7fb71963`.
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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 361-420. Ranks 1-240 are completed REJECT_ROUTING ROUTE=0. Ranks 241-300 and 301-360 are active and remain disjoint. Keyword-only rank was not used.

## Inspected ranks 361-420 (60)

361. GHSA-RVQX-WPFH-MFX7 repo=langflow-ai/langflow fix=faac4db133de np=1 files=3 code=3 members=31 REJECT_ROUTING
362. GHSA-RW6C-XP26-225V repo=ImageMagick/ImageMagick fix=26088a83d71e np=1 files=3 code=3 members=0 REJECT_ROUTING
363. GHSA-VP3H-GHGH-JR7G repo=nrwl/nx fix=2b20c2da39d2 np=1 files=3 code=3 members=0 REJECT_ROUTING
364. GHSA-W62V-XXXG-MG59 repo=honojs/hono fix=cd3f6f7194f0 np=1 files=3 code=3 members=0 REJECT_ROUTING
365. GHSA-W9HF-35Q4-VCJW repo=justinas/nosurf fix=ec9bb776d8e5 np=1 files=3 code=2 members=0 REJECT_ROUTING
366. GHSA-WC8C-QW6V-H7F6 repo=honojs/node-server fix=455015be1697 np=1 files=3 code=2 members=0 REJECT_ROUTING
367. GHSA-WQV2-4WPG-8HC9 repo=miniflux/v2 fix=76df99f3a3db np=1 files=3 code=3 members=0 REJECT_ROUTING
368. GHSA-WR4H-V87W-P3R7 repo=h3js/h3 fix=0e751b405906 np=1 files=3 code=3 members=0 REJECT_ROUTING
369. GHSA-X34H-54CW-9825 repo=nektos/act fix=c28c27e141e8 np=1 files=3 code=3 members=0 REJECT_ROUTING
370. GHSA-X958-RVG6-956W repo=matrix-org/matrix-rust-sdk fix=13c1d2048286 np=1 files=3 code=3 members=11 REJECT_ROUTING
371. GHSA-XPCF-PG52-R92G repo=honojs/hono fix=48fa2233bc09 np=1 files=3 code=3 members=0 REJECT_ROUTING
372. GHSA-XPH5-278P-26QX repo=lobehub/lobe-chat fix=70f52a3c1fad np=1 files=3 code=3 members=7 REJECT_ROUTING
373. GHSA-XR73-JQ5P-CH8R repo=goauthentik/authentik fix=9dbdfc3f1be0 np=1 files=3 code=2 members=55 REJECT_ROUTING
374. GHSA-23C5-XMQV-RM74 repo=isaacs/minimatch fix=11d0df6165d1 np=1 files=4 code=3 members=0 REJECT_ROUTING
375. GHSA-2464-8J7C-4CJM repo=go-viper/mapstructure fix=742921c9ba28 np=1 files=4 code=4 members=3 REJECT_ROUTING
376. GHSA-24QX-W28J-9M6P repo=jupyter-server/jupyter_server fix=057869a327c4 np=1 files=4 code=4 members=0 REJECT_ROUTING
377. GHSA-29QV-4J9F-FJW5 repo=josdejong/mathjs fix=513ab2a0e010 np=1 files=4 code=4 members=0 REJECT_ROUTING
378. GHSA-2RGP-F66F-4499 repo=intranda/goobi-viewer-core fix=326980f24ce1 np=1 files=4 code=3 members=132 REJECT_ROUTING
379. GHSA-38C7-23HJ-2WGQ repo=n8n-io/n8n fix=3839e310bd4c np=1 files=4 code=4 members=0 REJECT_ROUTING
380. GHSA-3CCG-X393-96V8 repo=go-vikunja/vikunja fix=89c17d3b23e2 np=1 files=4 code=4 members=0 REJECT_ROUTING
381. GHSA-4948-F92Q-F432 repo=nocobase/nocobase fix=202e2b8efe44 np=1 files=4 code=4 members=1 REJECT_ROUTING
382. GHSA-4VGF-2CM4-MP7C repo=nrkno/terraform-provider-windns fix=c76f69610c1b np=1 files=4 code=4 members=0 REJECT_ROUTING
383. GHSA-4W32-2493-32G7 repo=libp2p/rust-yamux fix=b1aae09d60c0 np=1 files=4 code=4 members=0 REJECT_ROUTING
384. GHSA-6RW7-VPXM-498P repo=ljharb/qs fix=3086902ecf7f np=1 files=4 code=4 members=0 REJECT_ROUTING
385. GHSA-6V7P-G79W-8964 repo=msgpack/msgpack-python fix=2c56ddb5d002 np=1 files=4 code=2 members=0 REJECT_ROUTING
386. GHSA-794G-X443-36F7 repo=keycloak/keycloak fix=b40a25908d93 np=1 files=4 code=4 members=0 REJECT_ROUTING
387. GHSA-79QW-G77V-2VFH repo=inspektor-gadget/inspektor-gadget fix=7c83ad84ff7a np=1 files=4 code=2 members=3 REJECT_ROUTING
388. GHSA-83XR-5XXR-MH92 repo=lxc/incus fix=487edf5984fa np=1 files=4 code=4 members=9 REJECT_ROUTING
389. GHSA-87F9-HVMW-GH4P repo=mermaid-js/mermaid fix=64769738d5b5 np=1 files=4 code=3 members=3 REJECT_ROUTING
390. GHSA-89V5-38XR-9M4J repo=gitroomhq/postiz-app fix=0ad89ccd26b1 np=1 files=4 code=4 members=0 REJECT_ROUTING
391. GHSA-8JHR-WPCM-HH4H repo=HumanSignal/label-studio fix=97db9e7b1678 np=1 files=4 code=2 members=1282 REJECT_ROUTING
392. GHSA-8P9X-46GM-QFX2 repo=kyverno/kyverno fix=e0ba4de4f1e0 np=1 files=4 code=4 members=0 REJECT_ROUTING
393. GHSA-8X88-C5MF-7J5W repo=isaacs/node-tar fix=9e78bf058b2c np=1 files=4 code=4 members=0 REJECT_ROUTING
394. GHSA-937X-GPQR-72GG repo=jugmac00/flask-reuploaded fix=5ded76092429 np=1 files=4 code=2 members=0 REJECT_ROUTING
395. GHSA-964W-F6GJ-5236 repo=goshs-labs/goshs fix=f3ef599e4091 np=1 files=4 code=3 members=0 REJECT_ROUTING
396. GHSA-9GM9-C8MQ-VQ7M repo=MervinPraison/PraisonAI fix=47bff65413be np=1 files=4 code=2 members=0 REJECT_ROUTING
397. GHSA-CG4G-M8JX-VJV2 repo=HackingRepo/dssrf-js fix=9211f91bf532 np=1 files=4 code=3 members=0 REJECT_ROUTING
398. GHSA-CWQ5-8PVQ-J65J repo=ndsev/zserio fix=a9932de4b5ee np=1 files=4 code=4 members=0 REJECT_ROUTING
399. GHSA-CWXW-98QJ-8QJX repo=guzzle/guzzle fix=7f537cded191 np=1 files=4 code=3 members=1 REJECT_ROUTING
400. GHSA-F49M-VF83-692W repo=i18next/i18next-http-middleware fix=7c6d26f137d3 np=1 files=4 code=3 members=0 REJECT_ROUTING
401. GHSA-F577-QRJJ-4474 repo=honojs/hono fix=5463db273547 np=1 files=4 code=4 members=0 REJECT_ROUTING
402. GHSA-F6QQ-3M3H-4G42 repo=go-pkgz/auth fix=c0b15ee72a84 np=1 files=4 code=4 members=0 REJECT_ROUTING
403. GHSA-FCW5-X6J4-CCMP repo=jupyter-server/jupyter_server fix=6cbee8d65e71 np=1 files=4 code=3 members=0 REJECT_ROUTING
404. GHSA-FWJ3-42WH-8673 repo=gtsteffaniak/filebrowser fix=112740bdd41d np=1 files=4 code=3 members=0 REJECT_ROUTING
405. GHSA-G446-98W2-8P5W repo=guzzle/guzzle fix=b9944c161b12 np=1 files=4 code=3 members=3 REJECT_ROUTING
406. GHSA-G956-2F74-RMV7 repo=kyndryl-open-source/hashi-vault-js fix=ea2f76052d36 np=1 files=4 code=1 members=3 REJECT_ROUTING
407. GHSA-GR75-JV2W-4656 repo=langchain-ai/langchain fix=dcaf7795a3e6 np=1 files=4 code=4 members=981 REJECT_ROUTING
408. GHSA-H3HW-29FV-2X75 repo=graphql-hive/envelop fix=ab49fa259a51 np=1 files=4 code=3 members=0 REJECT_ROUTING
409. GHSA-P6JQ-8VC4-79F6 repo=nuxt/nuxt fix=2566d2046bcc np=1 files=4 code=4 members=12 REJECT_ROUTING
410. GHSA-PHWH-4F42-GWF3 repo=henrygd/beszel fix=311095cfddda np=1 files=4 code=4 members=0 REJECT_ROUTING
411. GHSA-PXCC-8665-PHX8 repo=lsegal/yard fix=f78c19f0dd33 np=1 files=4 code=4 members=0 REJECT_ROUTING
412. GHSA-R3JF-HM7Q-QFW5 repo=mantisbt/mantisbt fix=c99a41272532 np=1 files=4 code=4 members=29 REJECT_ROUTING
413. GHSA-V39M-5M9J-M9W9 repo=mondeja/mkdocs-include-markdown-plugin fix=7466d67aa0de np=1 files=4 code=3 members=0 REJECT_ROUTING
414. GHSA-WG2Q-39H6-66X9 repo=goshs-labs/goshs fix=f3ef599e4091 np=1 files=4 code=3 members=0 REJECT_ROUTING
415. GHSA-WMRF-HV6W-MR66 repo=kysely-org/kysely fix=0a602bff2f44 np=1 files=4 code=4 members=0 REJECT_ROUTING
416. GHSA-WXHW-J4HC-FMQ6 repo=nyariv/SandboxJS fix=345aee6566e4 np=1 files=4 code=3 members=3 REJECT_ROUTING
417. GHSA-XF4J-XP2R-RQQX repo=honojs/hono fix=b470278920ff np=1 files=4 code=4 members=0 REJECT_ROUTING
418. GHSA-XMGR-9PQC-H5VW repo=nektos/act fix=0c739c8e39c4 np=1 files=4 code=2 members=0 REJECT_ROUTING
419. GHSA-XRHX-7G5J-RCJ5 repo=honojs/hono fix=c831020fb1fa np=1 files=4 code=4 members=0 REJECT_ROUTING
420. GHSA-XXJR-MMJV-4GPG repo=lodash/lodash fix=edadd452146f np=1 files=4 code=4 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor/unlanded member did not qualify. 18 rows had local PR members from containing-merge or self-merge topology; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path. Source_matcher hits on members without a same-mechanism hunk were REJECT_ROUTING.

## Conservation

bucket 729 = inspected through rank 420 (60+60+60+60+60+60+60) + unreviewed 309. Equation 729=420+309. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from ranks 1-240 and from active ranks 241-360.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
