# No-pre-fix PR-member recall repair ranks 421-480 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Authoritative inventory result SHA256 `cecb1710279e2df3e7635d3ee91e0d85f25e453528ea18aa29299380ff6dbbd9` replay `87ddd177ec134e756666d5f0ff0bb662038a8f91a87a1482e5ce9ed35d5672c7`.
Corroborating ranks 61-120 result SHA256 `81b693b0307fe800212cd7d1c00d0f1a06e59e1d86f6a576a214cf99789d5838`.
Corroborating ranks 121-180 result SHA256 `9d8df176577c9d306cc30c26bc930d868d3c1a179b1657ecaf6591b8953d500b`.
Corroborating ranks 181-240 result SHA256 `e067fffaf6399ee7785acb1d4fdfa0e0294de586e38df5e715a0d6ba7fb71963`.
Corroborating ranks 241-300 result SHA256 `d4622d2dcd51dff5d0a117a2edb2ab20cb1c37e70e6dbd1a36604f2c4147f6b5`.
Corroborating ranks 301-360 result SHA256 `66e3d203f3176b6ea2fedd5517848707a09a9e3c24689e0d69f9a0a60ab8123c`.
Corroborating ranks 361-420 result SHA256 `d5dc14623c032dc3d93fc88e7ee7058923ba514e065f094d1fb1b368269f8216`.
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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 421-480. Ranks 1-420 are completed REJECT_ROUTING ROUTE=0 and are disjoint. Keyword-only rank was not used.

## Inspected ranks 421-480 (60)

421. GHSA-22M3-C7VP-49FJ repo=irrdnet/irrd fix=8408e0f1b9f4 np=1 files=5 code=3 members=0 REJECT_ROUTING
422. GHSA-373J-MHPF-84WG repo=JanssenProject/jans fix=92eea4d4637f np=1 files=5 code=4 members=141 REJECT_ROUTING
423. GHSA-37G4-QQQV-7M99 repo=intake/intake fix=d0c0b6b57c1c np=1 files=5 code=4 members=1 REJECT_ROUTING
424. GHSA-46H3-79WF-XR6C repo=mmaitre314/picklescan fix=f2dea43e0c83 np=1 files=5 code=2 members=0 REJECT_ROUTING
425. GHSA-496G-MMPW-J9X3 repo=misskey-dev/misskey fix=dc77d59f8712 np=1 files=5 code=5 members=56 REJECT_ROUTING
426. GHSA-5J98-MCP5-4VW2 repo=isaacs/node-glob fix=1e4e297342a0 np=1 files=5 code=1 members=0 REJECT_ROUTING
427. GHSA-5Q7P-7JGV-WW56 repo=gotenberg/gotenberg fix=3f01ca18d3cc np=1 files=5 code=2 members=0 REJECT_ROUTING
428. GHSA-6R9F-759J-HJGV repo=nyariv/SandboxJS fix=e01505b1ea49 np=1 files=5 code=3 members=0 REJECT_ROUTING
429. GHSA-8HJV-92Q9-G4XJ repo=micronaut-projects/micronaut-core fix=48f05ae8dc41 np=1 files=5 code=4 members=0 REJECT_ROUTING
430. GHSA-955R-X9J8-7RHH repo=mmaitre314/picklescan fix=f2dea43e0c83 np=1 files=5 code=2 members=0 REJECT_ROUTING
431. GHSA-C2C7-RCM5-VVQJ repo=micromatch/picomatch fix=5eceecd27543 np=1 files=5 code=3 members=0 REJECT_ROUTING
432. GHSA-CWC9-CP4J-MCVV repo=libp2p/js-libp2p fix=773dd80ded24 np=1 files=5 code=5 members=0 REJECT_ROUTING
433. GHSA-F67F-6CW9-8MQ4 repo=honojs/hono fix=cc0aa7ae327e np=1 files=5 code=5 members=266 REJECT_ROUTING
434. GHSA-FW87-FV5R-9FPW repo=gohugoio/hugo fix=f8b5fa09a649 np=1 files=5 code=4 members=0 REJECT_ROUTING
435. GHSA-GGJM-F3G4-RWMM repo=n8n-io/n8n fix=c2c3e08cdf33 np=1 files=5 code=5 members=15 REJECT_ROUTING
436. GHSA-GQ57-V332-7666 repo=n8n-io/n8n fix=e5edc60e3449 np=1 files=5 code=5 members=0 REJECT_ROUTING
437. GHSA-GXXH-8VCJ-W2MH repo=mckenziearts/livewire-markdown-editor fix=1e60eaa5781e np=1 files=5 code=4 members=0 REJECT_ROUTING
438. GHSA-H395-GR6Q-CPJC repo=Keats/jsonwebtoken fix=abbc3076742c np=1 files=5 code=3 members=0 REJECT_ROUTING
439. GHSA-H64W-W9PR-82M4 repo=mattiasw/ExifReader fix=c9d88b67e127 np=1 files=5 code=3 members=0 REJECT_ROUTING
440. GHSA-H669-8M4G-R2HC repo=modelcontextprotocol/ruby-sdk fix=772e0cb1f9db np=1 files=5 code=4 members=1 REJECT_ROUTING
441. GHSA-HPWG-XG7M-3P6M repo=JuneAndGreen/sm-crypto fix=85295a859d07 np=1 files=5 code=2 members=0 REJECT_ROUTING
442. GHSA-J4RH-7JCR-QM69 repo=MISP/misp-modules fix=52cda9caa003 np=1 files=5 code=5 members=35 REJECT_ROUTING
443. GHSA-JF52-3F2H-H9J5 repo=n8n-io/n8n fix=a61a5991093c np=1 files=5 code=5 members=0 REJECT_ROUTING
444. GHSA-JP94-3292-C3XV repo=heartcombo/devise fix=025fe2124f99 np=1 files=5 code=4 members=0 REJECT_ROUTING
445. GHSA-M4H2-MJFM-MP55 repo=mercurius-js/mercurius fix=5b56f60f4b0d np=1 files=5 code=5 members=0 REJECT_ROUTING
446. GHSA-PGX9-497M-6C4V repo=JuneAndGreen/sm-crypto fix=b1c824e58fdf np=1 files=5 code=3 members=0 REJECT_ROUTING
447. GHSA-PMHH-3W7G-XQP8 repo=jhy/jsoup fix=92f1aca55254 np=1 files=5 code=4 members=0 REJECT_ROUTING
448. GHSA-PRH4-VHFH-24MJ repo=goharbor/harbor fix=85e756486fc1 np=1 files=5 code=5 members=2 REJECT_ROUTING
449. GHSA-Q355-H244-969H repo=komari-monitor/komari fix=53171affcaf0 np=1 files=5 code=5 members=1 REJECT_ROUTING
450. GHSA-RWCV-WHM8-FMXM repo=GeoNode/geonode fix=e53bdeff331f np=1 files=5 code=2 members=0 REJECT_ROUTING
451. GHSA-V273-448J-V4QJ repo=harttle/liquidjs fix=f41c1fc02fe9 np=1 files=5 code=5 members=0 REJECT_ROUTING
452. GHSA-VVXF-WJ5W-6GJ5 repo=HemmeligOrg/Hemmelig.app fix=6c909e571d07 np=1 files=5 code=5 members=0 REJECT_ROUTING
453. GHSA-W937-FG2H-XHQ2 repo=locize/locize fix=d006b75fadb8 np=1 files=5 code=3 members=0 REJECT_ROUTING
454. GHSA-WFX3-6G53-9FGC repo=ImageMagick/ImageMagick fix=fe0a49a58ac5 np=1 files=5 code=5 members=0 REJECT_ROUTING
455. GHSA-23HP-3JRH-7FPW repo=isaacs/node-tar fix=2812e9338665 np=1 files=6 code=5 members=0 REJECT_ROUTING
456. GHSA-2G9V-7MR5-FGJG repo=l3montree-dev/devguard fix=6f38310bf93b np=1 files=6 code=6 members=1 REJECT_ROUTING
457. GHSA-387M-935M-C4VW repo=micronaut-projects/micronaut-core fix=6e88a972718d np=1 files=6 code=3 members=23 REJECT_ROUTING
458. GHSA-3W8Q-XQ97-5J7X repo=mozilla/rhino fix=2bcf4c43deac np=1 files=6 code=5 members=0 REJECT_ROUTING
459. GHSA-4MXG-3P6V-XGQ3 repo=node-saml/node-saml fix=31ead9411ebc np=1 files=6 code=4 members=3 REJECT_ROUTING
460. GHSA-7P3P-8QV8-M2VH repo=jetty/jetty.project fix=3e5a4daec196 np=1 files=6 code=6 members=84 REJECT_ROUTING
461. GHSA-7P5M-XRH7-769R repo=nyariv/SandboxJS fix=cc8f20b4928a np=1 files=6 code=3 members=0 REJECT_ROUTING
462. GHSA-86RG-8HC8-V82P repo=librenms/librenms fix=30d3dd7e5f5e np=1 files=6 code=6 members=120 REJECT_ROUTING
463. GHSA-8WPR-639P-CCRJ repo=nestjs/nest fix=c4cedda15a05 np=1 files=6 code=3 members=1 REJECT_ROUTING
464. GHSA-9G4J-V8W5-7X42 repo=goauthentik/authentik fix=7a4c6b9b50f8 np=1 files=6 code=4 members=94 REJECT_ROUTING
465. GHSA-9PF3-7RRR-X5JH repo=InternLM/lmdeploy fix=eb04b4281c57 np=1 files=6 code=6 members=0 REJECT_ROUTING
466. GHSA-C2W2-PRH8-QM98 repo=guzzle/psr7 fix=ddd64f17d4cc np=1 files=6 code=5 members=2 REJECT_ROUTING
467. GHSA-F7QQ-56WW-84CR repo=mmaitre314/picklescan fix=28a7b4ef7534 np=1 files=6 code=3 members=0 REJECT_ROUTING
468. GHSA-G796-FGMG-93MV repo=nodeca/js-yaml fix=3105455b81de np=1 files=6 code=1 members=0 REJECT_ROUTING
469. GHSA-G8F2-4F4F-5JQW repo=nyariv/SandboxJS fix=826865251232 np=1 files=6 code=3 members=0 REJECT_ROUTING
470. GHSA-GXW4-4FC5-9GR5 repo=GLips/Figma-Context-MCP fix=7f4b5859454b np=1 files=6 code=4 members=0 REJECT_ROUTING
471. GHSA-H5J9-CVRW-V5QH repo=knadh/listmonk fix=db82035d6193 np=1 files=6 code=5 members=0 REJECT_ROUTING
472. GHSA-JGW4-CR84-MQXG repo=mmaitre314/picklescan fix=28a7b4ef7534 np=1 files=6 code=3 members=0 REJECT_ROUTING
473. GHSA-JMR7-XGP7-CMFJ repo=NaturalIntelligence/fast-xml-parser fix=910dae5be2de np=1 files=6 code=5 members=0 REJECT_ROUTING
474. GHSA-JV4P-GJWQ-9R2J repo=ImageMagick/ImageMagick fix=077b42643212 np=1 files=6 code=6 members=0 REJECT_ROUTING
475. GHSA-M837-G268-MMV7 repo=node-saml/node-saml fix=31ead9411ebc np=1 files=6 code=4 members=3 REJECT_ROUTING
476. GHSA-MJQP-26HC-GRXG repo=mmaitre314/picklescan fix=28a7b4ef7534 np=1 files=6 code=3 members=0 REJECT_ROUTING
477. GHSA-P863-5FGM-RGQ4 repo=ImageMagick/ImageMagick fix=e046417675d5 np=1 files=6 code=6 members=0 REJECT_ROUTING
478. GHSA-Q6GH-6V2R-HJV3 repo=micronaut-projects/micronaut-core fix=64e539736b81 np=1 files=6 code=3 members=0 REJECT_ROUTING
479. GHSA-R399-636X-V7F6 repo=langchain-ai/langchainjs fix=e5063f9c6e99 np=1 files=6 code=5 members=0 REJECT_ROUTING
480. GHSA-R6Q2-HW4H-H46W repo=isaacs/node-tar fix=3b1abfae6500 np=1 files=6 code=5 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor/unlanded member did not qualify. 18 rows had local PR members from containing-merge or self-merge topology; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path. 3 rows had a recognized source_matcher on members, all rejected as carrier/sibling with no mechanism-path overlap or non-ancestor of the closer. File history on mechanism paths produced no recognized source_matcher ancestor bound to closer reversal. Source_matcher hits on members without a same-mechanism hunk were REJECT_ROUTING.

## Conservation

bucket 729 = inspected through rank 480 (60+60+60+60+60+60+60+60) + unreviewed 249. Equation 729=480+249. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from ranks 1-420. Remaining 249.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
