# No-pre-fix PR-member recall repair ranks 541-600 (canonical94)

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
Ranked-order sha256 `68bc832c821f876b99633e23552c152402f30c255e880acdeae23f28f3c5f470`. Prefix ranks 1-540 sha256 `8ac63f8eda91596857d54b000baf3e4e5b310190b217afbae30736453d6e7f3b`.
Canonical94 overlap with the 729: 0. Later terminal identities after the nextqueue freeze overlapping the 729: 0. Remaining 729.

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 541-600. Reconstructed ranks 1-540 are disjoint from this slice. On-disk packets cover ranks 1-420 as REJECT_ROUTING ROUTE=0. Ranks 421-540 are reconstructed for disjointness and were not re-inspected here. Keyword-only rank was not used.

## Inspected ranks 541-600 (60)

541. GHSA-RR73-568V-28F8 repo=getgrav/grav fix=5a12f9be8314 np=1 files=10 code=8 members=417 REJECT_ROUTING
542. GHSA-VGMM-27FC-VMGP repo=MahoCommerce/maho fix=db54a1b44e9b np=1 files=10 code=7 members=0 REJECT_ROUTING
543. GHSA-VJ3M-2G9H-VM4P repo=getgrav/grav fix=5a12f9be8314 np=1 files=10 code=8 members=417 REJECT_ROUTING
544. GHSA-W48R-JPPP-RCFW repo=getgrav/grav fix=5a12f9be8314 np=1 files=10 code=8 members=417 REJECT_ROUTING
545. GHSA-W8CG-7JCJ-4VV2 repo=getgrav/grav fix=5a12f9be8314 np=1 files=10 code=8 members=417 REJECT_ROUTING
546. GHSA-WWV8-CQPR-VX3M repo=modoboa/modoboa fix=27a7aa133d36 np=1 files=10 code=10 members=8 REJECT_ROUTING
547. GHSA-XC93-Q32J-CPCG repo=jon4hz/jellysweep fix=174663125109 np=1 files=10 code=8 members=0 REJECT_ROUTING
548. GHSA-4HX9-48XH-5MXR repo=keycloak/keycloak fix=754c070cf8ca np=1 files=11 code=3 members=0 REJECT_ROUTING
549. GHSA-4RC3-7J7W-M548 repo=harttle/liquidjs fix=e2311dfd6e82 np=1 files=11 code=8 members=0 REJECT_ROUTING
550. GHSA-6P96-CFG5-4VHP repo=koel/koel fix=1331f335342b np=1 files=11 code=11 members=0 REJECT_ROUTING
551. GHSA-7789-65HX-F26W repo=gtsteffaniak/filebrowser fix=af08800667b8 np=1 files=11 code=9 members=1 REJECT_ROUTING
552. GHSA-79Q9-WC6P-CF92 repo=librenms/librenms fix=15429580baba np=1 files=11 code=11 members=0 REJECT_ROUTING
553. GHSA-9PGF-384G-P7MV repo=nuxt/nuxt fix=4e35ae9babd9 np=1 files=11 code=11 members=0 REJECT_ROUTING
554. GHSA-G8C6-8FJJ-2R4M repo=miguelgrinberg/python-socketio fix=53f6be094257 np=1 files=11 code=10 members=0 REJECT_ROUTING
555. GHSA-H3RV-Q4RQ-PQCV repo=librenms/librenms fix=15429580baba np=1 files=11 code=11 members=0 REJECT_ROUTING
556. GHSA-HQJR-43R5-9Q58 repo=MobSF/Mobile-Security-Framework-MobSF fix=6f8a43c1b78d np=1 files=11 code=8 members=1 REJECT_ROUTING
557. GHSA-HXCR-HM88-MPQ6 repo=nuxt/nuxt fix=4e35ae9babd9 np=1 files=11 code=11 members=0 REJECT_ROUTING
558. GHSA-MGCP-MFP8-3Q45 repo=locize/i18next-locize-backend fix=8f81ad4707aa np=1 files=11 code=5 members=0 REJECT_ROUTING
559. GHSA-MHR3-J7M5-C7C9 repo=langchain-ai/langgraph fix=f91d79d0c869 np=1 files=11 code=1 members=0 REJECT_ROUTING
560. GHSA-RH3R-8PXM-HG4W repo=navidrome/navidrome fix=d7ec7355c903 np=1 files=11 code=9 members=0 REJECT_ROUTING
561. GHSA-W2CQ-G8G3-GM83 repo=helmetjs/content-security-policy-parser fix=b13a52554f01 np=1 files=11 code=4 members=0 REJECT_ROUTING
562. GHSA-WMFP-5Q7X-987X repo=harttle/liquidjs fix=3cd024d652dc np=1 files=11 code=2 members=0 REJECT_ROUTING
563. GHSA-3329-GHMP-JMV5 repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
564. GHSA-4675-36F9-WF6R repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
565. GHSA-CFFC-MXRF-MHH4 repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
566. GHSA-HGRH-QX5J-JFWX repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
567. GHSA-M273-6V24-X4M4 repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
568. GHSA-Q89C-Q3H5-W34G repo=i18next/i18next-http-backend fix=4cee84f229c6 np=1 files=12 code=6 members=0 REJECT_ROUTING
569. GHSA-R8G5-CGF2-4M4M repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
570. GHSA-RRXM-2PVV-M66X repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
571. GHSA-VCQX-V2MG-7CHX repo=neo4j-contrib/mcp-neo4j fix=5b9fbdda6401 np=1 files=12 code=6 members=0 REJECT_ROUTING
572. GHSA-VQMV-47XG-9WPR repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
573. GHSA-W54X-XFXG-4GXQ repo=neuvector/neuvector fix=f9ddbdf42031 np=1 files=12 code=12 members=0 REJECT_ROUTING
574. GHSA-X843-G5MX-G377 repo=mmaitre314/picklescan fix=70c1c6c31beb np=1 files=12 code=3 members=0 REJECT_ROUTING
575. GHSA-3P8M-J85Q-PGMJ repo=netty/netty fix=9d804c54ce96 np=1 files=13 code=11 members=0 REJECT_ROUTING
576. GHSA-74M6-4HJP-7226 repo=klever-io/klever-go fix=333f6ec91090 np=1 files=13 code=13 members=0 REJECT_ROUTING
577. GHSA-JC6W-WMFC-FH33 repo=klever-io/klever-go fix=333f6ec91090 np=1 files=13 code=13 members=0 REJECT_ROUTING
578. GHSA-JJWV-57XH-XR6R repo=gotenberg/gotenberg fix=06b2b2e10c52 np=1 files=13 code=10 members=0 REJECT_ROUTING
579. GHSA-VVFJ-2JQX-52JM repo=jupyterlab/jupyterlab fix=88ef373039a8 np=1 files=13 code=9 members=0 REJECT_ROUTING
580. GHSA-3GF5-CXQ9-W223 repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
581. GHSA-3VG9-H568-4W9M repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
582. GHSA-49GJ-C84Q-6QM9 repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
583. GHSA-4WHJ-RM5R-C2V8 repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
584. GHSA-5QWP-399C-MJWF repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
585. GHSA-6VQJ-C2Q5-J97W repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
586. GHSA-6W4W-5W54-RJVR repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
587. GHSA-7CQ8-MJ8X-J263 repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
588. GHSA-8R4J-24QV-FMQ9 repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
589. GHSA-9W88-8RMG-7G2P repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
590. GHSA-9XPH-J2H6-G47V repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
591. GHSA-CJ3C-V495-4XQH repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
592. GHSA-F3F2-MCXC-PWJX repo=n8n-io/n8n fix=f73fae6fe7fc np=1 files=14 code=14 members=12 REJECT_ROUTING
593. GHSA-F54Q-57X4-JG88 repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
594. GHSA-FQQ6-7VQF-W3FG repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
595. GHSA-G344-HCPH-8VGG repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
596. GHSA-HFMV-HHH3-43F2 repo=n8n-io/n8n fix=7940384a8504 np=1 files=14 code=14 members=0 REJECT_ROUTING
597. GHSA-J343-8V2J-FF7W repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
598. GHSA-M869-42CG-3XWR repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
599. GHSA-P9W7-82W4-7Q8M repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
600. GHSA-Q77W-MWJJ-7MQX repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, and sibling path did not qualify. 8 rows had local PR members from nearby merges; 4 had an atomic source_matcher member that landed in mainline ancestry; none had added lines overlapping closer deleted lines on a fix-touched mechanism-relevant code path.

## Conservation

bucket 729 = inspected through 600 + unreviewed 129. Equation 729=600+129. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Remaining after this slice: 129.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
