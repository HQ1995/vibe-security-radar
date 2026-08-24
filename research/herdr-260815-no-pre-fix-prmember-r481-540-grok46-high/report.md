# No-pre-fix PR-member recall repair ranks 481-540 (canonical94)

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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 481-540. Ranks 1-420 are completed REJECT_ROUTING ROUTE=0 and match this reconstruction. Ranks 421-480 are the immediately preceding ranking prefix and remain disjoint. Keyword-only rank was not used.

## Inspected ranks 481-540 (60)

481. GHSA-W66H-J855-QR72 repo=geoserver/geoserver fix=dc9ff1c726dd np=1 files=6 code=2 members=0 REJECT_ROUTING
482. GHSA-W7X5-G22V-XQHR repo=jetty/jetty.project fix=82969c77f6da np=1 files=6 code=6 members=1 REJECT_ROUTING
483. GHSA-W8WR-V893-VJVP repo=isaacs/node-tar fix=e02a4e9e013c np=1 files=6 code=6 members=0 REJECT_ROUTING
484. GHSA-X8QP-WQQM-57PH repo=intlify/vue-i18n fix=49f982443ab8 np=1 files=6 code=6 members=0 REJECT_ROUTING
485. GHSA-XP7R-J8R6-J9H3 repo=milamer/parse-nested-form-data fix=527ad58eb486 np=1 files=6 code=2 members=0 REJECT_ROUTING
486. GHSA-227X-7MH8-3CF6 repo=gardener/gardener-extension-provider-aws fix=cb5045fc1462 np=1 files=7 code=7 members=0 REJECT_ROUTING
487. GHSA-3PPC-4F35-3M26 repo=isaacs/minimatch fix=2e111f3a79ab np=1 files=7 code=3 members=0 REJECT_ROUTING
488. GHSA-3VHC-576X-3QV4 repo=honojs/hono fix=190f6e28e2ca np=1 files=7 code=7 members=266 REJECT_ROUTING
489. GHSA-72C7-4G63-HPW5 repo=in-toto/go-witness fix=04ff20b600e2 np=1 files=7 code=4 members=0 REJECT_ROUTING
490. GHSA-7683-3W9X-CH42 repo=modelcontextprotocol/ruby-sdk fix=267b8fa62854 np=1 files=7 code=4 members=1 REJECT_ROUTING
491. GHSA-7R86-CG39-JMMJ repo=isaacs/minimatch fix=0bf499aa45f5 np=1 files=7 code=4 members=0 REJECT_ROUTING
492. GHSA-GQX7-99JW-6FPR repo=librenms/librenms fix=8e626b38ef92 np=1 files=7 code=3 members=35 REJECT_ROUTING
493. GHSA-H27M-3QW8-3PW8 repo=goharbor/harbor fix=dce7d9f5cffb np=1 files=7 code=7 members=0 REJECT_ROUTING
494. GHSA-JGVC-94C8-3CHC repo=geopython/pygeoapi fix=3a63f5b0cc62 np=1 files=7 code=5 members=2 REJECT_ROUTING
495. GHSA-M43G-M425-P68X repo=junit-team/junit-framework fix=d4fc834c8c1c np=1 files=7 code=3 members=0 REJECT_ROUTING
496. GHSA-M79R-R765-5F9J repo=lobehub/lobe-chat fix=9f044edd07ce np=1 files=7 code=6 members=4 REJECT_ROUTING
497. GHSA-P6X5-P4XF-CC4R repo=mauriciopoppe/math-codegen fix=4bb52d303068 np=1 files=7 code=6 members=0 REJECT_ROUTING
498. GHSA-QPX9-HPMF-5GMW repo=jashkenas/underscore fix=411e222eb0ca np=1 files=7 code=3 members=14 REJECT_ROUTING
499. GHSA-RJ4J-2JPH-GG43 repo=lf-edge/ekuiper fix=58362b089c76 np=1 files=7 code=7 members=0 REJECT_ROUTING
500. GHSA-4CC2-G9W2-FHF6 repo=mvantellingen/python-zeep fix=83eb07bc6c84 np=1 files=8 code=7 members=0 REJECT_ROUTING
501. GHSA-4GV9-MP8M-592R repo=langflow-ai/langflow fix=c188ec113c9c np=1 files=8 code=5 members=8 REJECT_ROUTING
502. GHSA-6FGX-X7M2-74QM repo=kxxt/tracexec fix=0dbe63214c86 np=1 files=8 code=8 members=0 REJECT_ROUTING
503. GHSA-6PVW-G552-53C5 repo=git-lfs/git-lfs fix=0cffe93176b8 np=1 files=8 code=6 members=19 REJECT_ROUTING
504. GHSA-84H7-RJJ3-6JX4 repo=netty/netty fix=77e81f1e5944 np=1 files=8 code=8 members=0 REJECT_ROUTING
505. GHSA-8FRV-Q972-9RQ5 repo=LFDT-Lockness/cggmp21 fix=9d98157e1515 np=1 files=8 code=7 members=6 REJECT_ROUTING
506. GHSA-98WM-CXPW-847P repo=invoiceninja/invoiceninja fix=b81a3fc30257 np=1 files=8 code=8 members=7 REJECT_ROUTING
507. GHSA-F659-372H-6X3X repo=netty/netty-incubator-codec-ohttp fix=3d3b4e527fc8 np=1 files=8 code=8 members=0 REJECT_ROUTING
508. GHSA-H34R-JXQM-QGPR repo=juju/utils fix=766f27d7bcd1 np=1 files=8 code=8 members=1 REJECT_ROUTING
509. GHSA-JVFF-X2QM-6286 repo=josdejong/mathjs fix=0aee2f61866e np=1 files=8 code=8 members=0 REJECT_ROUTING
510. GHSA-MGHP-5CQ4-V6MG repo=grokability/snipe-it fix=e37649212861 np=1 files=8 code=8 members=4 REJECT_ROUTING
511. GHSA-RR89-W3H9-M66J repo=mattiasw/ExifReader fix=5f116128adc1 np=1 files=8 code=5 members=0 REJECT_ROUTING
512. GHSA-245V-P8FJ-VWM2 repo=juju/juju fix=26ff93c903d5 np=1 files=9 code=8 members=4 REJECT_ROUTING
513. GHSA-2FVJ-HGJ9-J2GR repo=jetty/jetty.project fix=4bcdbc7db387 np=1 files=9 code=8 members=0 REJECT_ROUTING
514. GHSA-3F29-PQWF-V4J4 repo=getgrav/grav fix=c66dfeb5ff67 np=1 files=9 code=8 members=417 REJECT_ROUTING
515. GHSA-6PX8-MR29-CJ4R repo=iterative/datachain fix=914b95610620 np=1 files=9 code=9 members=165 REJECT_ROUTING
516. GHSA-HG73-4W7G-Q96W repo=nyariv/SandboxJS fix=abc02f657279 np=1 files=9 code=8 members=0 REJECT_ROUTING
517. GHSA-HMCX-CH82-3FV2 repo=getgrav/grav fix=c66dfeb5ff67 np=1 files=9 code=8 members=417 REJECT_ROUTING
518. GHSA-PJP7-Q6WP-97QX repo=geonetwork/core-geonetwork fix=0d74f673dfc9 np=1 files=9 code=8 members=0 REJECT_ROUTING
519. GHSA-PWX3-QCGW-VH7H repo=gogs/gogs fix=070df61ecd14 np=1 files=9 code=1 members=0 REJECT_ROUTING
520. GHSA-V66J-6WWF-JC57 repo=mercurius-js/mercurius fix=962d402ec7a9 np=1 files=9 code=6 members=0 REJECT_ROUTING
521. GHSA-VH45-F885-3848 repo=JuneAndGreen/sm-crypto fix=1f9bd7bd160c np=1 files=9 code=6 members=0 REJECT_ROUTING
522. GHSA-253Q-9Q78-63X4 repo=jmlepisto/clatter fix=b65ae6e9b801 np=1 files=10 code=9 members=0 REJECT_ROUTING
523. GHSA-3446-6MGW-F79P repo=getgrav/grav fix=5a12f9be8314 np=1 files=10 code=8 members=417 REJECT_ROUTING
524. GHSA-58JH-XV4V-PCX4 repo=nyariv/SandboxJS fix=67cb186c41c7 np=1 files=10 code=6 members=1 REJECT_ROUTING
525. GHSA-58Q2-9X27-H2JM repo=solspace/craft-freeform fix=e7402a1d1ce9 np=1 files=10 code=2 members=0 REJECT_ROUTING
526. GHSA-5R6X-G6JV-4V87 repo=ibexa/admin-ui fix=72a64d90d249 np=1 files=10 code=7 members=3 REJECT_ROUTING
527. GHSA-6457-MXPQ-4FQQ repo=i18next/i18nextify fix=16f23dbcdcf8 np=1 files=10 code=6 members=0 REJECT_ROUTING
528. GHSA-66H4-QJ4X-38XP repo=nyariv/SandboxJS fix=67cb186c41c7 np=1 files=10 code=6 members=1 REJECT_ROUTING
529. GHSA-6P54-FW2F-Q7GF repo=l3montree-dev/devguard fix=1be88ec1309a np=1 files=10 code=10 members=59 REJECT_ROUTING
530. GHSA-7C78-RM87-5673 repo=modelscope/ms-swift fix=32f09e9b0a44 np=1 files=10 code=10 members=0 REJECT_ROUTING
531. GHSA-7HGR-XVRR-XPW3 repo=nhost/nhost fix=52c70664a7e9 np=1 files=10 code=6 members=0 REJECT_ROUTING
532. GHSA-7X3H-RM86-3342 repo=nyariv/SandboxJS fix=67cb186c41c7 np=1 files=10 code=6 members=1 REJECT_ROUTING
533. GHSA-9695-8FR9-HW5Q repo=getgrav/grav fix=5a12f9be8314 np=1 files=10 code=8 members=417 REJECT_ROUTING
534. GHSA-C2Q3-P4JR-C55F repo=getgrav/grav fix=5a12f9be8314 np=1 files=10 code=8 members=417 REJECT_ROUTING
535. GHSA-C5VG-26P8-Q8CR repo=MobSF/Mobile-Security-Framework-MobSF fix=6987a946485a np=1 files=10 code=6 members=0 REJECT_ROUTING
536. GHSA-GWFR-JFJF-92VV repo=getgrav/grav fix=5a12f9be8314 np=1 files=10 code=8 members=417 REJECT_ROUTING
537. GHSA-J5G9-F88F-GFJ3 repo=httplib2/httplib2 fix=87581ad6cf75 np=1 files=10 code=5 members=0 REJECT_ROUTING
538. GHSA-JJPW-65FV-8G48 repo=nyariv/SandboxJS fix=67cb186c41c7 np=1 files=10 code=6 members=1 REJECT_ROUTING
539. GHSA-MWFG-948F-2CC5 repo=MobSF/Mobile-Security-Framework-MobSF fix=6987a946485a np=1 files=10 code=6 members=0 REJECT_ROUTING
540. GHSA-R2RJ-WWM5-X6MQ repo=kyverno/kyverno fix=7a651be3a8c7 np=1 files=10 code=7 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor/unlanded member did not qualify. 27 rows had local PR members from containing-merge or self-merge topology; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path. Source_matcher hits on members without a same-mechanism hunk were REJECT_ROUTING. 9 rows had at least one source_matcher-recognized PR member; those without a landed same-mechanism hunk stayed REJECT_ROUTING.

## Conservation

bucket 729 = inspected through rank 540 (60+60+60+60+60+60+60+60+60) + unreviewed 189. Equation 729=540+189. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from reconstructed ranks 1-480 and from on-disk ranks 1-420.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
