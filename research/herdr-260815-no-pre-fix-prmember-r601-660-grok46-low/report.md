# No-pre-fix PR-member recall repair (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
Inventory result SHA256 `cecb1710279e2df3e7635d3ee91e0d85f25e453528ea18aa29299380ff6dbbd9` replay `87ddd177ec134e756666d5f0ff0bb662038a8f91a87a1482e5ce9ed35d5672c7`.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only.

## Exclusive bucket reconstruction

Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet itself and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Exclusive walk on 34389 reviewed identities: withdrawn, no GitHub repository, no exact same-repo 40-hex commit, published before 2025-05-01, terminal verdict, no first-party repo-advisory URL, then local clone and fix object.
Structural remainder 803 = no_local_clone 5 + fix_object_missing 38 + object-present 760.
Object-present 760 minus nextqueue ai_hit 31 (queued 20 + leftover 11) = exclusive no_pre_fix_ai_marker 729.
no_pre_fix_ids sha256 `ffeceb62c6fa243e5865020390ba5de297d01ce3fc0ac1c9754f46d2739c63b1`.
Canonical94 overlap with the 729: 0. Later terminal identities after the nextqueue freeze overlapping the 729: 0. Remaining 729.

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 601-660. Keyword-only rank was not used.
Reconstructed ranks 1-600 are disjoint from this slice (overlap 0). Uniqueness of the 60 IDs holds.

## Inspected ranks 601-660 (60)

601. GHSA-WM8W-6QJM-CV43 repo=nuxt/nuxt fix=ac9b41a36b62 np=1 files=14 code=12 members=0 REJECT_ROUTING
602. GHSA-X696-VM39-CP64 repo=mmaitre314/picklescan fix=aecd11be9870 np=1 files=14 code=2 members=0 REJECT_ROUTING
603. GHSA-XP4F-HRF8-RXW7 repo=mmaitre314/picklescan fix=1931c2d04eac np=1 files=14 code=2 members=0 REJECT_ROUTING
604. GHSA-9Q5R-WFVF-RR7F repo=mlc-ai/xgrammar fix=ced69c3ad2f8 np=1 files=15 code=15 members=0 REJECT_ROUTING
605. GHSA-F7JH-M6WP-JM7F repo=hal/console fix=216de3b8aa82 np=1 files=15 code=11 members=1 REJECT_ROUTING
606. GHSA-GCMJ-C9GG-9VH6 repo=laurent22/joplin fix=791668455e1a np=1 files=15 code=12 members=0 REJECT_ROUTING
607. GHSA-C3H8-G69V-PJRG repo=i18next/i18next-http-middleware fix=65301c194593 np=1 files=16 code=8 members=0 REJECT_ROUTING
608. GHSA-Q82R-2J7M-9RV4 repo=go-acme/lego fix=238454b5f74f np=1 files=16 code=16 members=0 REJECT_ROUTING
609. GHSA-FW9Q-39R9-C252 repo=langchain-ai/langsmith-sdk fix=31d3c3aec028 np=1 files=17 code=16 members=0 REJECT_ROUTING
610. GHSA-HV4R-MVR4-25VW repo=minio/minio fix=76913a9fd5c6 np=1 files=17 code=17 members=0 REJECT_ROUTING
611. GHSA-5CMR-4PX5-23PC repo=mlc-ai/xgrammar fix=b943feacb5a1 np=1 files=18 code=17 members=0 REJECT_ROUTING
612. GHSA-8HF7-H89P-3PQJ repo=MobSF/Mobile-Security-Framework-MobSF fix=2b08dd050e76 np=1 files=18 code=3 members=2 REJECT_ROUTING
613. GHSA-4R9R-CH6F-VXMX repo=mmaitre314/picklescan fix=7f994d62084f np=1 files=19 code=3 members=0 REJECT_ROUTING
614. GHSA-86CJ-95QR-2P4F repo=mmaitre314/picklescan fix=7f994d62084f np=1 files=19 code=3 members=0 REJECT_ROUTING
615. GHSA-8FF6-PC43-JWV3 repo=neuvector/neuvector fix=addc9308b3a6 np=1 files=19 code=19 members=0 REJECT_ROUTING
616. GHSA-F4X7-RFWP-V3XW repo=mmaitre314/picklescan fix=7f994d62084f np=1 files=19 code=3 members=0 REJECT_ROUTING
617. GHSA-F745-W6JP-HPXX repo=mmaitre314/picklescan fix=7f994d62084f np=1 files=19 code=3 members=0 REJECT_ROUTING
618. GHSA-H3QP-7FH3-F8H4 repo=mmaitre314/picklescan fix=7f994d62084f np=1 files=19 code=3 members=0 REJECT_ROUTING
619. GHSA-VR7H-P6MM-WPMH repo=mmaitre314/picklescan fix=7f994d62084f np=1 files=19 code=3 members=0 REJECT_ROUTING
620. GHSA-29V9-FRVH-C426 repo=monetr/monetr fix=c260caa3c573 np=1 files=20 code=17 members=0 REJECT_ROUTING
621. GHSA-2FMP-9RVW-HC96 repo=Jovancoding/Network-AI fix=a59c13a1f0ce np=1 files=20 code=3 members=0 REJECT_ROUTING
622. GHSA-2QVQ-RJWJ-GVW9 repo=handlebars-lang/handlebars.js fix=68d8df5a88e0 np=1 files=20 code=20 members=0 REJECT_ROUTING
623. GHSA-2W6W-674Q-4C4Q repo=handlebars-lang/handlebars.js fix=68d8df5a88e0 np=1 files=20 code=20 members=0 REJECT_ROUTING
624. GHSA-3MFM-83XF-C92R repo=handlebars-lang/handlebars.js fix=68d8df5a88e0 np=1 files=20 code=20 members=0 REJECT_ROUTING
625. GHSA-442J-39WM-28R2 repo=handlebars-lang/handlebars.js fix=68d8df5a88e0 np=1 files=20 code=20 members=0 REJECT_ROUTING
626. GHSA-48X2-6PR9-2JJF repo=Jovancoding/Network-AI fix=a59c13a1f0ce np=1 files=20 code=3 members=0 REJECT_ROUTING
627. GHSA-6X2M-P4XP-WG22 repo=Jovancoding/Network-AI fix=a59c13a1f0ce np=1 files=20 code=3 members=0 REJECT_ROUTING
628. GHSA-9CX6-37PM-9JFF repo=handlebars-lang/handlebars.js fix=68d8df5a88e0 np=1 files=20 code=20 members=0 REJECT_ROUTING
629. GHSA-JVCM-F35G-W78P repo=Jovancoding/Network-AI fix=a59c13a1f0ce np=1 files=20 code=3 members=0 REJECT_ROUTING
630. GHSA-MXJX-28VX-XJJJ repo=Jovancoding/Network-AI fix=a59c13a1f0ce np=1 files=20 code=3 members=0 REJECT_ROUTING
631. GHSA-XHPV-HC6G-R9C6 repo=handlebars-lang/handlebars.js fix=68d8df5a88e0 np=1 files=20 code=20 members=0 REJECT_ROUTING
632. GHSA-XJPJ-3MR7-GCPF repo=handlebars-lang/handlebars.js fix=68d8df5a88e0 np=1 files=20 code=20 members=0 REJECT_ROUTING
633. GHSA-VX58-FWWQ-5G8J repo=nocobase/nocobase fix=75da3dddc4ab np=1 files=23 code=6 members=2 REJECT_ROUTING
634. GHSA-P6X6-9MX6-26WJ repo=gogs/gogs fix=a617d52374e9 np=1 files=27 code=12 members=0 REJECT_ROUTING
635. GHSA-WW7G-4GWX-M7WJ repo=nyariv/SandboxJS fix=f369f8db2664 np=1 files=27 code=24 members=0 REJECT_ROUTING
636. GHSA-H773-7GF7-9M2X repo=neuvector/neuvector fix=084a437033b4 np=1 files=28 code=27 members=0 REJECT_ROUTING
637. GHSA-QQJ3-G7MX-5P4W repo=neuvector/neuvector fix=06424701e69b np=1 files=28 code=27 members=0 REJECT_ROUTING
638. GHSA-J3W7-9QC3-G96P repo=kottster/kottster fix=0a7d24922a23 np=1 files=33 code=24 members=0 REJECT_ROUTING
639. GHSA-535G-62R7-CX6V repo=nautobot/nautobot-app-ssot fix=1530d25cdeb9 np=1 files=45 code=19 members=10 REJECT_ROUTING
640. GHSA-3HW7-QJ9H-R835 repo=gardener/gardener fix=bbd19b1dd3a3 np=1 files=55 code=51 members=0 REJECT_ROUTING
641. GHSA-272M-GCWP-MPWG repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
642. GHSA-4QHR-G3C6-FCFX repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
643. GHSA-6JQX-86GH-F27W repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
644. GHSA-93WV-JW9V-4972 repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
645. GHSA-HPCC-26XQ-25FV repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
646. GHSA-JPPX-W49H-X2QQ repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
647. GHSA-MFG7-5GFP-C4W3 repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
648. GHSA-MVH2-CRG5-V77C repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
649. GHSA-P9JM-Q85P-7MCP repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
650. GHSA-V74W-7MR3-4QG3 repo=netty/netty fix=5b68c61f37aa np=1 files=58 code=55 members=6 REJECT_ROUTING
651. GHSA-H749-FXX7-PWPG repo=minio/minio fix=7c14cdb60e53 np=1 files=59 code=45 members=0 REJECT_ROUTING
652. GHSA-69RH-HCCR-CXRJ repo=Lomkit/laravel-rest-api fix=88b14587b4ef np=1 files=60 code=60 members=0 REJECT_ROUTING
653. GHSA-JG2J-2W24-54CG repo=kimai/kimai fix=6a86afb5fd79 np=1 files=60 code=41 members=1 REJECT_ROUTING
654. GHSA-3J22-8QJ3-26MX repo=lxsmnsyc/seroval fix=ce9408ebc873 np=1 files=67 code=18 members=26 REJECT_ROUTING
655. GHSA-3RXJ-6CGF-8CFW repo=lxsmnsyc/seroval fix=ce9408ebc873 np=1 files=67 code=18 members=26 REJECT_ROUTING
656. GHSA-66FC-RW6M-C2Q6 repo=lxsmnsyc/seroval fix=ce9408ebc873 np=1 files=67 code=18 members=26 REJECT_ROUTING
657. GHSA-HJ76-42VX-JWP4 repo=lxsmnsyc/seroval fix=ce9408ebc873 np=1 files=67 code=18 members=26 REJECT_ROUTING
658. GHSA-HX9M-JF43-8FFR repo=lxsmnsyc/seroval fix=ce9408ebc873 np=1 files=67 code=18 members=26 REJECT_ROUTING
659. GHSA-R4V7-6WCG-GHJ5 repo=gtsteffaniak/filebrowser fix=fa5abc8c67f3 np=1 files=119 code=75 members=28 REJECT_ROUTING
660. GHSA-XH32-CX6C-CP4V repo=gogs/gogs fix=110117b2e5e5 np=1 files=482 code=6 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, and sibling path did not qualify. Nearby-merge PR members were counted when the closer sat on a later merge first-parent path; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path that is not a test, doc, or lockfile.

## Conservation

bucket 729 = inspected through rank 660 plus unreviewed remainder 69. Equation 729=660+69. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
