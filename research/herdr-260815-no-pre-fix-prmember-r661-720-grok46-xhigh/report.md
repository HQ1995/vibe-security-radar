# No-pre-fix PR-member recall repair ranks 661-720 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
Inventory result SHA256 `cecb1710279e2df3e7635d3ee91e0d85f25e453528ea18aa29299380ff6dbbd9` replay `87ddd177ec134e756666d5f0ff0bb662038a8f91a87a1482e5ce9ed35d5672c7`.
Corroborating ranks 601-660 result SHA256 `a8c7917affd92e1f17867dcb97f2cda8dbef330c332aac0f4204d42aee8bc61c`.
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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 661-720. Keyword-only rank was not used.
Reconstructed ranks 1-660 are disjoint from this slice (overlap 0). Uniqueness of the 60 IDs holds. Remaining after rank 720 is 9.

## Inspected ranks 661-720 (60)

661. GHSA-35C5-67FM-CPCP repo=johnbillion/wp-crontrol fix=b085bd306588 np=2 files=0 code=0 members=9 REJECT_ROUTING
662. GHSA-3V2J-6FW9-F57C repo=mantisbt/mantisbt fix=17072d4c322c np=2 files=0 code=0 members=3 REJECT_ROUTING
663. GHSA-428G-F7CQ-PGP5 repo=marshmallow-code/marshmallow fix=d24a0c9df061 np=2 files=0 code=0 members=4 REJECT_ROUTING
664. GHSA-439W-V2P7-PGGC repo=juju/juju fix=d06919eb03ec np=2 files=0 code=0 members=136 REJECT_ROUTING
665. GHSA-46XP-26XH-HPQH repo=kubevirt/kubevirt fix=00d03e43e3bf np=2 files=0 code=0 members=2 REJECT_ROUTING
666. GHSA-4CWQ-J7JV-QMWG repo=getgrav/grav fix=b7e1958a6e80 np=2 files=0 code=0 members=1 REJECT_ROUTING
667. GHSA-557J-XG8C-Q2MM repo=helm/helm fix=4b8e61093d8f np=2 files=0 code=0 members=1 REJECT_ROUTING
668. GHSA-58PV-8J8X-9VJ2 repo=jaraco/jaraco.context fix=7b26a42b5257 np=2 files=0 code=0 members=9 REJECT_ROUTING
669. GHSA-5CJ2-RQQF-HX9P repo=juju/juju fix=d06919eb03ec np=2 files=0 code=0 members=136 REJECT_ROUTING
670. GHSA-5QJG-9MJH-4R92 repo=karmada-io/dashboard fix=8457b8bb8772 np=2 files=0 code=0 members=2 REJECT_ROUTING
671. GHSA-662M-56V4-3R8F repo=getgrav/grav fix=e37259527d9c np=2 files=0 code=0 members=1 REJECT_ROUTING
672. GHSA-6R7F-3FWQ-HQ74 repo=kubewarden/kubewarden-controller fix=4e41b60ae449 np=2 files=0 code=0 members=1 REJECT_ROUTING
673. GHSA-72QJ-48G4-5XGX repo=jruby/jruby-openssl fix=31a56d690ce9 np=2 files=0 code=0 members=1 REJECT_ROUTING
674. GHSA-7899-W6C4-VQC4 repo=misskey-dev/summaly fix=45153b4f08a7 np=2 files=0 code=0 members=2 REJECT_ROUTING
675. GHSA-7GCF-G7XR-8HXJ repo=jonasbb/serde_with fix=c8a1d820ea25 np=2 files=0 code=0 members=2 REJECT_ROUTING
676. GHSA-7V42-G35V-XRCH repo=junkurihara/httpsig-rs fix=5533f596c650 np=2 files=0 code=0 members=3 REJECT_ROUTING
677. GHSA-8535-HVM8-2HMV repo=getgrav/grav fix=e37259527d9c np=2 files=0 code=0 members=1 REJECT_ROUTING
678. GHSA-858Q-77WX-HHX6 repo=getgrav/grav fix=e37259527d9c np=2 files=0 code=0 members=1 REJECT_ROUTING
679. GHSA-89X7-5M5M-MCMM repo=juju/juju fix=d06919eb03ec np=2 files=0 code=0 members=136 REJECT_ROUTING
680. GHSA-96C2-H667-9FXP repo=marshmallow-packages/nova-tiptap fix=fed42d2f8ebb np=2 files=0 code=0 members=3 REJECT_ROUTING
681. GHSA-983W-RHVV-GWMV repo=Kozea/WeasyPrint fix=b6a14f0f3f4c np=2 files=0 code=0 members=2 REJECT_ROUTING
682. GHSA-9C3J-XM6V-J7J3 repo=mantisbt/mantisbt fix=9e3bee2e7b90 np=2 files=0 code=0 members=2 REJECT_ROUTING
683. GHSA-9H84-QMV7-982P repo=helm/helm fix=b78692c18f0f np=2 files=0 code=0 members=1 REJECT_ROUTING
684. GHSA-C3XH-98XP-6QHF repo=gouef/githubtoplanguages fix=157840482e59 np=2 files=0 code=0 members=1 REJECT_ROUTING
685. GHSA-CJCP-QXVG-4RJM repo=getgrav/grav fix=3462d94d5750 np=2 files=0 code=0 members=1 REJECT_ROUTING
686. GHSA-F9F8-9PMF-XV68 repo=helm/helm fix=ec5f59e2db56 np=2 files=0 code=0 members=2 REJECT_ROUTING
687. GHSA-GJC5-8CFH-653X repo=getgrav/grav fix=e37259527d9c np=2 files=0 code=0 members=1 REJECT_ROUTING
688. GHSA-GQ3G-666W-7H85 repo=getgrav/grav fix=9d11094e4133 np=2 files=0 code=0 members=1 REJECT_ROUTING
689. GHSA-H756-WH59-HHJV repo=getgrav/grav fix=3462d94d5750 np=2 files=0 code=0 members=1 REJECT_ROUTING
690. GHSA-J3V9-553H-X28J repo=mantisbt/mantisbt fix=9e8409cdd979 np=2 files=0 code=0 members=6 REJECT_ROUTING
691. GHSA-J422-QMXP-HV94 repo=getgrav/grav fix=ed640a13143c np=2 files=0 code=0 members=1 REJECT_ROUTING
692. GHSA-JHMR-57CJ-Q6G9 repo=komari-monitor/komari fix=cc3d54bff4c6 np=2 files=0 code=0 members=1 REJECT_ROUTING
693. GHSA-M8VH-V6R6-W7P6 repo=getgrav/grav fix=ed640a13143c np=2 files=0 code=0 members=1 REJECT_ROUTING
694. GHSA-MMXM-8W33-WC4H repo=jetty/jetty.project fix=f9ee3904788b np=2 files=0 code=0 members=3 REJECT_ROUTING
695. GHSA-P4WW-MCP9-J6F2 repo=getgrav/grav fix=ed640a13143c np=2 files=0 code=0 members=1 REJECT_ROUTING
696. GHSA-PC3F-X583-G7J2 repo=moby/spdystream fix=ef6121f62c73 np=2 files=0 code=0 members=7 REJECT_ROUTING
697. GHSA-PMWQ-PJRM-6P5R repo=in-toto/in-toto-golang fix=36d782ffb2ca np=2 files=0 code=0 members=1 REJECT_ROUTING
698. GHSA-PV22-FQCJ-7XWH repo=inspektor-gadget/inspektor-gadget fix=c51d419964f5 np=2 files=0 code=0 members=1 REJECT_ROUTING
699. GHSA-PV9C-9MFH-HVXQ repo=icalendar/icalendar fix=b8d23b490363 np=2 files=0 code=0 members=1 REJECT_ROUTING
700. GHSA-PW5X-2MF9-3XC8 repo=mantisbt/mantisbt fix=029d9d203d9e np=2 files=0 code=0 members=3 REJECT_ROUTING
701. GHSA-Q6HV-WCJR-WP8H repo=kcp-dev/kcp fix=02134a2a51d3 np=2 files=0 code=0 members=1 REJECT_ROUTING
702. GHSA-Q747-C74M-69PR repo=mantisbt/mantisbt fix=21e9fbedde85 np=2 files=0 code=0 members=15 REJECT_ROUTING
703. GHSA-Q7CG-457F-VX79 repo=hapijs/joi fix=2392713d3e9d np=2 files=0 code=0 members=1 REJECT_ROUTING
704. GHSA-Q7PG-9PR4-MRP2 repo=junkurihara/httpsig-rs fix=fc095b6ce604 np=2 files=0 code=0 members=1 REJECT_ROUTING
705. GHSA-RRVG-CXH4-QHRV repo=jupyterhub/oauthenticator fix=f0c7002dc36e np=2 files=0 code=0 members=1 REJECT_ROUTING
706. GHSA-VXVC-CG7J-RWQJ repo=gittuf/gittuf fix=dd76efa505f9 np=2 files=0 code=0 members=3 REJECT_ROUTING
707. GHSA-WJ2J-QWCF-CFCC repo=lxc/incus-os fix=e3b35f230d23 np=2 files=0 code=0 members=9 REJECT_ROUTING
708. GHSA-WX3R-V6H7-FRJP repo=jjjake/internetarchive fix=cba2d459e10a np=2 files=0 code=0 members=9 REJECT_ROUTING
709. GHSA-X4RX-4GW3-53P4 repo=moby/moby fix=bea959c7b793 np=2 files=0 code=0 members=2 REJECT_ROUTING
710. GHSA-X62Q-P736-3997 repo=getgrav/grav fix=9d11094e4133 np=2 files=0 code=0 members=1 REJECT_ROUTING
711. GHSA-X93P-W2CH-FG67 repo=ibexa/user fix=9d485bf385e6 np=2 files=0 code=0 members=1 REJECT_ROUTING
712. GHSA-46Q4-43PH-C6FR repo=http4s/blaze fix=ef3e666c146c np=1 files=1 code=0 members=0 REJECT_ROUTING
713. GHSA-65RG-554R-9J5X repo=lycheeverse/lychee-action fix=7cd0af4c74a6 np=1 files=1 code=0 members=0 REJECT_ROUTING
714. GHSA-897W-FCG9-F6XJ repo=jelmer/dulwich fix=49eb56e51aad np=1 files=1 code=0 members=0 REJECT_ROUTING
715. GHSA-8F95-V3JQ-CJ86 repo=jetperch/pymonocypher fix=90ff5b13b13b np=1 files=1 code=0 members=2 REJECT_ROUTING
716. GHSA-HMX5-QPQ5-P643 repo=nolimits4web/swiper fix=d3e663322a13 np=1 files=1 code=0 members=4 REJECT_ROUTING
717. GHSA-MHVJ-JHPQ-885V repo=http4s/blaze fix=3f7c022e3066 np=1 files=1 code=0 members=0 REJECT_ROUTING
718. GHSA-VHGQ-R8GX-5FPV repo=ibexa/admin-ui-assets fix=219b71b70aae np=1 files=1 code=0 members=2 REJECT_ROUTING
719. GHSA-24CH-W38V-XMH8 repo=juju/juju fix=6356e984b82a np=1 files=2 code=0 members=10 REJECT_ROUTING
720. GHSA-9GVJ-PP9X-GCFR repo=mmaitre314/picklescan fix=2a8383cfeb41 np=1 files=2 code=0 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor/unlanded member did not qualify.
Fifty-one rows are merge closers whose ranking combined-diff is empty; first-parent reversal and PR members were still inspected. Nine rows are non-code ranking fanout (docs, lockfiles, or extensions outside the frozen code set). Fifty-five rows had local PR members from the merge second-parent range or a containing merge; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a mechanism-relevant path. File history on those paths produced no recognized source_matcher ancestor bound to closer reversal.

## Conservation

bucket 729 = inspected through rank 720 plus unreviewed remainder 9. Equation 729=720+9. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from reconstructed ranks 1-660. Remaining count 9.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
