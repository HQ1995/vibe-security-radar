# No-pre-fix PR-member recall repair (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect prefix 60. Keyword-only rank was not used.

## Inspected prefix (60)

01. GHSA-23HG-53Q6-HQFG repo=ImageMagick/ImageMagick fix=077a417a19a5 np=1 files=1 code=1 members=0 REJECT_ROUTING
02. GHSA-26QP-FFJH-2X4V repo=ImageMagick/ImageMagick fix=bcd8519c70ec np=1 files=1 code=1 members=0 REJECT_ROUTING
03. GHSA-273H-M46V-96Q4 repo=ImageMagick/ImageMagick fix=5b91ab69af61 np=1 files=1 code=1 members=0 REJECT_ROUTING
04. GHSA-275G-G844-73JH repo=matrix-org/matrix-rust-sdk fix=d0c01006e480 np=1 files=1 code=1 members=0 REJECT_ROUTING
05. GHSA-29XP-372Q-XQPH repo=isaacs/node-tar fix=5330eb04bc43 np=1 files=1 code=1 members=0 REJECT_ROUTING
06. GHSA-2GQ3-WW97-WFJM repo=ImageMagick/ImageMagick fix=f5049954f12c np=1 files=1 code=1 members=0 REJECT_ROUTING
07. GHSA-2GW9-C2R2-F5QF repo=m1k1o/neko fix=6b561feb9016 np=1 files=1 code=1 members=0 REJECT_ROUTING
08. GHSA-2R4R-5X78-MVQF repo=kubevirt/kubevirt fix=3ce9f41c54d0 np=1 files=1 code=1 members=22 REJECT_ROUTING
09. GHSA-33G4-646G-QWMM repo=grokability/snipe-it fix=d58fda626e8f np=1 files=1 code=1 members=14 REJECT_ROUTING
10. GHSA-389R-RCCM-H3H5 repo=GOVCERT-LU/eml_parser fix=99af03a09a90 np=1 files=1 code=1 members=0 REJECT_ROUTING
11. GHSA-39H3-G67R-7G3C repo=ImageMagick/ImageMagick fix=3e0330721020 np=1 files=1 code=1 members=0 REJECT_ROUTING
12. GHSA-3H6J-9X8M-RG3G repo=j0k3r/graby fix=0295d828822f np=1 files=1 code=1 members=11 REJECT_ROUTING
13. GHSA-3J4X-RWRX-XXJ9 repo=ImageMagick/ImageMagick fix=168ffe18def9 np=1 files=1 code=1 members=0 REJECT_ROUTING
14. GHSA-3Q5F-GMJC-38R8 repo=ImageMagick/ImageMagick fix=e6394098af39 np=1 files=1 code=1 members=0 REJECT_ROUTING
15. GHSA-42P5-62QQ-MMH7 repo=ImageMagick/ImageMagick fix=bbae0215e1b7 np=1 files=1 code=1 members=0 REJECT_ROUTING
16. GHSA-42WG-38GX-85RH repo=go-vikunja/vikunja fix=1b3d8dc59cb5 np=1 files=1 code=1 members=0 REJECT_ROUTING
17. GHSA-4JJ9-CGQC-X9H5 repo=neuvector/neuvector fix=955904b5762f np=1 files=1 code=1 members=0 REJECT_ROUTING
18. GHSA-4QGR-4H56-8895 repo=go-vikunja/vikunja fix=a42b4f37bde5 np=1 files=1 code=1 members=0 REJECT_ROUTING
19. GHSA-4V8W-GG5J-PH37 repo=mantisbt/mantisbt fix=966554a19cf1 np=1 files=1 code=1 members=11 REJECT_ROUTING
20. GHSA-4VPF-W7QV-5H3Q repo=mantisbt/mantisbt fix=de2f71fd8874 np=1 files=1 code=1 members=13 REJECT_ROUTING
21. GHSA-543G-8GRM-9CW6 repo=ImageMagick/ImageMagick fix=49000e7298fb np=1 files=1 code=1 members=0 REJECT_ROUTING
22. GHSA-55WF-5M3Q-6JJF repo=Icinga/ipl-web fix=f387e92504d7 np=1 files=1 code=1 members=21 REJECT_ROUTING
23. GHSA-5PQF-54QP-32WX repo=librenms/librenms fix=64b31da44436 np=1 files=1 code=1 members=0 REJECT_ROUTING
24. GHSA-5XG3-585R-9JH5 repo=ImageMagick/ImageMagick fix=2a06c7be3bba np=1 files=1 code=1 members=0 REJECT_ROUTING
25. GHSA-687H-XW6F-Q2QW repo=Lookyloo/PlaywrightCapture fix=49e289eba756 np=1 files=1 code=1 members=13 REJECT_ROUTING
26. GHSA-68RR-P4FP-J59V repo=gofiber/fiber fix=eb874b6f6c58 np=1 files=1 code=1 members=1 REJECT_ROUTING
27. GHSA-68W5-W573-Q2R8 repo=mantisbt/mantisbt fix=3f952e68fa86 np=1 files=1 code=1 members=2 REJECT_ROUTING
28. GHSA-6H2F-WJHF-4WJX repo=Mayuri-Chan/pyrofork fix=2f2d515575cc np=1 files=1 code=1 members=0 REJECT_ROUTING
29. GHSA-6Q5M-63H6-5X4V repo=harttle/liquidjs fix=35d523026345 np=1 files=1 code=1 members=0 REJECT_ROUTING
30. GHSA-6WHJ-7QMG-86QJ repo=khoj-ai/khoj fix=1b7ccd141d47 np=1 files=1 code=1 members=0 REJECT_ROUTING
31. GHSA-6XMX-XR9P-58P7 repo=librenms/librenms fix=087608cf9f85 np=1 files=1 code=1 members=0 REJECT_ROUTING
32. GHSA-72HF-FJ62-W6J4 repo=ImageMagick/ImageMagick fix=9afe96cc325d np=1 files=1 code=1 members=0 REJECT_ROUTING
33. GHSA-7355-PWX2-PM84 repo=ImageMagick/ImageMagick fix=5a545ab9d6c3 np=1 files=1 code=1 members=0 REJECT_ROUTING
34. GHSA-73VX-49MV-V8W5 repo=mantisbt/mantisbt fix=f32787c14d45 np=1 files=1 code=1 members=0 REJECT_ROUTING
35. GHSA-77FJ-VX54-GVH7 repo=gomarkdown/markdown fix=759bbc3e3207 np=1 files=1 code=1 members=0 REJECT_ROUTING
36. GHSA-77X8-3V3H-HRHV repo=mantisbt/mantisbt fix=0f32ceabadc7 np=1 files=1 code=1 members=13 REJECT_ROUTING
37. GHSA-782X-JH29-9MF7 repo=ImageMagick/ImageMagick fix=4354fc1d554e np=1 files=1 code=1 members=0 REJECT_ROUTING
38. GHSA-7MQJ-8GJ2-CG59 repo=mantisbt/mantisbt fix=5cb4b4692958 np=1 files=1 code=1 members=4 REJECT_ROUTING
39. GHSA-7RVH-XQP3-PR8J repo=ImageMagick/ImageMagick fix=204718c22119 np=1 files=1 code=1 members=0 REJECT_ROUTING
40. GHSA-8423-W5WX-H2R6 repo=mpetroff/pannellum fix=9391ef8da6a6 np=1 files=1 code=1 members=0 REJECT_ROUTING
41. GHSA-889J-63JV-QHR8 repo=jetty/jetty.project fix=c8c2515936ef np=1 files=1 code=1 members=10 REJECT_ROUTING
42. GHSA-898V-775G-777C repo=neuron-core/neuron-ai fix=44bab85d92bf np=1 files=1 code=1 members=7 REJECT_ROUTING
43. GHSA-8CJ5-5RVV-WF4V repo=mafintosh/tar-fs fix=647447b572bc np=1 files=1 code=1 members=0 REJECT_ROUTING
44. GHSA-8CMM-J6C4-RR8V repo=go-vikunja/vikunja fix=833f2aec006a np=1 files=1 code=1 members=0 REJECT_ROUTING
45. GHSA-93FX-G747-695X repo=librenms/librenms fix=882fe6f90ea5 np=1 files=1 code=1 members=0 REJECT_ROUTING
46. GHSA-94JP-7776-QJ6Q repo=hydro-dev/Hydro fix=8450390fcce5 np=1 files=1 code=1 members=0 REJECT_ROUTING
47. GHSA-9CCG-6PJW-X645 repo=ImageMagick/ImageMagick fix=439b362b93c0 np=1 files=1 code=1 members=0 REJECT_ROUTING
48. GHSA-9CWV-PXCR-HFJC repo=lf-edge/ekuiper fix=943c02e10f0f np=1 files=1 code=1 members=0 REJECT_ROUTING
49. GHSA-9P3P-W5JF-8XXG repo=getkirby/kirby fix=3ebc9ad3f5ad np=1 files=1 code=1 members=43 REJECT_ROUTING
50. GHSA-9PP9-CFWX-54RM repo=ImageMagick/ImageMagick fix=cea1693e2ded np=1 files=1 code=1 members=0 REJECT_ROUTING
51. GHSA-9Q7C-QMHM-JV86 repo=lxc/incus fix=2516fb19ad84 np=1 files=1 code=1 members=27 REJECT_ROUTING
52. GHSA-9R5M-9576-7F6X repo=harttle/liquidjs fix=95ddefc056a1 np=1 files=1 code=1 members=0 REJECT_ROUTING
53. GHSA-C2XG-QJQW-2V98 repo=mantisbt/mantisbt fix=e3571c319b17 np=1 files=1 code=1 members=13 REJECT_ROUTING
54. GHSA-CFH4-9F7V-FHRC repo=ImageMagick/ImageMagick fix=fc3ab0812ede np=1 files=1 code=1 members=0 REJECT_ROUTING
55. GHSA-CJ6R-RRR9-FG82 repo=nuxt-modules/mdc fix=3657a5bf2326 np=1 files=1 code=1 members=0 REJECT_ROUTING
56. GHSA-CR67-PVMX-2PP2 repo=ImageMagick/ImageMagick fix=ae679e2fd19e np=1 files=1 code=1 members=0 REJECT_ROUTING
57. GHSA-CR88-6MQM-4G57 repo=gogs/gogs fix=961a79e8f9f2 np=1 files=1 code=1 members=0 REJECT_ROUTING
58. GHSA-CRMX-4P49-46M2 repo=mantisbt/mantisbt fix=71df1f67e05b np=1 files=1 code=1 members=13 REJECT_ROUTING
59. GHSA-F4QM-VJ5J-9XPW repo=ImageMagick/ImageMagick fix=d3c0a3748531 np=1 files=1 code=1 members=0 REJECT_ROUTING
60. GHSA-F4V5-65JJ-PCR2 repo=jetty/jetty.project fix=72206b3ea623 np=1 files=1 code=1 members=10 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, and sibling path did not qualify. Eighteen rows had local PR members from nearby merges; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path.

## Conservation

bucket 729 = inspected 60 + unreviewed 669. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
