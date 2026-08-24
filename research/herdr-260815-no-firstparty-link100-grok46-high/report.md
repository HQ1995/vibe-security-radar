# GHSA-200 no-first-party link100

Routing only. This packet does not call a PASS. Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported. Worker PASS is proposal only; this packet emits none.

## Verdict

Inspected prefix 100 of the reconstructed 691 `no_first_party_repo_advisory` bucket: ROUTE 0, PASS 0, REJECT_ROUTING 96, UNKNOWN 4.
ROUTE IDs: none.
Identity closed from repository-owned evidence: 1 (GHSA-9965-VMPH-33XX). That row still fails the atomic pre-fix AI hunk gate.

## Freeze

Authority: canonical94 HOLD at `autoresearch/orchestrator-260814-ghsa200-canonical94`. CONTRACT SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3` from `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`.
canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`. summary SHA256 `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b`.
Source nextqueue-v2 `autoresearch/herdr-260814-nextqueue-v2-grok46-low`: result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1`, report SHA256 `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380`, replay SHA256 `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
First-party github-reviewed tree HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` from read-only cache `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. Reviewed JSON identities: 34389.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. No credentials. No commit or push.

## Bucket reconstruction

Exact nextqueue `parse_advisory` exclusive walk over github-reviewed identities. A row is `no_first_party_repo_advisory` when it is not withdrawn, has a GitHub repository, has at least one strict same-repo 40-hex commit URL, is published on or after 2025-05-01, is absent from nextqueue-era terminal verdicts, and has no matching first-party `github.com/<owner>/<repo>/security/advisories/GHSA-*` URL.
Reconstructed count 691. ID list SHA256 `3f55da6c8a951aed503327b7cd1ed4e05950c5a1e6909ce93157ee186947748c`.
This walk's earlier exclusive counts are not nextqueue's published split (nextqueue used additional structural tests before the 691). Frozen source universe from nextqueue remains `34389 = 910 + 4053 + 10631 + 9533 + 7692 + 691 + 76 + 803`. This walk accounts `34389 = 910 + 4068 + 14050 + 9708 + 4159 + 691 + 803`. The 691 set is the exclusive remainder after those gates and is the bucket this packet reconstructs.

Era inventory at nextqueue result mtime: files=584 cases.jsonl=267 adjudication=34 result.json=283 rows=12504 distinct terminal identities=7932. Verdicts PASS,NARROW,REJECT,UNKNOWN,BLOCKED,KEEP,FAIL,FALSE_POSITIVE,CONFIRM,ACCEPT,HOLD only. Skipped work/notes/pages/snapshot/clones/cache/tmp/node_modules, nextqueue itself, `.leader-quarantine-260814`, and this packet.

## Conservation

691 = 0 canonical94 + 11 later terminals + 680 remaining. Holds.
Later-terminal overlap (explicit identities after the era list that also sit in the 691): GHSA-5XRP-6693-JJX9, GHSA-7G3R-8C6V-HFMR, GHSA-7JCP-V9W4-WJMG, GHSA-83C4-FFJP-MXP9, GHSA-F696-867G-2759, GHSA-FXP5-37MH-VFF5, GHSA-HHF6-3XPG-PGGX, GHSA-MJ73-J457-8X9Q, GHSA-MPMF-3W4R-QFPF, GHSA-X6FH-7QMF-69XH, GHSA-XH69-987W-HRP8.
Remaining 680 ID list SHA256 `d5378e79c92e117b4a7d00bde6afd30af4f7f9a7b408a3662cf9cdd853582a12`.
Of 680 remaining, 329 have same-repo issue, PR, release-tag, or changelog URL evidence. Rank local clone first, then issue over PR over release over changelog, then more identity kinds, then low issue/PR fanout, then case_id. Prefix 100. Did not pad.
Selected-ID SHA256 `5bea24094264b1a3c23ecd3f1713644201ef5d6440c41ae390bba7128843ed17`.
680 = 100 inspected + 580 unreviewed remainder. Holds.
329 = 100 inspected + 229 identity-bearing leftover. Holds.
100 = 96 REJECT_ROUTING + 0 ROUTE + 4 UNKNOWN. Equation 100=100+0 assigned=reviewed+unreviewed. Holds.
PASS=0. ROUTE=0. Canonical94 strict count remains 94.

## Identity rule

The GitHub-reviewed JSON is routing evidence only. GitHub issue/PR/release HTML that contains a GHSA string because `github/advisory-database` linked the page is not repository-owned identity. Identity closes only when a clone blob, tag, or commit message in the named repository contains the GHSA id.
Whole-tree `git grep` at the named fix found that string in one row: GHSA-9965-VMPH-33XX `validatorjs/validator.js` `test/validators.test.js` at `cbef5088f02d36caf978f378bb845fe49bdc0809`. Parent `6f436be36945e460ee624bf72a935a06daded859`. Minimum fix is that atomic commit (n_parents=1) touching `src/lib/isURL.js` plus tests. Tag `13.15.20` contains the fix. No pre-fix source_matcher hit on the mechanism hunk, so REJECT_ROUTING.

## UNKNOWN (4)

Local clone present; named 40-hex fix is not a commit object. No fetch into the shared cache.
01. GHSA-X5GF-QVW8-R2RM Unitech/pm2 `8b9354800a1d157cb9503a3ec414ef1e4700dc1c`
02. GHSA-2HFH-94W5-WXVF saltbo/zpan `8662db8d4b06057631faf3deba4132e66705e947`
08. GHSA-Q23M-VM9R-5745 stefanprodan/podinfo `cbebb20fd48588d36fc7ff3e874c128eb89692f4`
13. GHSA-GW2X-MFWR-H46P xuxueli/xxl-job `d24e4ccd6073cc75305e1d3b9c29bc8db7437e7a`

## Other gates

Pre-fix source_matcher hits on overlapping files: 1 row (GHSA-R87G-78MX-3WG4 wonderwhy-er/DesktopCommanderMCP). The closer `4ce845f8749b6a159b57b38dcc3357f7222a8078` is itself Claude-attributed, so the marker is AI-on-fix, and identity is not closed.
Merge closers (n_parents=2): 10 rows. Empty combined diffs are not a minimum fix.
Release tags that contain the named fix object: GHSA-399J-VXMF-HJVR v20.0.0, GHSA-9965-VMPH-33XX 13.15.20, GHSA-2QFP-Q593-8484 v1.2.0, GHSA-378V-28HJ-76WF v5.2.3, GHSA-25QH-J22F-PWP8 v_1.5.19, GHSA-JMP9-X22R-554X v6.2.11, GHSA-JQPM-WF57-QX5C v1.38.0-rc.0, GHSA-Q97M-8853-PQ76 3.69, GHSA-8V5Q-RHF3-JPHM 6.5.4. Containment without identity and an atomic pre-fix AI hunk is not a ROUTE.

## Inspected prefix (100)

Order is the deterministic rank. Verdict is REJECT_ROUTING unless marked UNKNOWN.

001. GHSA-X5GF-QVW8-R2RM repo=Unitech/pm2 UNKNOWN fix_object_missing no-ident np=None files=None parent=- fix=-
002. GHSA-2HFH-94W5-WXVF repo=saltbo/zpan UNKNOWN fix_object_missing no-ident np=None files=None parent=- fix=-
003. GHSA-399J-VXMF-HJVR repo=react-native-community/cli REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=02622969fb8e fix=15089907d1f1
004. GHSA-6497-PRX7-GPMQ repo=geopandas/geopandas REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=c301579e0ac4 fix=6aa8ef14ffde
005. GHSA-9965-VMPH-33XX repo=validatorjs/validator.js REJECT_ROUTING no_atomic_pre_fix_marker_on_mechanism_hunk ident np=1 files=4 parent=6f436be36945 fix=cbef5088f02d
006. GHSA-HQ3P-W4XV-X7VP repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=be84d28ce4c6 fix=56bbfa3d8abc
007. GHSA-J3V9-6GC7-VF5F repo=meteor/meteor REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=b155192b3916 fix=f7ea6817b909
008. GHSA-Q23M-VM9R-5745 repo=stefanprodan/podinfo UNKNOWN fix_object_missing no-ident np=None files=None parent=- fix=-
009. GHSA-R87G-78MX-3WG4 repo=wonderwhy-er/DesktopCommanderMCP REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=eb687ccccf5b fix=4ce845f8749b
010. GHSA-2QFP-Q593-8484 repo=google/brotli REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=b01b63a46731 fix=67d78bc41db1
011. GHSA-378V-28HJ-76WF repo=indutny/bn.js REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=6db7c3818569 fix=33df26b5771e
012. GHSA-25QH-J22F-PWP8 repo=qos-ch/logback REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=a07cfd53e4a3 fix=61f6a2544f36
013. GHSA-GW2X-MFWR-H46P repo=xuxueli/xxl-job UNKNOWN fix_object_missing no-ident np=None files=None parent=- fix=-
014. GHSA-H4H6-VCCR-44H2 repo=uptrace/bun REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=b25423b6e08e fix=8067a8f13f8d
015. GHSA-JMP9-X22R-554X repo=spring-projects/spring-framework REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=5 parent=ed28390d24bc fix=6d710d482a67
016. GHSA-JQPM-WF57-QX5C repo=weaviate/weaviate REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=54a8d2765ec5 fix=40f2cc32279f
017. GHSA-M297-3JV9-M927 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=7 parent=a4a092d591ad fix=4fd5367e6cc2
018. GHSA-MJJP-XJFG-97WG repo=lief-project/LIEF REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=cda768476781 fix=81bd5d7ea0c3
019. GHSA-Q723-847Q-5G8G repo=spring-projects/spring-framework REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=8a93a889620c fix=a42a6e0c6ac6
020. GHSA-Q97M-8853-PQ76 repo=seaweedfs/seaweedfs REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=8211b29689b2 fix=9ac102336200
021. GHSA-VPQ2-C234-7XJ6 repo=TooTallNate/once REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=a8c9dc3b7a24 fix=b9f43cc5259b
022. GHSA-WV3H-X6C4-R867 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=fb3a5a54c99e fix=2d0aa31c4830
023. GHSA-37GF-GMXV-74WV repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=4 parent=7d6108d4b901 fix=176dc8902ce5
024. GHSA-45H5-66JX-R2WF repo=mjmlio/mjml REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=9 parent=e3cc1230086b fix=517b376b068e
025. GHSA-4HFH-6X8G-GWPP repo=spring-projects/spring-framework REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=a42a6e0c6ac6 fix=b8ddd2c690fe
026. GHSA-585Q-CM62-757J repo=mullvad/mnl-rs REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=7f1369e7fa96 fix=61929d11c13b
027. GHSA-5V8V-XVJV-57X7 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=57b75538b21e fix=1439bd58a9f2
028. GHSA-6G26-7CX5-MRRG repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=11 parent=df72459a344e fix=bf0df40a91a0
029. GHSA-6XV4-9CQP-92RH repo=messageformat/messageformat REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=15e6da2588b7 fix=82cd10b40e3f
030. GHSA-7GCM-G887-7QV7 repo=protocolbuffers/protobuf REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=f3403239ba03 fix=5ebddcb1bcbe
031. GHSA-8JF4-FCJR-68C2 repo=Upsonic/Upsonic REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=98 parent=f5dd5df1c69f fix=a54529acc6e4
032. GHSA-8V5Q-RHF3-JPHM repo=spring-projects/spring-security REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=ad86ae0a79ad fix=d0f93fa6d833
033. GHSA-933F-RG6J-F46P repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=479620769073 fix=33f6f873fda2
034. GHSA-9Q78-27F3-2JMH repo=jaredforth/webp REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=d5238934376b fix=62b47060d7fb
035. GHSA-C739-F6XW-6PV2 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=7 parent=50f9ec2c780f fix=0cea089bd19f
036. GHSA-F6R7-6W34-X2GP repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=37dabf59d0b5 fix=2c4fe42235ba
037. GHSA-FXMW-JCGR-W44V repo=pgadmin-org/pgadmin4 REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=ed52a44b176a fix=1d397395f753
038. GHSA-G78X-7VWX-9F58 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=bdf1f4464b6e fix=1d7ab8d5fb14
039. GHSA-G8VR-X4QH-25QG repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=8 parent=f86c74940191 fix=47b9aef70948
040. GHSA-H5J3-CRG5-8JQM repo=orxfun/orx-pinned-vec REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=3f2cfa74e686 fix=4a4007a1aaff
041. GHSA-HCVW-475W-8G7P repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=6 parent=8316e8538f00 fix=82cd7941d1dd
042. GHSA-J39J-6GW9-JW6H repo=rust-lang/git2-rs REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=03ec58122907 fix=9e160f15bd05
043. GHSA-P9WX-2529-FP83 repo=markedjs/marked REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=8aecb42372ec fix=20bfc106013e
044. GHSA-PQ65-77RC-7R8C repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=13 parent=0d1738060c2d fix=39cb8de54c85
045. GHSA-PRFW-69R3-WQXF repo=modelscope/ms-swift REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=5efb4afdfa72 fix=27426a643175
046. GHSA-QM9P-F9J5-W83W repo=parcel-bundler/parcel REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=40ebdcd87a4b fix=4bc56e3242a8
047. GHSA-RHGQ-F8X5-J2JC repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=6 parent=49c1831c9a8f fix=b137016cc6dc
048. GHSA-RPFV-46XJ-5984 repo=Upsonic/Upsonic REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=98 parent=f5dd5df1c69f fix=a54529acc6e4
049. GHSA-RR5Q-3XWR-F323 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=17 parent=e2109d585f7c fix=f1e5b7776c42
050. GHSA-RX8G-88G5-QH64 repo=Raynos/min-document REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=bf7b69130a36 fix=fe32e8da464c
051. GHSA-WCVJ-VPVW-9RR5 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=5 parent=b745dfa51aa1 fix=18832bcae5be
052. GHSA-X4P7-7CHP-64HQ repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=7 parent=a4a092d591ad fix=4fd5367e6cc2
053. GHSA-X8C6-GJ59-6RX8 repo=libp2p/py-libp2p REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=7d324b129b84 fix=e150d3153af3
054. GHSA-XH32-C9WX-PHRP repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=66f4a7e630a3 fix=215bc1e27230
055. GHSA-22RM-WP4X-V5CX repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=6 parent=ad34724a5d1b fix=00dd0dd716c4
056. GHSA-33J3-G875-37RP repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=33 parent=0f60d6116374 fix=13622ee0ffed
057. GHSA-655H-HG88-5QMF repo=rust-x-bindings/rust-xcb REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=521241dba9cc fix=da830976870c
058. GHSA-FQJH-8322-VGRV repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=a77c60f2f3e0 fix=05e98366773e
059. GHSA-W87R-VG9Q-CRQM repo=google/zx REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=cc2a4f7b5b42 fix=9ef6d3c9962c
060. GHSA-4Q93-V92X-P89F repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=13 parent=7750e3ff823d fix=0e706e7c83d1
061. GHSA-CPF7-J4CF-VQX4 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=a589b95590a0 fix=2b8692499e90
062. GHSA-Q6H7-XXP7-7429 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=4db2780ca218 fix=11c2695064cd
063. GHSA-V5G5-WWMP-JPPW repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=ef06df91d344 fix=165df48d3f0f
064. GHSA-2FJW-WHXM-9V4Q repo=mullvad/nftnl-rs REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=d702312a9ff2 fix=94a286f87e88
065. GHSA-3P7X-94Q9-JQ9X repo=pgadmin-org/pgadmin4 REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=3b184dbeeef9 fix=62e2d18b0261
066. GHSA-4P9M-8GC4-RW2H repo=osrg/gobgp REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=c3eb0db6df91 fix=583080a7258e
067. GHSA-4WP7-92PW-Q264 repo=spring-projects/spring-framework REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=f93132b11ef6 fix=edfcc6ffb188
068. GHSA-4X4M-3C2P-QPPC repo=kubernetes/kubernetes REJECT_ROUTING github_reviewed_only_not_identity no-ident np=2 files=0 parent=34fa4fa3fc24 fix=a2d98cac56a0
069. GHSA-565H-44M8-4C2V repo=xuxueli/xxl-job REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=42 parent=e02f2c65c098 fix=cb1bd548a6d9
070. GHSA-64W3-5Q9M-68XF repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=6 parent=89c960cd4e91 fix=a34094100716
071. GHSA-6859-2QXQ-FFV2 repo=pgadmin-org/pgadmin4 REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=0de635cc4c7d fix=cdeb18fcbb13
072. GHSA-6R3C-XF4W-JXJM repo=spring-projects/spring-framework REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=e86dc9ad9520 fix=f0e7b42704e6
073. GHSA-7C3F-CG9X-F3GR repo=Jaspersoft/jasperreports REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=9c9386cbbe42 fix=3541a3e2b1ad
074. GHSA-7GMJ-H9XC-MCXC repo=nodemailer/mailparser REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=bb325f156d35 fix=921a67df4cfb
075. GHSA-7XCV-9J6C-2FMC repo=modular/modular REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=5bc48caa56fc fix=10620059fb5c
076. GHSA-7XF9-4JFC-WGM4 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=513697218e22 fix=79ab3110a257
077. GHSA-84FX-PWF3-7777 repo=r-huijts/xcode-mcp-server REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=11 parent=f3419f00117a fix=11f8d6bacadd
078. GHSA-8G9R-9WJW-37J4 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=1deb03922e84 fix=68f5779230d0
079. GHSA-9CG4-9HV5-3376 repo=huashengdun/webssh REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=1cf19c71861a fix=a7a704f11139
080. GHSA-CJM2-J6CM-6P6M repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=049ad529e4d3 fix=35a71b00bc85
081. GHSA-CVF4-F829-762V repo=pgadmin-org/pgadmin4 REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=4 parent=e374edc69239 fix=09d2b7eeb0e3
082. GHSA-F29H-PXVX-F335 repo=prettier/eslint-config-prettier REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=4c9489339d37 fix=9b0b0a47ec28
083. GHSA-F2HX-5FX3-HMCV repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=aaae635b5e24 fix=995832f8b74b
084. GHSA-F2M2-4Q6R-CWC4 repo=suyuan32/simple-admin-core REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=4 parent=1d69aa23ac66 fix=f1e2c4f3c55c
085. GHSA-FJF4-6F34-W64Q repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=bb492174094b fix=743ac24081b2
086. GHSA-FMJH-F678-CV3X repo=nyaruka/phonenumbers REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=ccd8c4bbabf8 fix=0479e35488e8
087. GHSA-G4R8-3QMH-PMCH repo=pgadmin-org/pgadmin4 REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=4 parent=e374edc69239 fix=09d2b7eeb0e3
088. GHSA-GJ8W-FFQ9-6828 repo=jeecgboot/JeecgBoot REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=4042579167ed fix=ddf0f61ae59d
089. GHSA-GX6C-PV62-9MCF repo=snowflakedb/snowflake-jdbc REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=8 parent=89018894e124 fix=5fb0a8a318a2
090. GHSA-H4WV-G838-66G3 repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=6 parent=4ba4a1707347 fix=b455ee4f28ab
091. GHSA-HFCF-79GH-F3JC repo=usememos/memos REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=c2528c57f038 fix=46d5307d7f21
092. GHSA-HJ93-H7PG-FH6V repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=8 parent=35a71b00bc85 fix=9046f201125a
093. GHSA-HP6R-R9VC-Q8WX repo=tomasvotava/fastapi-sso REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=da63c19bca7d fix=6117d1a5ad49
094. GHSA-HX9Q-6W63-J58V repo=ijl/orjson REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=3 parent=d860078a973f fix=62bb185b7078
095. GHSA-M63Q-4HR8-5R5H repo=opensolon/solon REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=1 parent=4fdbc8f37e3e fix=49a3bf95fdcf
096. GHSA-Q35R-VVHV-VX5H repo=keycloak/keycloak REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=14 parent=15106e12228a fix=f1baf25cbb15
097. GHSA-QQPG-MVQG-649V repo=qos-ch/logback REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=10 parent=b07355e26aaf fix=1f97ae1844b1
098. GHSA-RM79-X4G6-HVG5 repo=pgadmin-org/pgadmin4 REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=4 parent=1d397395f753 fix=e374edc69239
099. GHSA-RPC5-PM7Q-HJMP repo=naver/billboard.js REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=7 parent=059a785f82bd fix=49e079cdd466
100. GHSA-RPQR-J937-6QR9 repo=volcengine/OpenViking REJECT_ROUTING github_reviewed_only_not_identity no-ident np=1 files=2 parent=04dff4642ee8 fix=46b3e76e28b9

## Stop

No ledger, site, or other-directory edits. No retained clone or advisory fetch. No credentials. No commit or push. Canonical94 stays 94 HOLD. This packet does not call a PASS.
