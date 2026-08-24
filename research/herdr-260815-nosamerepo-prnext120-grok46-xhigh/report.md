# No-same-repo-fix PR/compare/patch next 120 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Fix-recovery, not admission.
Disjoint high-yield slice of still-unreviewed identities with an exact same-repository
PR, compare, or patch reference after excluding recovery-packet ranks 1-340.
Release tags and patched-version-only rows were not selected.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
Recovery ranks 1-40 result SHA256 `6620de70c68eaecde0c82dd90bd2f637b866e2d94cbc04f70ef18b80c646567a` report `a772ed3e00daae1000341e2ada8ed768e1f21f7e8ea8435d278633c18709fea3` replay `72b2e0a0af11ee6a15cd974375acbe5fcfc06b755838104f65549bc37bab455c`.
Ranks 41-100 result SHA256 `0b3b2de92383de78b56466e92e9c9ed29da43daff8cd0b3e941370e615f7b4f4`.
Ranks 101-160 result SHA256 `a32debffc56a5f19ed901f835502bafecfff32b82c9852a6add6bcb104d263ab`.
Ranks 161-220 result SHA256 `9530603d133ebbb6bfb989e3ab7374d34523b202dfd336c5e00aff49b2e49e5a`.
Ranks 221-280 result SHA256 `b98015266cdcd3020179a7e9175688a6020049342fc27b4637890608ee617eef`.
Ranks 281-340 result SHA256 `a21e6a81e0562e8a11696c16d74ef4b690ee6560e5c28cc8914011b5ec928b17`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
no_same_repo_fix_ids sha256 `47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5`.
Mixed recoverable ranks 1-340 ids sha256 `cd4142059694dd8071dea31244fac74e16333d991c11095259d1960ca404e04e`.
Selected 120 ids sha256 `4fcd65f5e99289d89b06bbe479ef5ee1a2576252566e275d2c511c4c845fd38b`.
Shared caches were read-only. Temporary PR fetches were discarded. Anonymous public git only. No credentials.

## Exclusive bucket reconstruction

Same reconstruction as the recovery packet. Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet, the recovery packets, this packet, `.leader-quarantine-260814`, herdr-260815 packets, and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Reviewed identities 34389. Not withdrawn, has a GitHub repository from a matching first-party advisory URL or bare homepage or OSV range repo, and no same-repo 40-hex commit URL under strict terminator regex `https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)`.
Minus nextqueue-era list terminals and canonical94 overlap `GHSA-V52W-28XH-V562` yields exclusive no_same_repo_fix 10631.
Frozen later terminals after the nextqueue freeze overlapping the 10631: 51 (pinned from the recovery packet; not recomputed against later 260814/260815 packets). Remaining 10580.
Recoverable remaining with a first-party repository advisory URL plus a same-repository PR, compare/patch, release, or patched-version reference: 2844.
Mixed recoverable ranks 1-340 are already covered by the recovery packets (83 PR/compare/patch and 257 release-or-patched-only). This packet does not re-inspect them.
PR/compare/patch identities in remaining 10580: 408. After excluding ranks 1-340: 325. High-yield rank: published date, local clone, low PR fanout, PR then compare/patch, then uppercase GHSA ID. Cap 120. Did not pad. Did not infer causality from OSV ranges. Did not spend the slice on release tags or patched-version-only rows.

## Conservation

named bucket 10631 = ranks 1-340 + this slice 120 + remainder 10171. Equation 10631=340+120+10171. Holds.
named bucket 10631 = later_terminals 51 + remaining 10580. Equation 10631=51+10580. Holds.
remaining 10580 = ranks 1-340 + this slice 120 + unreviewed 10120. Equation 10580=340+120+10120. Holds.
remaining 10580 = recoverable 2844 + non-recoverable 7736.
PR/compare/patch after ranks 1-340: 325 = selected 120 + leftover 205. Equation 325=120+205. Holds. Did not pad.
assigned 120 = REJECT_ROUTING 120 + ROUTE 0 + unreviewed 0. Equation 120=120+0. Holds.
PASS=0. ROUTE 0. selected 0. rejected 120. unreviewed remainder of named bucket 10171.

## Inspected slice (120)

001. GHSA-232P-VWFF-86MP repo=moby/moby closer=307afda2e35d src=pr_head np=1 files=4 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
002. GHSA-24M5-R6HV-CCGP repo=cilium/cilium closer=2b7caae65229 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
003. GHSA-26W3-Q4J8-4XJP repo=1Panel-dev/1Panel closer=882a53fd5092 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
004. GHSA-273R-RM8G-7F3X repo=mercurius-js/mercurius closer=732b2f895312 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
005. GHSA-2CCW-7PX8-VMPF repo=dpgaspar/Flask-AppBuilder closer=2bca590edd1f src=pr_head np=2 files=7 nontest=4 members=3 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
006. GHSA-2CMQ-823J-5QJ8 repo=SixLabors/ImageSharp closer=67f7848d6e97 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
007. GHSA-2P94-8669-XG86 repo=vyperlang/vyper closer=b19d7c29e212 src=pr_head np=2 files=3 nontest=2 members=2 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
008. GHSA-2XPM-CMVW-3JCC repo=pimcore/pimcore closer=626faf1b7944 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
009. GHSA-33HQ-F2MF-JM3C repo=kyverno/kyverno closer=8d93e3b42c85 src=pr_head np=2 files=1 nontest=1 members=2 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
010. GHSA-33PG-M6JH-5237 repo=moby/moby closer=307afda2e35d src=pr_head np=1 files=4 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
011. GHSA-3633-5H82-39PQ repo=theupdateframework/go-tuf closer=78c7829d0ec9 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
012. GHSA-375M-5FVV-XQ23 repo=vyperlang/vyper closer=b1bf2148412e src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
013. GHSA-3824-QMFQ-2QV7 repo=surrealdb/surrealdb closer=5645f573efda src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
014. GHSA-389X-67PX-MJG3 repo=mlc-ai/xgrammar closer=c0a9bb256cd3 src=pr_head np=1 files=3 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
015. GHSA-38H4-FX85-QCX7 repo=Exiv2/exiv2 closer=638ff11ce748 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
016. GHSA-3P32-J457-PG5X repo=laravel/framework closer=02e304bc2aad src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
017. GHSA-446W-RRM4-R47F repo=ericcornelissen/shescape closer=d17852fe6d46 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
018. GHSA-49R2-73M6-PP8F repo=vaadin/flow closer=11b6e6fca7ce src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
019. GHSA-4G63-C64M-25W9 repo=OpenZeppelin/openzeppelin-contracts closer=43698a3d7766 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
020. GHSA-4HC4-PGFX-3MRX repo=cilium/cilium closer=2a5abf7d6d71 src=pr_head np=1 files=5 nontest=5 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
021. GHSA-4HG4-9MF5-WXXQ repo=vyperlang/vyper closer=b88d0c090d4c src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
022. GHSA-4HMQ-GGRM-QFC6 repo=directus/directus closer=4e4da78c4603 src=pr_head np=2 files=43 nontest=29 members=16 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
023. GHSA-4V98-7QMW-RQR8 repo=moby/buildkit closer=23bebc4a180b src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
024. GHSA-4XP2-W642-7MCX repo=cilium/cilium closer=f5557613de9e src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
025. GHSA-56J7-2PM8-RGMX repo=gogs/gogs closer=0c0468dafce4 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
026. GHSA-579X-CJVR-CQJ9 repo=pimcore/pimcore closer=d0a4de39cf05 src=pr_head np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
027. GHSA-5JRJ-52X8-M64H repo=vyperlang/vyper closer=4d9e8bbce422 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
028. GHSA-63G3-9JQ3-MCCV repo=grafana/grafana closer=9c7f31fb2b6d src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
029. GHSA-65X7-C272-7G7R repo=SixLabors/ImageSharp closer=36b3533cc376 src=pr_head np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
030. GHSA-683X-4444-JXH8 repo=CycloneDX/cyclonedx-core-java closer=ab0bc9c530d2 src=pr_head np=1 files=3 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
031. GHSA-6H3M-36W8-HV68 repo=nats-io/nats-server closer=b4128693ed61 src=pr_head np=1 files=23 nontest=6 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
032. GHSA-6P68-W45G-48J7 repo=traefik/traefik closer=e05e73bde1e4 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
033. GHSA-6WR5-JMPR-MJCX repo=surrealdb/surrealdb closer=7188d3158ba7 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
034. GHSA-745P-R637-7VVP repo=codeigniter4/CodeIgniter4 closer=295525347de5 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
035. GHSA-7GC4-R5JR-9HXV repo=flipped-aurora/gin-vue-admin closer=248ea28ced29 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
036. GHSA-7GRF-83VW-6F5X repo=OpenZeppelin/openzeppelin-contracts closer=bba77a87b83b src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
037. GHSA-7M48-WC93-9G85 repo=electron/electron closer=342cf186d98e src=pr_head np=1 files=4 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
038. GHSA-7W85-PP86-P4PQ repo=DSpace/DSpace closer=621a0569eda2 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
039. GHSA-958J-443G-7MM7 repo=gogs/gogs closer=249c4e07c77a src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
040. GHSA-9654-PR4F-GH6M repo=hapifhir/org.hl7.fhir.core closer=d16bca7340eb src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
041. GHSA-9856-9GG9-QCMQ repo=ethereum/go-ethereum closer=4d4879cafd1b src=pr_head np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
042. GHSA-9C22-PWXW-P6HX repo=OpenZeppelin/openzeppelin-contracts closer=95e0f57c0710 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
043. GHSA-9HCR-9HCV-X6PV repo=dpgaspar/Flask-AppBuilder closer=7723ff118104 src=pr_head np=2 files=11 nontest=7 members=4 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
044. GHSA-9J3M-G383-29QR repo=OpenZeppelin/openzeppelin-contracts closer=be8506368d4e src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
045. GHSA-9J5W-2CQC-CWJ9 repo=OpenMage/magento-lts closer=288bd56cb0db src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
046. GHSA-9W2P-RH8C-V9G5 repo=pyinstaller/pyinstaller closer=e8996b6e6ac4 src=pr_head np=1 files=9 nontest=8 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
047. GHSA-C2G2-GX4J-RJ3J repo=getsentry/sentry closer=b34812a5db2d src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
048. GHSA-C43Q-5HPJ-4CRV repo=eclipse-ee4j/jersey closer=c9497de67090 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
049. GHSA-C6PF-2V8J-96MC repo=cilium/cilium closer=6360190e0ae1 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
050. GHSA-C6WG-CM5X-RQVJ repo=opensearch-project/security closer=313d4a947481 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
051. GHSA-C7PR-343R-5C46 repo=vyperlang/vyper closer=3e036aaf49dc src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
052. GHSA-CFH4-7WQ9-6PGG repo=wp-graphql/wp-graphql closer=35090ef63730 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
053. GHSA-CFHH-XGWQ-5R67 repo=plone/volto closer=eb1e3b3a3edb src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
054. GHSA-CM8H-Q92V-XCFC repo=mercurius-js/mercurius closer=b5d430ebab11 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
055. GHSA-CM9X-C3RH-7RC4 repo=cri-o/cri-o closer=41dca27cb53b src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
056. GHSA-CMF4-H3XC-JW8W repo=grafana/grafana closer=9c7f31fb2b6d src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
057. GHSA-CQ58-R77C-5JJW repo=getkirby/kirby closer=7f7337cba8e4 src=pr_head np=1 files=3 nontest=0 members=0 REJECT_ROUTING test_only_closer
058. GHSA-CRMJ-QH74-2R36 repo=Exiv2/exiv2 closer=b04e48c210b7 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
059. GHSA-CX2Q-HFXR-RJ97 repo=vyperlang/vyper closer=0a1dfe132896 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
060. GHSA-F598-MFPV-GMFX repo=sequelize/sequelize closer=e05e13859c71 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
061. GHSA-FMVM-X8MV-47MJ repo=vercel/next.js closer=a75a538a709a src=pr_head np=2 files=4 nontest=0 members=2 REJECT_ROUTING test_only_closer
062. GHSA-FWVG-2739-22V7 repo=cloudflare/workers-sdk closer=0967ebf55005 src=pr_head np=1 files=5 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
063. GHSA-G27J-74FP-XFPR repo=directus/directus closer=7056d77a4ad1 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
064. GHSA-G2J6-57V7-GM8C repo=opencontainers/runc closer=0abab45c9b97 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
065. GHSA-G2MC-FQQC-HXG3 repo=pimcore/pimcore closer=be7a2670d405 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
066. GHSA-G2XH-C426-V8MF repo=vyperlang/vyper closer=a90f50db87d6 src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
067. GHSA-G4H6-QP44-WQVX repo=xwiki/xwiki-platform closer=2631642d0216 src=pr_head np=1 files=7 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
068. GHSA-G8M5-722R-8WHQ repo=jetty/jetty.project closer=b2c261dcdd29 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
069. GHSA-G8Q8-FGGX-9R3Q repo=keycloak/keycloak closer=9fb61a502cbd src=pr_head np=2 files=1 nontest=1 members=2 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
070. GHSA-G9XM-7538-MQ8W repo=Exiv2/exiv2 closer=b04e48c210b7 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
071. GHSA-GGGM-66RH-PP98 repo=directus/directus closer=b911285d3eed src=pr_head np=2 files=6 nontest=3 members=4 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
072. GHSA-GR3C-Q7XF-47VH repo=hapifhir/org.hl7.fhir.core closer=5dc40f8030fa src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
073. GHSA-H2PH-VHM7-G4HP repo=traefik/traefik closer=495987cf988a src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
074. GHSA-H33Q-MHMP-8P67 repo=vyperlang/vyper closer=fbdcf855fb04 src=pr_head np=2 files=2 nontest=2 members=2 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
075. GHSA-H36C-M3RF-34H9 repo=argoproj/argo-workflows closer=14a11367a653 src=pr_head np=1 files=9 nontest=7 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
076. GHSA-H4F5-H82V-5W4R repo=surrealdb/surrealdb closer=556fe2b62865 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
077. GHSA-H924-8G65-J9WG repo=traefik/traefik closer=7a83b85f3585 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
078. GHSA-HGV6-W7R3-W4QW repo=kyverno/kyverno closer=a839c37bcde0 src=pr_head np=2 files=6 nontest=5 members=3 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
079. GHSA-HRHX-6H34-J5HC repo=traefik/traefik closer=a2128f77aa6b src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
080. GHSA-J2CR-JC39-WPX5 repo=cosmos/cosmos-sdk closer=c4fc0aaff7a1 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
081. GHSA-J5C3-R84F-9596 repo=pimcore/pimcore closer=9da44c3731b5 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
082. GHSA-JMX8-355M-8VWH repo=vaadin/flow closer=75669537671e src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
083. GHSA-JQXR-VJVV-899M repo=keystonejs/keystone closer=600bc3b803e7 src=pr_head np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
084. GHSA-M2JR-HMC3-QMPR repo=spree/spree closer=a20a53ca7520 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
085. GHSA-M3CQ-XCX9-3GVM repo=kyverno/kyverno closer=6bd90f08ae33 src=pr_head np=2 files=1 nontest=1 members=2 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
086. GHSA-M3Q4-7QMJ-657M repo=openfga/openfga closer=f3de37d4f72c src=pr_head np=2 files=2 nontest=1 members=2 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
087. GHSA-M3R6-H7WV-7XXV repo=moby/buildkit closer=c82ace129685 src=pr_head np=1 files=7 nontest=7 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
088. GHSA-M54H-5X5F-5M6R repo=authzed/spicedb closer=293794712c74 src=pr_head np=1 files=13 nontest=9 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
089. GHSA-M697-4V8F-55QG repo=traefik/traefik closer=e93061435b5a src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
090. GHSA-MC52-JPM2-CQH6 repo=denoland/deno closer=ddd87c45f3e2 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
091. GHSA-MF4F-J588-5XM8 repo=opencast/opencast closer=59321c193f63 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
092. GHSA-MPJM-V997-C4H4 repo=electron/electron closer=225a64a3bd6d src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
093. GHSA-MQ39-4GV4-MVPX repo=moby/moby closer=19b74dc69124 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
094. GHSA-MQQG-XJHJ-WFGW repo=miniflux/v2 closer=d04d07b35d1e src=pr_head np=1 files=2 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
095. GHSA-MV6W-J4XC-QPFW repo=argoproj/argo-cd closer=4025842024e4 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
096. GHSA-MX2Q-35M2-X2RH repo=OpenZeppelin/openzeppelin-contracts closer=b082da8228df src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
097. GHSA-P7JQ-V8JP-J424 repo=vaadin/flow closer=3fe644cab2cf src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
098. GHSA-PC2Q-JCXQ-RJRR repo=tinacms/tinacms closer=61f8c0e509e7 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
099. GHSA-PP2H-95HM-HV9R repo=pimcore/pimcore closer=bc966df15ae2 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
100. GHSA-PPJQ-QXHX-M25F repo=auth0/passport-wsfed-saml2 closer=81fa4dfc2e64 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
101. GHSA-PXW4-94J3-V9PF repo=surrealdb/surrealdb closer=5645f573efda src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
102. GHSA-Q2F9-X4P4-7XMH repo=apollographql/federation closer=c743f29f8bc1 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
103. GHSA-Q3GG-M8HR-H4X4 repo=surrealdb/surrealdb closer=3c559552a417 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
104. GHSA-Q8Q8-93CV-V6H8 repo=helm/helm closer=c67b644a791a src=pr_head np=1 files=9 nontest=6 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
105. GHSA-QC84-GQF4-9926 repo=crossbeam-rs/crossbeam closer=f7c378b26e27 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
106. GHSA-QCGX-7P5F-HXVR repo=statamic/cms closer=0b5e95183286 src=pr_head np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
107. GHSA-QH8G-58PP-2WXH repo=jetty/jetty.project closer=18e8198489a6 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
108. GHSA-QH9X-GCFH-PCRW repo=OpenZeppelin/openzeppelin-contracts closer=43698a3d7766 src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
109. GHSA-QQ5V-F4C3-395C repo=argoproj/argo-cd closer=0ee4e75f118d src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
110. GHSA-QWHM-H7V3-MRJX repo=pendulum-project/ntpd-rs closer=5439bccf44bf src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
111. GHSA-R2QC-W64X-6J54 repo=vega/vega closer=674aa9d20f55 src=pr_head np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
112. GHSA-R56X-J438-VW5M repo=vyperlang/vyper closer=4d9e8bbce422 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
113. GHSA-R5VF-WF4H-82GG repo=matrix-org/matrix-rust-sdk closer=1b05380b60f9 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
114. GHSA-R5W7-F542-Q2J4 repo=getsentry/sentry-javascript closer=373bbff6bcbd src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
115. GHSA-R5X6-W42P-JHPP repo=cilium/cilium closer=1d29bda208bb src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
116. GHSA-RCG9-HRHX-6Q69 repo=pimcore/pimcore closer=33d1d831954a src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
117. GHSA-RCRX-FPJP-MFRW repo=julianhille/MuhammaraJS closer=4df356bd2811 src=pr_head np=1 files=4 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
118. GHSA-RP4X-WXQV-CF9M repo=vaadin/flow closer=cde1389507aa src=ls_remote np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
119. GHSA-RQ86-9M6R-CM3G repo=surrealdb/surrealdb closer=0596b5d178a7 src=pr_head np=1 files=3 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
120. GHSA-V5M7-53CV-F3HX repo=crossbeam-rs/crossbeam closer=be327d581e84 src=pr_head np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk

ROUTE 0. REJECT_ROUTING 120. Did not pad. Shared SHA is not identity dedupe. Slice unique and disjoint from ranks 1-340 by selection identity. All 120 rows have a named closer from anonymous git ls-remote of an exact same-repository PR ref. 97 PR heads were opened for member and pre-closer source_matcher search. 23 named closers had no reachable commit object in the read-only clone or discarded temp fetch. No production source_matcher hit was found on a pre-closer same-mechanism hunk.

## Shared SHA identities (preserved separately)

- closer `307afda2e35dcad9d9458c921eadf5455e33817d`: GHSA-232P-VWFF-86MP, GHSA-33PG-M6JH-5237
- closer `5645f573efdadab15865882ed7080375c83bb78b`: GHSA-3824-QMFQ-2QV7, GHSA-PXW4-94J3-V9PF
- closer `43698a3d77668affa333eb1870db7db848f92c26`: GHSA-4G63-C64M-25W9, GHSA-QH9X-GCFH-PCRW
- closer `4d9e8bbce422741c52943f5e493b7e5aa9ac8741`: GHSA-5JRJ-52X8-M64H, GHSA-R56X-J438-VW5M
- closer `9c7f31fb2b6dd4c6159d74c82eab2006ce4ce888`: GHSA-63G3-9JQ3-MCCV, GHSA-CMF4-H3XC-JW8W
- closer `b04e48c210b7faa08c9a8a4b2b922b6f76b8306a`: GHSA-CRMJ-QH74-2R36, GHSA-G9XM-7538-MQ8W

Shared closer SHAs do not merge identities and are not a uniqueness failure.

## Routing rule

ROUTE requires a named exact closer object and a recognized atomic source_matcher hit before that closer on a plausible same-mechanism non-test hunk, plus landed topology. Reject AI-on-fix, shared SHA as dedupe, filename overlap, PR branding, squash trailer transfer, OSV introduced, nearby history, carrier-only trailers, sibling file, old bug, comment-only overlap, and test-only closers. This slice produced 0 ROUTE rows. No PASS proposal.

## Blockers

- Inspected PR/compare/patch cap-120 produced 0 ROUTE rows. No PASS proposal.
- Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
- Recovered PR objects without a pre-closer same-mechanism AI hunk are not seven-gate proof.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
