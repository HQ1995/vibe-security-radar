# No-same-repo-fix PR/compare/patch leftover 205 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Fix-recovery, not admission.
Exact leftover of the frozen PR/compare/patch pool after ranks 1-340: 325=120+205.
The prior cap-120 packet inspected the first 120. This packet inspects the remaining exact 205 IDs.
No rerank substitution and no padding. Release tags and patched-version-only rows were not selected.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
Recovery ranks 1-40 result SHA256 `6620de70c68eaecde0c82dd90bd2f637b866e2d94cbc04f70ef18b80c646567a` report `a772ed3e00daae1000341e2ada8ed768e1f21f7e8ea8435d278633c18709fea3` replay `72b2e0a0af11ee6a15cd974375acbe5fcfc06b755838104f65549bc37bab455c`.
Ranks 41-100 result SHA256 `0b3b2de92383de78b56466e92e9c9ed29da43daff8cd0b3e941370e615f7b4f4`.
Ranks 101-160 result SHA256 `a32debffc56a5f19ed901f835502bafecfff32b82c9852a6add6bcb104d263ab`.
Ranks 161-220 result SHA256 `9530603d133ebbb6bfb989e3ab7374d34523b202dfd336c5e00aff49b2e49e5a`.
Ranks 221-280 result SHA256 `b98015266cdcd3020179a7e9175688a6020049342fc27b4637890608ee617eef`.
Ranks 281-340 result SHA256 `a21e6a81e0562e8a11696c16d74ef4b690ee6560e5c28cc8914011b5ec928b17`.
PR/compare/patch next 120 result SHA256 `c720d6c5203cde6868de6334b6bd1c4d88596368193a65900ca4e706e31cd28d` report `d40fc8cf827b88bbdcbe6b8c2624aa08ab5c1b129b3352c04d28ac999902f4ed` replay `0eaaa76efb09c4d5f6d99fdb4eefec616064037e02d5af1a8f26c8e4951866b2`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
no_same_repo_fix_ids sha256 `47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5`.
Mixed recoverable ranks 1-340 ids sha256 `cd4142059694dd8071dea31244fac74e16333d991c11095259d1960ca404e04e`.
Prior selected 120 ids sha256 `4fcd65f5e99289d89b06bbe479ef5ee1a2576252566e275d2c511c4c845fd38b`.
Selected leftover 205 ids sha256 `3f83227880f8a98e36b357c3505d34207c8ef2b5884db1faec68d5db45ac4f45`.
Shared caches were read-only. Temporary PR fetches were discarded. Anonymous public git only. No credentials.

## Exclusive bucket reconstruction

Same reconstruction as the recovery packet and the next-120 packet. Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet, the recovery packets, the next-120 packet, this packet, `.leader-quarantine-260814`, herdr-260815 packets, and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Reviewed identities 34389. Not withdrawn, has a GitHub repository from a matching first-party advisory URL or bare homepage or OSV range repo, and no same-repo 40-hex commit URL under strict terminator regex `https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)`.
Minus nextqueue-era list terminals and canonical94 overlap `GHSA-V52W-28XH-V562` yields exclusive no_same_repo_fix 10631.
Frozen later terminals after the nextqueue freeze overlapping the 10631: 51 (pinned from the recovery packet; not recomputed against later 260814/260815 packets). Remaining 10580.
Recoverable remaining with a first-party repository advisory URL plus a same-repository PR, compare/patch, release, or patched-version reference: 2844.
Mixed recoverable ranks 1-340 are already covered by the recovery packets. The next-120 packet covered the first 120 of the remaining PR/compare/patch identities. This packet does not re-inspect those 460 identities.
PR/compare/patch identities in remaining 10580: 408. After excluding ranks 1-340: 325. After excluding the frozen next-120 slice: 205. Exact leftover order preserved. Did not pad. Did not substitute. Did not infer causality from OSV ranges.

## Conservation

named bucket 10631 = ranks 1-340 + next120 120 + this slice 205 + remainder 9966. Equation 10631=340+120+205+9966. Holds.
named bucket 10631 = later_terminals 51 + remaining 10580. Equation 10631=51+10580. Holds.
remaining 10580 = ranks 1-340 + next120 120 + this slice 205 + unreviewed 9915. Equation 10580=340+120+205+9915. Holds.
remaining 10580 = recoverable 2844 + non-recoverable 7736.
PR/compare/patch after ranks 1-340: 325 = prior 120 + this leftover 205. Equation 325=120+205. Holds. Did not pad.
assigned 205 = REJECT_ROUTING 201 + UNKNOWN 4 + ROUTE 0 + unreviewed 0. Equation 205=201+4. Holds.
PASS=0. ROUTE 0. selected 0. rejected 201. unknown 4. unreviewed remainder of named bucket 9966.

## Inspected leftover (205)

001. GHSA-VC2P-R46X-M3VX repo=lettre/lettre closer=182c42a0f745 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
002. GHSA-VF23-F26F-MJJ9 repo=YOURLS/YOURLS closer=a7b6750c74ee src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
003. GHSA-VF7Q-G2PV-JXVX repo=pimcore/pimcore closer=3495992ab505 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
004. GHSA-VJV6-GQ77-3MJW repo=mapfish/mapfish-print closer=89155f2506b9 src=pr_head np=1 files=6 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
005. GHSA-VVP7-R422-RX83 repo=xwiki/xwiki-platform closer=98105f3be90f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
006. GHSA-W24W-WP77-QFFM repo=cometbft/cometbft closer=4206e03b5986 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
007. GHSA-W534-Q4XF-H5V2 repo=mapfish/mapfish-print closer=89155f2506b9 src=pr_head np=1 files=6 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
008. GHSA-W6J8-JC36-X5Q9 repo=pimcore/pimcore closer=1bda24e90675 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
009. GHSA-WJXW-GH3M-7PM5 repo=ethereum/go-ethereum closer=4f1c4231fdc5 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
010. GHSA-WR66-VRWM-5G5X repo=vercel/next.js closer=397988fb4d23 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
011. GHSA-WVHM-4HHF-97X9 repo=PrismJS/prism closer=7bd7de05edf7 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
012. GHSA-XC9P-R5QJ-8XM9 repo=pimcore/pimcore closer=824cbc96ee70 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
013. GHSA-XG58-75QF-9R67 repo=cilium/cilium closer=6861644b3092 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
014. GHSA-XMJJ-3C76-5W84 repo=directus/directus closer=6e1f5f8fffe4 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
015. GHSA-XRC4-737V-9Q75 repo=OpenZeppelin/openzeppelin-contracts closer=08e9bdf5e5d7 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
016. GHSA-XV8X-PR4H-73JV repo=vyperlang/vyper closer=3e036aaf49dc src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
017. GHSA-XWG3-QRCG-W9X6 repo=vaadin/flow closer=621ef1b32273 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
018. GHSA-XWHF-G6J5-J5GC repo=tensorflow/tensorflow closer=1816c43041a6 src=pr_head np=2 files=400 nontest=309 members=80 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
019. GHSA-XX4C-JJ58-R7X6 repo=validatorjs/validator.js closer=b21879cf45c0 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
020. GHSA-25MX-2MXM-6343 repo=keystonejs/keystone closer=381143400a9a src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
021. GHSA-25XC-JWFQ-39JW repo=vaadin/flow closer=36b14db94a39 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
022. GHSA-2R7V-CMCH-5X26 repo=julianhille/MuhammaraJS closer=6ce062318e33 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
023. GHSA-2V88-QQ7X-XQ5F repo=pimcore/pimcore closer=79a5757e4762 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
024. GHSA-3633-G6MG-P6QQ repo=surrealdb/surrealdb closer=4517ffa40973 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
025. GHSA-3P22-GHQ8-V749 repo=electron/electron closer=5f162614c074 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
026. GHSA-5824-CM3X-3C38 repo=vyperlang/vyper closer=b5b670552a52 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
027. GHSA-7F92-RR6W-CQ64 repo=vyperlang/vyper closer=37d62d633d5f src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
028. GHSA-9PRM-JQWX-45X9 repo=parse-community/parse-server closer=8d5dc933bca7 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
029. GHSA-9RFR-PF2X-G4XF repo=geoserver/geoserver closer=efa1fd8d77ba src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
030. GHSA-C25X-CM9X-QQGX repo=denoland/deno closer=58894051fca2 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
031. GHSA-C8FJ-4PM8-MP2C repo=zitadel/zitadel closer=2e9a47ae48d3 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
032. GHSA-C8HM-HR8H-5XJW repo=n8n-io/n8n closer=61d505f655d6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
033. GHSA-JC55-246C-R88F repo=surrealdb/surrealdb closer=6b6bee52c2df src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
034. GHSA-JQWC-C49R-4W2X repo=bytecodealliance/wasmtime closer=fe0d4af23d05 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
035. GHSA-M5Q3-8WGF-X8XF repo=directus/directus closer=6b37cc27db37 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
036. GHSA-MMX5-32M4-WXVX repo=apptainer/apptainer closer=aa67b2489efb src=pr_head np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
037. GHSA-P26G-97M4-6Q7C repo=eclipse/jetty.project closer=7071cef51d6b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
038. GHSA-PRM5-8G2M-24GG repo=parse-community/parse-server closer=75d60808fe8c src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
039. GHSA-PWH8-58VV-VW48 repo=eclipse/jetty.project closer=b0790926eaf1 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
040. GHSA-Q7RV-6HP3-VH96 repo=guzzle/psr7 closer=bc778a3f18eb src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
041. GHSA-QV98-3369-G364 repo=kubevirt/kubevirt closer=257354834ad7 src=pr_head np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
042. GHSA-QW69-RQJ8-6QW8 repo=eclipse/jetty.project closer=f5a51548c988 src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
043. GHSA-RJWW-2X8V-M9V9 repo=vaadin/flow closer=061a1f9dffd9 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
044. GHSA-V5H2-Q2W4-GPCX repo=getsentry/sentry closer=05943ee459f3 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
045. GHSA-VQFX-GJ96-3W95 repo=sequelize/sequelize closer=adb35c4bf033 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
046. GHSA-3GH6-V5V9-6V9J repo=eclipse/jetty.project closer=5d1d2d7da87e src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
047. GHSA-44VR-RWWJ-P88H repo=ericcornelissen/shescape closer=191713e8facf src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
048. GHSA-9WMC-RG4H-28WV repo=kumahq/kuma closer=1cf4b6343f29 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
049. GHSA-M52V-24P8-654F repo=surrealdb/surrealdb closer=73e6652f1209 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
050. GHSA-MVJ3-QRQH-CJVR repo=cometbft/cometbft closer=1c7f60c885f1 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
051. GHSA-Q8WC-J5M9-27W3 repo=quinn-rs/quinn closer=f124af2111a3 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
052. GHSA-QJ6R-FHRC-JJ5R repo=hyperledger/fabric closer=a7fa32b5257d src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
053. GHSA-WR2M-38XH-RPC9 repo=LemmyNet/lemmy closer=a90fa0b68e88 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
054. GHSA-9P8R-4XP4-GW5W repo=vyperlang/vyper closer=898a91dc4dfc src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
055. GHSA-R7M4-F9H5-GR79 repo=jetty/jetty.project closer=ce80bf46d4f9 src=pr_head np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
056. GHSA-J3G3-5QV5-52MJ repo=ruby/net-imap closer=15b6a65e655d src=pr_head np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
057. GHSA-4XC9-8HMQ-J652 repo=ethereum/go-ethereum closer=c5ba367eb623 src=compare_right np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
058. GHSA-7R7X-4C4Q-C4QF repo=nextauthjs/next-auth closer=50b117dfbbd8 src=compare_right np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
059. GHSA-23X4-M842-FMWF repo=OpenAPITools/openapi-generator closer=0c38e6dfcee4 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
060. GHSA-256Q-HX8W-XCQX repo=silverstripe/silverstripe-framework closer=3cafa4cbf838 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
061. GHSA-27C6-MCXV-X3FH repo=fastify/fastify-multipart closer=c887455d1e57 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
062. GHSA-29PR-6JR8-Q5JM repo=getsentry/sentry-python closer=c23f742f5f72 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
063. GHSA-2MXR-89GF-RC4V repo=yahoo/elide closer=273c702d30fd src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
064. GHSA-2V5C-755P-P4GV repo=faye/faye-websocket-ruby closer=8b76cd904ae4 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
065. GHSA-2XX4-JJ5V-6MFF repo=projectdiscovery/nuclei closer=beab2a302af4 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
066. GHSA-3244-8MFF-W398 repo=gotify/server closer=501aa9534777 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
067. GHSA-356J-HG45-X525 repo=activeadmin/activeadmin closer=100c1113ff56 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
068. GHSA-35VC-W93W-75C2 repo=pomerium/pomerium closer=8f786c491e8f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
069. GHSA-36J3-XXF7-4PQG repo=react-native-webview/react-native-webview closer=75b521542a5f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
070. GHSA-3P4G-RCW5-8298 repo=etcd-io/etcd closer=c9b368119e4f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
071. GHSA-3QMC-2R76-4RQP repo=redwoodjs/redwood closer=b4a851eb2b67 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
072. GHSA-3W9W-9833-GCPV repo=microsoft/DirectXTex closer=288d5ba90c47 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
073. GHSA-3X8C-FMPC-5RMQ repo=matrix-org/synapse closer=17255e4168fe src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
074. GHSA-42J4-733X-5VCF repo=vaadin/framework closer=17630366a125 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
075. GHSA-45CJ-F97F-GGWV repo=matrix-org/synapse closer=d613f098a849 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
076. GHSA-47P7-XFCC-4PV9 repo=Webklex/php-imap closer=846d0d7e38a3 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
077. GHSA-48WP-P9QV-4J64 repo=gjtorikian/commonmarker closer=d793fbf45106 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
078. GHSA-4999-659W-MQ36 repo=minio/console closer=none src=none np=0 files=0 nontest=0 members=0 UNKNOWN missing_closer_object
079. GHSA-4G52-PQCJ-PHVH repo=filecoin-project/lotus closer=e4f4fa2c7de8 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
080. GHSA-4MQG-H5JF-J9M7 repo=pytorch/serve closer=119d8d3e116a src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
081. GHSA-4P6F-M4F9-CH88 repo=gagliardetto/binary closer=b4927ddf838a src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
082. GHSA-4QW4-JPP4-8GVP repo=gjtorikian/commonmarker closer=ac916346314a src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
083. GHSA-55J9-849X-26H4 repo=Cog-Creators/Red-DiscordBot closer=9ab536235baf src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
084. GHSA-58QP-5328-V7MH repo=DrPaulBrewer/cumulative-distribution-function closer=10c25b08e3b6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
085. GHSA-5JPF-PJ32-XX53 repo=auth0/node-auth0 closer=13854a6f1f27 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
086. GHSA-5VPC-35F4-R8W6 repo=containers/buildah closer=a07dde1b8d12 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
087. GHSA-626Q-V9J4-MCP4 repo=OpenZeppelin/cairo-contracts closer=6d4cb750478f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
088. GHSA-66Q9-2RVX-QFJ5 repo=kolide/launcher closer=c9d34b4a99ba src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
089. GHSA-67G8-C724-8MP3 repo=silverstripe/silverstripe-graphql closer=48240859fe0c src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
090. GHSA-6J22-WV8G-894F repo=Shopify/hydrogen closer=5f4f231069ef src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
091. GHSA-7257-96VG-QF6X repo=Cog-Creators/Red-DiscordBot closer=14c834307d8f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
092. GHSA-753P-WRJ5-G8FJ repo=PQClean/PQClean closer=a021b0e5a818 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
093. GHSA-773G-X274-8QMF repo=apple/swift-nio-extras closer=359015de2c49 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
094. GHSA-77MV-4RG7-R8QV repo=Finastra/finastra-nodejs-libs closer=none src=none np=0 files=0 nontest=0 members=0 UNKNOWN missing_closer_object
095. GHSA-7FW6-6MFJ-G3Q2 repo=nervosnetwork/ckb closer=0419a49029a1 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
096. GHSA-7H5V-85W9-PQ6C repo=matrix-org/synapse closer=551232b4c014 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
097. GHSA-7RRJ-XR53-82P7 repo=tokio-rs/tokio closer=a29c3d986122 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
098. GHSA-7VWR-G6PM-9HC8 repo=WSH032/fastapi-proxy-lib closer=305a2caa1863 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
099. GHSA-7W2C-W47H-789W repo=doorkeeper-gem/doorkeeper closer=f202079baac4 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
100. GHSA-82HM-VH7G-HRH9 repo=nervosnetwork/molecule closer=5b4b4816e8c0 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
101. GHSA-82V2-MX6X-WQ7Q repo=log4js-node/log4js-node closer=8042252861a1 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
102. GHSA-867Q-77CC-98MV repo=OpenAPITools/openapi-generator closer=6445ea6511a6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
103. GHSA-87X9-7GRX-M28V repo=notaryproject/notation-go closer=3f534dc08f59 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
104. GHSA-8CW9-5HMV-77W6 repo=sanic-org/sanic closer=b57dca323456 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
105. GHSA-8F4F-V9X5-CG6J repo=kubeedge/kubeedge closer=5d60ae9eabd6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
106. GHSA-8FXR-QFR9-P34W repo=pytorch/serve closer=391bdec3348e src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
107. GHSA-8H9C-R582-MGGC repo=geopython/OWSLib closer=b92687702be9 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
108. GHSA-8PF3-6FGR-3G3G repo=Uniswap/web3-react closer=ffce5729f082 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
109. GHSA-8XPJ-9J9G-FC9R repo=yahoo/elide closer=465fb51bec75 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
110. GHSA-92WQ-Q9PQ-GW47 repo=dgraph-io/dgraph closer=4e5ba7fc95e9 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
111. GHSA-98PX-6486-J7QC repo=matrix-org/synapse closer=8a073a2cd000 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
112. GHSA-9GJ3-HWP5-PMWC repo=jquery/jquery-ui closer=6809ce843e5a src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
113. GHSA-9MG6-X45V-HCFM repo=activeadmin/activeadmin closer=d76c6fbdc918 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
114. GHSA-9WH7-397J-722M repo=metal3-io/baremetal-operator closer=a58a905cccd6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
115. GHSA-C332-W4JM-55WV repo=vaadin/framework closer=7cfcdfc95673 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
116. GHSA-C9VV-FHGV-CJC3 repo=dfinity/agent-js closer=21a775c524fa src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
117. GHSA-CVJ7-5F3C-9VG9 repo=ChainSafe/lodestar closer=fd5870fcfed1 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
118. GHSA-F3WC-3VXV-XMVR repo=matrix-org/synapse closer=23ca964eeec3 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
119. GHSA-F9QJ-7GH3-MHJ4 repo=kartverket/github-workflows closer=f0e09d5cae1c src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
120. GHSA-FGW4-V983-MGP8 repo=cli/cli closer=bf3a40aef3af src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
121. GHSA-FHV8-FX5F-7FXF repo=ecomfe/zrender closer=4281e3333b36 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
122. GHSA-FM53-MPMP-7QW2 repo=FriendsOfFlarum/upload closer=2f50e59ccf73 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
123. GHSA-FV82-R8QV-CH4V repo=pomerium/pomerium closer=ca611b43d6f5 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
124. GHSA-G49Q-JW42-6X85 repo=thelounge/thelounge closer=29fcc2da053b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
125. GHSA-G63H-Q855-VP3Q repo=edgexfoundry/edgex-go closer=583e9f9f48d4 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
126. GHSA-G8PH-74M6-8M7R repo=ClickHouse/clickhouse-java closer=9a8f7c99a91c src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
127. GHSA-G9MP-8G3H-3C5C repo=flynn/noise closer=7fa33310641d src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
128. GHSA-GGMR-44CV-24PM repo=awslabs/sockeye closer=a20a34d1ec5b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
129. GHSA-H2FG-54X9-5QHQ repo=nats-io/jwt closer=e74ae88d2a8a src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
130. GHSA-HC82-W9V8-83PR repo=lightningnetwork/lnd closer=c8a3fbe265c6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
131. GHSA-HHC4-47RH-CR34 repo=rust-blockchain/evm closer=4c652b8ab252 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
132. GHSA-HJ57-J5CW-2MWP repo=coreos/ignition closer=b0562e383703 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
133. GHSA-HXWM-X553-X359 repo=npm/git closer=f48dc34b31ff src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
134. GHSA-J23J-Q57M-63V3 repo=vaadin/framework closer=47f9de521fb0 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
135. GHSA-J257-JFVV-H3X5 repo=MirahezeBots/sopel-channelmgnt closer=fd5da591fed6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
136. GHSA-J3FF-XP6C-6GCC repo=ChainSafe/js-libp2p-noise closer=705093676bc9 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
137. GHSA-J562-C3CW-3P5G repo=Finastra/finastra-nodejs-libs closer=none src=none np=0 files=0 nontest=0 members=0 UNKNOWN missing_closer_object
138. GHSA-J7QV-PGF6-HVH4 repo=jquery/jquery-ui closer=463654df9f0b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
139. GHSA-JGH8-VCHW-Q3G7 repo=IncludeSecurity/safeurl-python closer=7b8596171b7b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
140. GHSA-M36X-MGFH-8G78 repo=projectdiscovery/interactsh closer=0a616b3f2038 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
141. GHSA-M5XF-X7Q6-3RM7 repo=kubevela/kubevela closer=fbeacb0a6bb5 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
142. GHSA-MJ46-R4GR-5X83 repo=gatsbyjs/gatsby closer=f214eb0694c6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
143. GHSA-P9P4-97G9-WCRH repo=playframework/playframework closer=200a86af8b4d src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
144. GHSA-PHJ8-4CQ3-794G repo=ratpack/ratpack closer=60302fae7ef2 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
145. GHSA-PP64-WJ43-XQCR repo=aws/aws-sam-cli closer=ca034d1ab01f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
146. GHSA-PVH2-PJ76-4M96 repo=rust-blockchain/evm closer=a90cf79fcac7 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
147. GHSA-PWQF-9H7J-7MV8 repo=theupdateframework/tuf closer=67a3a7ab9214 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
148. GHSA-PX37-JPQX-97Q9 repo=aws/aws-sam-cli closer=6c8b7c41015d src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
149. GHSA-PXCC-HJ8W-FMM7 repo=prisma/prisma closer=fa7bd7770812 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
150. GHSA-Q324-Q795-2Q5P repo=Redocly/openapi-cli closer=c2c74d484430 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
151. GHSA-Q4XM-6FJC-5F6W repo=sigstore/sigstore-java closer=1dd557b54a14 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
152. GHSA-Q9WV-22M9-VHQH repo=tauri-apps/tauri closer=63e8ac908bc6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
153. GHSA-QCGX-CRRX-38V5 repo=vaadin/framework closer=47f9de521fb0 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
154. GHSA-QCQV-38JG-2R43 repo=codevise/pageflow closer=2a512682bb19 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
155. GHSA-QMHJ-M29V-GVMR repo=Pycord-Development/pycord closer=2d1575354c10 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
156. GHSA-R7VQ-6425-J94W repo=theupdateframework/python-tuf closer=83ac7be525b7 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
157. GHSA-RC4Q-9M69-GQP8 repo=fastify/fastify-csrf closer=3b9a7eed6bde src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
158. GHSA-RCJV-MGP8-QVMR repo=open-telemetry/opentelemetry-go-contrib closer=3541453403a1 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
159. GHSA-RP4V-HHM6-RCV9 repo=vmware-tanzu/pinniped closer=c40465127ebe src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
160. GHSA-RWGM-F83R-V3QJ repo=wp-cli/wp-cli closer=d3da414c28d4 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
161. GHSA-V57H-6HMH-G2P4 repo=paritytech/frontier closer=b75db324ef4b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
162. GHSA-V8X6-59G4-5G3W repo=playframework/playframework closer=15393b736df9 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
163. GHSA-V935-PQMR-G8V9 repo=rust-num/num-bigint closer=056e0d42fe98 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
164. GHSA-VC89-HCCF-RQ55 repo=typelevel/jawn closer=0707e2569f43 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
165. GHSA-W6CX-QG2Q-RVQ8 repo=Finastra/ssr-pages closer=none src=none np=0 files=0 nontest=0 members=0 UNKNOWN missing_closer_object
166. GHSA-WHJ9-M24X-QHHP repo=IntellectualSites/FastAsyncWorldEdit closer=84dcb1d7e187 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
167. GHSA-WRRW-CRP8-979Q repo=codevise/pageflow closer=2a512682bb19 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
168. GHSA-X477-FQ37-Q5WR repo=fortio/proxy closer=2548595ae60e src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
169. GHSA-X938-FVFW-7JH5 repo=kubeedge/kubeedge closer=5d60ae9eabd6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
170. GHSA-XC27-F9Q3-4448 repo=plannigan/hyper-bump-it closer=4454586ccace src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
171. GHSA-XCJX-M2PJ-8G79 repo=py-pdf/PyPDF2 closer=3d5548d3c4f6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
172. GHSA-XH6M-7CR7-XX66 repo=hazelcast/hazelcast closer=037293620ce7 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
173. GHSA-XPMX-H7XQ-XFFH repo=ctripcorp/apollo closer=ae9ba6cfd32e src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
174. GHSA-XRR9-RH8P-433V repo=ktorio/ktor closer=007f2d2c870f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
175. GHSA-26C5-PPR8-F33P repo=matrix-org/synapse closer=0602fc9f5265 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
176. GHSA-2C6M-6GQH-6QG3 repo=actions/runner closer=b3771255ac1b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
177. GHSA-36GQ-35J3-P9R9 repo=compose-spec/compose-go closer=1e1af297b27b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
178. GHSA-3R3G-G73X-G593 repo=coreos/coreos-installer closer=a87cd4d2ce1d src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
179. GHSA-47XC-9RR2-Q7P4 repo=Azure/azure-cli closer=110fd2cd2735 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
180. GHSA-4822-JVWX-W47H repo=matrix-org/synapse closer=d508ec17653f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
181. GHSA-5JCR-82FH-339V repo=marmelab/react-admin closer=9b3eed2307c6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
182. GHSA-75XC-QVXH-27F8 repo=vaadin/framework closer=8cae7d9550f3 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
183. GHSA-88CV-MJ24-8W3Q repo=jordansissel/ruby-arr-pm closer=c109bbd147de src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
184. GHSA-89QM-WCMW-3MGG repo=weaveworks/weave-gitops closer=babd91574b99 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
185. GHSA-C74F-6MFW-MM4V repo=open-telemetry/opentelemetry-collector closer=974aa7634ba6 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
186. GHSA-CG3Q-J54F-5P7P repo=prometheus/client_golang closer=ff409ead375a src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
187. GHSA-F28G-86HC-823Q repo=superfly/tokenizer closer=7a34f61f914f src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
188. GHSA-GP2F-254M-RH32 repo=SAP/cloud-sdk-js closer=602d79c70b68 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
189. GHSA-HVWX-QH2H-XCFJ repo=TYPO3/html-sanitizer closer=77be3bf90a4c src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
190. GHSA-Q74R-4XW3-PPX9 repo=vaadin/framework closer=c40bed109c37 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
191. GHSA-W9FG-XFFH-P362 repo=matrix-org/synapse closer=a4aaf29e1344 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
192. GHSA-WJ7Q-GJG8-3CPM repo=thephpleague/oauth2-server closer=605f6f0b7d13 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
193. GHSA-WR3C-G326-486C repo=weaveworks/weave-gitops closer=966823bbda8c src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
194. GHSA-XV6X-456V-24XH repo=gotify/server closer=925fb7e2c9fa src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
195. GHSA-XVHG-W6QC-M3QQ repo=yaklang/yaklang closer=d5ddcba43b8b src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
196. GHSA-9FHW-R42P-5C7R repo=progfay/scrapbox-parser closer=75f1fa6d23ce src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
197. GHSA-CQXR-XF2W-943W repo=OpenAPITools/openapi-generator closer=fc39e29fbaac src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
198. GHSA-VWM6-QC77-V2RH repo=kubeedge/kubeedge closer=327096ebe250 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
199. GHSA-X39J-H85H-3F46 repo=ipfs/go-merkledag closer=875457ed9fa2 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
200. GHSA-2C6G-PFX3-W7H8 repo=resteasy/resteasy closer=807d7456f213 src=pr_head np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
201. GHSA-7MC6-X925-7QVX repo=microsoftgraph/msgraph-beta-sdk-php closer=4057bf69af02 src=compare_right np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
202. GHSA-86C2-4X57-WC8G repo=git-ecosystem/git-credential-manager closer=99e2f7f60e73 src=compare_right np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
203. GHSA-CGWQ-6PRQ-8H9Q repo=microsoftgraph/msgraph-sdk-php closer=df60bc9d4b86 src=compare_right np=0 files=0 nontest=0 members=0 REJECT_ROUTING closer_not_in_local_clone
204. GHSA-MHHP-C3CM-2R86 repo=microsoftgraph/msgraph-sdk-php-core closer=3428ae84dbf7 src=compare_right np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
205. GHSA-X99J-R8VV-GWWJ repo=pimcore/customer-data-framework closer=e3f333391582 src=patch np=0 files=0 nontest=0 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk

ROUTE 0. REJECT_ROUTING 201. UNKNOWN 4. Did not pad. Shared SHA is not identity dedupe. Slice unique and disjoint from ranks 1-340 and from the prior 120 by selection identity.
201 rows have a named closer SHA from anonymous git ls-remote of an exact same-repository PR ref, compare right-hand object, or patch SHA. 200 closer objects were opened for member and pre-closer source_matcher search. No production source_matcher hit was found on a pre-closer same-mechanism hunk. Four private or prompt-blocked repositories yielded no closer SHA. One compare closer SHA was named but not reachable as a commit object.

## Shared SHA identities (preserved separately)

- closer `2a512682bb196a6ec841cff705e9019455c7f1d1`: GHSA-QCQV-38JG-2R43, GHSA-WRRW-CRP8-979Q
- closer `47f9de521fb096202bd647f4303cc77dcebfbbb4`: GHSA-J23J-Q57M-63V3, GHSA-QCGX-CRRX-38V5
- closer `5d60ae9eabd6b6b7afe38758e19bbe8137664701`: GHSA-8F4F-V9X5-CG6J, GHSA-X938-FVFW-7JH5
- closer `89155f2506b9cee822e15ce60ccae390a1419d5e`: GHSA-VJV6-GQ77-3MJW, GHSA-W534-Q4XF-H5V2

Shared closer SHAs do not merge identities and are not a uniqueness failure.

## Routing rule

ROUTE requires a named exact closer object and a recognized atomic source_matcher hit before that closer on a plausible same-mechanism non-test hunk, plus ancestry or proven carrier membership, but-for, fix reversal, a released vulnerable artifact, and uniqueness. Reject AI-on-fix, tests only, missing objects, human members under AI carriers, path-only overlap, shared SHA as dedupe, filename overlap, PR branding, squash trailer transfer, OSV introduced, nearby history, carrier-only trailers, sibling file, old bug, and comment-only overlap. ROUTE only with no fatal gate FAIL. This packet never emits PASS. This slice produced 0 ROUTE rows.

## Blockers

- Inspected leftover exact 205 produced 0 ROUTE rows. No PASS proposal.
- Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
- Recovered PR or compare objects without a pre-closer same-mechanism AI hunk are not seven-gate proof.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
