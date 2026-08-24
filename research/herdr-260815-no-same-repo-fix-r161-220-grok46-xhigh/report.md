# No-same-repo-fix recovery ranks 161-220 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Fix-recovery, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
Recovery ranking packet result SHA256 `6620de70c68eaecde0c82dd90bd2f637b866e2d94cbc04f70ef18b80c646567a` report `a772ed3e00daae1000341e2ada8ed768e1f21f7e8ea8435d278633c18709fea3` replay `72b2e0a0af11ee6a15cd974375acbe5fcfc06b755838104f65549bc37bab455c`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. Temporary tag fetches were discarded. Anonymous public git only. No credentials.

## Exclusive bucket reconstruction

Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet itself, the recovery packet, this packet, `.leader-quarantine-260814`, and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Reviewed identities 34389. Not withdrawn, has a GitHub repository from a matching first-party advisory URL or bare homepage or OSV range repo, and no same-repo 40-hex commit URL under strict terminator regex `https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)`.
Minus nextqueue-era list terminals and canonical94 overlap `GHSA-V52W-28XH-V562` yields exclusive no_same_repo_fix 10631.
no_same_repo_fix_ids sha256 `47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5`.
Canonical94 overlap with the 10631: 0 (V52W already removed while forming the named bucket). Later terminal identities after the nextqueue freeze overlapping the 10631: 51. Remaining 10580.

Selector: remaining 10580 with a first-party repository advisory URL plus a same-repository PR, compare/patch, release, or patched-version reference, ranked by local clone, published on or after 2025-05-01, low PR fanout, signal order PR then compare/patch then release then patched-version, then uppercase GHSA ID. Inspect ranks 161-220 only. Did not pad. Did not infer causality from OSV ranges.
Reconstructed ranks 1-160 are disjoint from this slice by selection identity (overlap 0). Uniqueness of the 60 IDs holds.

## Conservation

named bucket 10631 = inspected through rank 220 plus unreviewed remainder 10411. Equation 10631=220+10411. Holds.
10411 = later_terminals 51 + remaining after rank 220 of 10580, which is 10360. 51+10360=10411.
remaining 10580 = inspected through 220 + unreviewed 10360.
assigned 60 = REJECT_ROUTING 60 + ROUTE 0 + unreviewed_on_prefix 0. Equation 60=60+0. Holds. Did not pad.
PASS=0. ROUTE 0. selected 0. rejected 60. unreviewed remainder of bucket 10411.

## Inspected ranks 161-220 (60)

161. GHSA-763J-3P5V-JFC6 repo=mvt-project/androidqf closer=472203c2395f src=release_tag np=2 files=0 nontest=0 members=3 REJECT_ROUTING merge_update_not_mechanism
162. GHSA-777W-RPR6-C52H repo=n8n-io/n8n closer=7786117e9766 src=release_tag np=1 files=35 nontest=0 members=0 REJECT_ROUTING test_only_closer
163. GHSA-7CF7-9WRR-VRF4 repo=indico/indico closer=12652ce3d8a9 src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
164. GHSA-7F3J-J7JJ-R3VR repo=microsoft/kiota closer=3639d3825c30 src=release_tag np=1 files=3 nontest=0 members=0 REJECT_ROUTING ai_on_fix
165. GHSA-7JP5-298Q-JG98 repo=go-vikunja/vikunja closer=25268530e4a8 src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
166. GHSA-7JQV-FW35-GMX9 repo=jupyter/nbconvert closer=78ed30837a60 src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
167. GHSA-7P4H-3GXQ-X3H3 repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
168. GHSA-7RGV-GQHR-FXG3 repo=mlc-ai/xgrammar closer=62e13551b9b6 src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
169. GHSA-7RX3-28CR-V5WH repo=handlebars-lang/handlebars.js closer=dce542c9a660 src=release_tag np=1 files=5 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
170. GHSA-7WW3-XVF5-CXWM repo=Jo-Jo98/ciguard closer=477c69aca386 src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
171. GHSA-7XJM-G8F4-RP26 repo=Giskard-AI/giskard-oss closer=0a826ad544d5 src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
172. GHSA-82F7-87HM-852X repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
173. GHSA-84HF-8GH5-575J repo=getkirby/kirby closer=2278dae6b418 src=release_tag np=2 files=29 nontest=16 members=9 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
174. GHSA-85X2-R8XV-WW8C repo=getkirby/kirby closer=d952dfc0a890 src=release_tag np=1 files=27 nontest=21 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
175. GHSA-86RH-H242-J8XP repo=getkirby/kirby closer=2b37e83368ea src=release_tag np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
176. GHSA-87X4-J8VH-P5QF repo=makeplane/plane closer=f53446340b90 src=release_tag np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
177. GHSA-89CP-7P28-JFFG repo=getkirby/kirby closer=274dca6df93d src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
178. GHSA-89GH-3PGC-V5H2 repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING test_only_closer
179. GHSA-8CXW-CC62-Q28V repo=Jo-Jo98/ciguard closer=477c69aca386 src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
180. GHSA-8FRJ-8Q3M-XHGM repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=6 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
181. GHSA-8G87-J6Q8-G93X repo=lepture/mistune closer=067f90861088 src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
182. GHSA-8HF9-3Q64-Q2QF repo=hahwul/dalfox closer=1dcb01cbb196 src=release_tag np=1 files=3 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
183. GHSA-8JXR-PR72-R468 repo=modelcontextprotocol/java-sdk closer=3c87155b9ac1 src=release_tag np=1 files=14 nontest=0 members=0 REJECT_ROUTING test_only_closer
184. GHSA-8M7C-HF24-5G47 repo=nocodb/nocodb closer=93adcf0cdc77 src=release_tag np=2 files=6 nontest=6 members=5 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
185. GHSA-8MXQ-7XR7-2FXJ repo=jupyterhub/ltiauthenticator closer=4fb95e2b72ec src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
186. GHSA-8P9H-49RC-QGXJ repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
187. GHSA-8Q6Q-M837-FV64 repo=koel/koel closer=8ee1de0f5589 src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
188. GHSA-8VM4-G489-V3W7 repo=nocodb/nocodb closer=391834484b11 src=release_tag np=2 files=654 nontest=469 members=80 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
189. GHSA-8X8F-54WF-VV92 repo=MervinPraison/PraisonAI closer=961f5046c9e8 src=release_tag np=1 files=27 nontest=7 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
190. GHSA-94V3-77J7-VM48 repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
191. GHSA-95FF-46G6-6GW9 repo=nocodb/nocodb closer=046ea02f9748 src=release_tag np=2 files=3 nontest=0 members=5 REJECT_ROUTING test_only_closer
192. GHSA-96FH-M4R8-6V9V repo=nocodb/nocodb closer=93adcf0cdc77 src=release_tag np=2 files=6 nontest=6 members=5 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
193. GHSA-9837-48HR-Q32J repo=nicolargo/glances closer=988cad684745 src=release_tag np=1 files=6 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
194. GHSA-98VH-X9CX-9CFP repo=lxc/incus closer=6255b3956027 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
195. GHSA-99F4-GRH7-6PCQ repo=grpc/grpc-node closer=2c99fbddc969 src=release_tag np=2 files=1 nontest=0 members=1 REJECT_ROUTING test_only_closer
196. GHSA-99G3-W8GR-X37C repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=6 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
197. GHSA-9CMH-XCQM-5HQR repo=n8n-io/n8n closer=ff05cd3be8c4 src=release_tag np=1 files=20 nontest=0 members=0 REJECT_ROUTING test_only_closer
198. GHSA-9G5Q-2W5X-HMXF repo=go-chi/chi closer=3b171578ca44 src=release_tag np=1 files=7 nontest=3 members=0 REJECT_ROUTING ai_on_fix
199. GHSA-9GJV-JVM7-VV2V repo=gramps-project/gramps-web-api closer=f75f37f39151 src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING test_only_closer
200. GHSA-9H64-2846-7X7F repo=getaxonflow/axonflow closer=f2a23a27a3fd src=release_tag np=1 files=4 nontest=2 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
201. GHSA-9HMG-827W-9RHJ repo=nuts-foundation/nuts-node closer=ba3095f896ff src=release_tag np=1 files=3 nontest=1 members=0 REJECT_ROUTING ai_on_fix
202. GHSA-9HX7-C53C-V6X8 repo=getkirby/kirby closer=b583392a7246 src=release_tag np=2 files=120 nontest=78 members=73 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
203. GHSA-9R8P-H6CC-6QHM repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING test_only_closer
204. GHSA-9W78-79Q7-R4FP repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING test_only_closer
205. GHSA-9WCP-9R3J-383Q repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING test_only_closer
206. GHSA-9WFJ-C55W-J9QR repo=getkirby/kirby closer=d952dfc0a890 src=release_tag np=1 files=27 nontest=21 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
207. GHSA-9WGH-M22W-9XJ8 repo=nocodb/nocodb closer=93adcf0cdc77 src=release_tag np=2 files=6 nontest=6 members=5 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
208. GHSA-C2GF-V879-257J repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=0 members=0 REJECT_ROUTING test_only_closer
209. GHSA-C2RX-5R8W-8XR2 repo=netty/netty closer=a41f7b289ce1 src=release_tag np=1 files=62 nontest=0 members=0 REJECT_ROUTING test_only_closer
210. GHSA-C5FP-P67M-GQ56 repo=KnpLabs/snappy closer=5f84912209d1 src=release_tag np=2 files=1 nontest=1 members=1 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
211. GHSA-C653-97M9-RCG9 repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=0 members=0 REJECT_ROUTING test_only_closer
212. GHSA-C67F-GMXW-MJ93 repo=NeoRazorX/facturascripts closer=a4078cdd3cdb src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING ai_on_fix
213. GHSA-C69G-56F8-XWQJ repo=netty/netty closer=fca0764703b3 src=release_tag np=1 files=47 nontest=0 members=0 REJECT_ROUTING test_only_closer
214. GHSA-C7JM-38GQ-H67H repo=http4k/http4k closer=7adc55e0662f src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING test_only_closer
215. GHSA-CC37-9Q2J-3HFV repo=netty/netty closer=f05f765d8146 src=release_tag np=1 files=47 nontest=0 members=0 REJECT_ROUTING test_only_closer
216. GHSA-CCFX-MFMX-2FX9 repo=lepture/mistune closer=067f90861088 src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
217. GHSA-CFG2-MXFJ-J6PW repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=6 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
218. GHSA-CH3W-9456-38V3 repo=gravitl/netmaker closer=6b7d33fa7749 src=release_tag np=1 files=10 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
219. GHSA-CHQ7-94J8-CJ28 repo=jupyter-server/enterprise_gateway closer=0344929cbca6 src=release_tag np=1 files=7 nontest=0 members=0 REJECT_ROUTING test_only_closer
220. GHSA-CMM3-54F8-PX4J repo=netty/netty closer=a41f7b289ce1 src=release_tag np=1 files=62 nontest=0 members=0 REJECT_ROUTING test_only_closer

Release tags were resolved with anonymous git ls-remote. Recovered closer is the peeled tag commit. Shared SHA is not identity dedupe. Shared groups: GHSA-7P4H-3GXQ-X3H3+GHSA-82F7-87HM-852X+GHSA-8P9H-49RC-QGXJ+GHSA-94V3-77J7-VM48 closer b969123b7fac; GHSA-7WW3-XVF5-CXWM+GHSA-8CXW-CC62-Q28V closer 477c69aca386; GHSA-85X2-R8XV-WW8C+GHSA-9WFJ-C55W-J9QR closer d952dfc0a890; GHSA-89GH-3PGC-V5H2+GHSA-9R8P-H6CC-6QHM+GHSA-9W78-79Q7-R4FP+GHSA-9WCP-9R3J-383Q closer 25d74f918253; GHSA-8FRJ-8Q3M-XHGM+GHSA-99G3-W8GR-X37C+GHSA-CFG2-MXFJ-J6PW closer b4e3a8a84ade; GHSA-8G87-J6Q8-G93X+GHSA-CCFX-MFMX-2FX9 closer 067f90861088; GHSA-8M7C-HF24-5G47+GHSA-96FH-M4R8-6V9V+GHSA-9WGH-M22W-9XJ8 closer 93adcf0cdc77; GHSA-C2GF-V879-257J+GHSA-C653-97M9-RCG9+GHSA-CC37-9Q2J-3HFV closer f05f765d8146; GHSA-C2RX-5R8W-8XR2+GHSA-CMM3-54F8-PX4J closer a41f7b289ce1.

## Routing rule

ROUTE requires a named exact closer object and a recognized atomic source_matcher hit before that closer on a plausible same-mechanism non-test hunk. Reject AI-on-fix, carrier-only trailers, sibling file, old bug, comment-only overlap, test-only closers, PR branding, squash trailer transfer, OSV introduced, and nearby history. Inspected ranks 161-220 produced 0 ROUTE rows. No PASS proposal.
Reject reasons: ai_on_fix 4, merge_update_not_mechanism 1, no_atomic_pr_member_marker_on_mechanism_hunk 30, test_only_closer 25.

## Blockers

- Inspected ranks 161-220 produced 0 ROUTE rows. No PASS proposal.
- Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
- Recovered PR/release objects without a pre-closer same-mechanism AI hunk are not seven-gate proof.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
