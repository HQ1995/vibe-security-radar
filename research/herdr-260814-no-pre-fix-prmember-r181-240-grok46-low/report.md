# No-pre-fix PR-member recall repair ranks 181-240 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Authoritative inventory result SHA256 `cecb1710279e2df3e7635d3ee91e0d85f25e453528ea18aa29299380ff6dbbd9` replay `87ddd177ec134e756666d5f0ff0bb662038a8f91a87a1482e5ce9ed35d5672c7`.
Corroborating ranks 61-120 result SHA256 `81b693b0307fe800212cd7d1c00d0f1a06e59e1d86f6a576a214cf99789d5838`.
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

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect ranks 181-240. Ranks 1-60, 61-120, and the active 121-180 slice are prior or in-flight REJECT_ROUTING and are disjoint. Keyword-only rank was not used.

## Inspected ranks 181-240 (60)

181. GHSA-4VC8-WVHW-M5GV repo=juju/juju fix=22cdcf6b54c2 np=1 files=2 code=2 members=9 REJECT_ROUTING
182. GHSA-527M-2XHR-J27G repo=hiyouga/LlamaFactory fix=95b7188090a1 np=1 files=2 code=2 members=0 REJECT_ROUTING
183. GHSA-52JH-2XXH-PWH6 repo=nats-io/nats-server fix=a1488de6f2ba np=1 files=2 code=2 members=0 REJECT_ROUTING
184. GHSA-534H-C3CW-V3H9 repo=nuxt/nuxt fix=1f9f4767a872 np=1 files=2 code=2 members=0 REJECT_ROUTING
185. GHSA-54FX-42GC-7VW4 repo=honojs/hono fix=f70e2c316843 np=1 files=2 code=2 members=0 REJECT_ROUTING
186. GHSA-5592-P365-24XH repo=ImageMagick/ImageMagick fix=f86452a8aea3 np=1 files=2 code=2 members=0 REJECT_ROUTING
187. GHSA-5JPX-9HW9-2FX4 repo=nextauthjs/next-auth fix=82efcf81f218 np=1 files=2 code=1 members=0 REJECT_ROUTING
188. GHSA-5MQ8-78GM-PJMQ repo=kepano/defuddle fix=f154cb740ee6 np=1 files=2 code=2 members=0 REJECT_ROUTING
189. GHSA-5R97-79VW-QVM4 repo=microsoft/DirectXTK12 fix=c037a024a7ed np=1 files=2 code=1 members=0 REJECT_ROUTING
190. GHSA-5VJ6-WJR7-5V9F repo=n8n-io/n8n fix=4865d1e360a0 np=1 files=2 code=2 members=99 REJECT_ROUTING
191. GHSA-5WGP-VJXM-3X2R repo=navidrome/navidrome fix=b19d5f0d3e07 np=1 files=2 code=2 members=207 REJECT_ROUTING
192. GHSA-674P-XV2X-RF3G repo=litestar-org/litestar fix=03b5813d4f44 np=1 files=2 code=2 members=0 REJECT_ROUTING
193. GHSA-6MMJ-JHQJ-6C6Q repo=grokability/snipe-it fix=ded6515cbc27 np=1 files=2 code=2 members=7 REJECT_ROUTING
194. GHSA-6WQW-2P9W-4VW4 repo=honojs/hono fix=12c511745b3f np=1 files=2 code=2 members=266 REJECT_ROUTING
195. GHSA-6XVF-4VH9-MW47 repo=mindersec/minder fix=f77040092398 np=1 files=2 code=1 members=0 REJECT_ROUTING
196. GHSA-73RR-HH4G-FPGX repo=kpdecker/jsdiff fix=15a158523074 np=1 files=2 code=1 members=0 REJECT_ROUTING
197. GHSA-76C9-3JPH-RJ3Q repo=jshttp/on-headers fix=c6e384908c9c np=1 files=2 code=2 members=0 REJECT_ROUTING
198. GHSA-7F5H-V6XP-FCQ8 repo=Kludex/starlette fix=4ea6e22b489e np=1 files=2 code=2 members=0 REJECT_ROUTING
199. GHSA-7P73-8JQX-23R8 repo=langchain-ai/langgraph fix=bc9d45b47610 np=1 files=2 code=2 members=0 REJECT_ROUTING
200. GHSA-7WC8-WVC4-M498 repo=miguelgrinberg/microdot fix=99b281b45fae np=1 files=2 code=2 members=0 REJECT_ROUTING
201. GHSA-825Q-W924-XHGX repo=n8n-io/n8n fix=ced34c0f93ab np=1 files=2 code=2 members=0 REJECT_ROUTING
202. GHSA-86QP-5C8J-P5MR repo=Kludex/starlette fix=764dab0dcfb9 np=1 files=2 code=2 members=58 REJECT_ROUTING
203. GHSA-86VW-MFPG-WWV9 repo=jsonata-js/jsonata fix=80ba95d170f7 np=1 files=2 code=1 members=0 REJECT_ROUTING
204. GHSA-8FPG-XM3F-6CX3 repo=nextauthjs/next-auth fix=d008b9b764bf np=1 files=2 code=2 members=0 REJECT_ROUTING
205. GHSA-8J4G-W8FX-2239 repo=honojs/hono fix=93fc250d8b4d np=1 files=2 code=2 members=0 REJECT_ROUTING
206. GHSA-8QQ5-RM4J-MR97 repo=isaacs/node-tar fix=340eb285b6d9 np=1 files=2 code=2 members=0 REJECT_ROUTING
207. GHSA-8R6M-32JQ-JX6Q repo=NaturalIntelligence/fast-xml-parser fix=4e546e039876 np=1 files=2 code=2 members=0 REJECT_ROUTING
208. GHSA-92PP-H63X-V22M repo=honojs/node-server fix=025c30f55d58 np=1 files=2 code=2 members=4 REJECT_ROUTING
209. GHSA-92VJ-G62V-JQHH repo=honojs/hono fix=605c70560b52 np=1 files=2 code=2 members=266 REJECT_ROUTING
210. GHSA-93PH-P7V4-HWH4 repo=litestar-org/litestar fix=06b36f481d1b np=1 files=2 code=2 members=0 REJECT_ROUTING
211. GHSA-95Q8-X6R6-672M repo=LemmyNet/lemmy fix=637151121a8e np=1 files=2 code=2 members=7 REJECT_ROUTING
212. GHSA-9FWW-8CPR-Q66R repo=isso-comments/isso fix=0afbfe0691ee np=1 files=2 code=2 members=3 REJECT_ROUTING
213. GHSA-9HP6-4448-45G2 repo=honojs/hono fix=1d79aedc3f82 np=1 files=2 code=2 members=266 REJECT_ROUTING
214. GHSA-9MQV-5HH9-4CGG repo=honojs/node-server fix=3a21938c4183 np=1 files=2 code=2 members=0 REJECT_ROUTING
215. GHSA-9QV6-4PWM-M68F repo=ibexa/fieldtype-richtext fix=4a4a170c7faa np=1 files=2 code=2 members=1 REJECT_ROUTING
216. GHSA-9R4W-JG96-92MV repo=google/go-attestation fix=b6e905e7ae52 np=1 files=2 code=2 members=0 REJECT_ROUTING
217. GHSA-9R54-Q6CX-XMH5 repo=honojs/hono fix=2cf60046d730 np=1 files=2 code=2 members=266 REJECT_ROUTING
218. GHSA-C55G-RP4X-FX84 repo=microsoft/DirectXTK fix=ef1bd5d7f492 np=1 files=2 code=1 members=0 REJECT_ROUTING
219. GHSA-C73C-X77G-854R repo=Gitlawb/openclaude fix=739b8d1f40fd np=1 files=2 code=2 members=0 REJECT_ROUTING
220. GHSA-C7P4-HX26-PR73 repo=jwt/ruby-jwe fix=1e719d79ba3d np=1 files=2 code=2 members=0 REJECT_ROUTING
221. GHSA-C8J7-8CV4-2XMQ repo=lepture/mistune fix=96d0f57f8fe9 np=1 files=2 code=2 members=0 REJECT_ROUTING
222. GHSA-CC8F-XG8V-72M3 repo=node-modules/compressing fix=8d16c196c7f1 np=1 files=2 code=2 members=0 REJECT_ROUTING
223. GHSA-F38F-5XPM-9R7C repo=Kozea/CairoSVG fix=6dde8685ed3f np=1 files=2 code=2 members=0 REJECT_ROUTING
224. GHSA-F47C-3C5W-V7P4 repo=indico/indico fix=70d341826116 np=1 files=2 code=2 members=0 REJECT_ROUTING
225. GHSA-F6PR-83PG-GHH6 repo=geopython/pygeoapi fix=bf25b8695edb np=1 files=2 code=2 members=2 REJECT_ROUTING
226. GHSA-FFQ3-XPV3-J92Q repo=lepture/mistune fix=2b04d7ba341c np=1 files=2 code=2 members=0 REJECT_ROUTING
227. GHSA-FJ3W-JWP8-X2G3 repo=NaturalIntelligence/fast-xml-parser fix=c13a961910f1 np=1 files=2 code=2 members=0 REJECT_ROUTING
228. GHSA-FM6C-F59H-7MMG repo=modelscope/ms-swift fix=b3418ed9b050 np=1 files=2 code=1 members=0 REJECT_ROUTING
229. GHSA-FVFV-PPW4-7H2W repo=n8n-io/n8n fix=8d0251d1deef np=1 files=2 code=2 members=1 REJECT_ROUTING
230. GHSA-G66V-54V9-52PR repo=go-vikunja/vikunja fix=93297742236e np=1 files=2 code=2 members=0 REJECT_ROUTING
231. GHSA-G6V3-7XMC-W563 repo=gopacket/gopacket fix=76119086f593 np=1 files=2 code=2 members=0 REJECT_ROUTING
232. GHSA-G7VP-J25F-H34P repo=lf-edge/eve fix=c0c966dc31e2 np=1 files=2 code=2 members=0 REJECT_ROUTING
233. GHSA-GQ3J-XVXP-8HRF repo=honojs/hono fix=91def7cab654 np=1 files=2 code=2 members=0 REJECT_ROUTING
234. GHSA-H5FQ-653G-GXRM repo=Luzifer/ots fix=3511bd18a2be np=1 files=2 code=2 members=0 REJECT_ROUTING
235. GHSA-H6HF-9846-XWRQ repo=LemmyNet/lemmy fix=9ffe586dafac np=1 files=2 code=2 members=0 REJECT_ROUTING
236. GHSA-HF68-G98V-WP9G repo=grokability/snipe-it fix=aea387771815 np=1 files=2 code=2 members=5 REJECT_ROUTING
237. GHSA-HG3G-GPHW-5HHM repo=gofiber/fiber fix=e115c08b8f05 np=1 files=2 code=2 members=0 REJECT_ROUTING
238. GHSA-HP36-V28F-W3R4 repo=joaonuno/flat-to-nested-js fix=680a5ebe1194 np=1 files=2 code=2 members=0 REJECT_ROUTING
239. GHSA-HQ28-CRG7-95PR repo=grokability/snipe-it fix=ce18ff669ceb np=1 files=2 code=2 members=6 REJECT_ROUTING
240. GHSA-HXW5-9CC5-CMW5 repo=librenms/librenms fix=88fe1a7abdb5 np=1 files=2 code=1 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, sibling path, test/docs/lockfile, old-bug preservation, and non-ancestor/unlanded member did not qualify. 17 rows had local PR members from containing-merge or self-merge topology; none had an atomic source_matcher member whose added lines overlapped closer deleted lines on a fix-touched code path. Source_matcher hits on members without a same-mechanism hunk were REJECT_ROUTING.

## Conservation

bucket 729 = inspected through rank 240 (60+60+60+60) + unreviewed 489. Equation 729=240+489. Holds.
assigned 60 = reviewed REJECT_ROUTING 60 + unreviewed 0. Equation 60=60+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.
Slice disjoint from ranks 1-60, 61-120, and 121-180.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
