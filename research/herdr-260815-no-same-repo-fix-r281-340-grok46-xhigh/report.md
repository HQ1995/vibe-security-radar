# No-same-repo-fix ranks 281-340 (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Fix-recovery, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
Recovery ranks 1-40 result SHA256 `6620de70c68eaecde0c82dd90bd2f637b866e2d94cbc04f70ef18b80c646567a` report `a772ed3e00daae1000341e2ada8ed768e1f21f7e8ea8435d278633c18709fea3` replay `72b2e0a0af11ee6a15cd974375acbe5fcfc06b755838104f65549bc37bab455c`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
no_same_repo_fix_ids sha256 `47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5`.
Shared caches were read-only. Temporary PR/tag fetches were discarded. Anonymous public git only. No credentials.

## Exclusive bucket reconstruction

Same reconstruction as the recovery packet. Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet, the recovery packet, this packet, `.leader-quarantine-260814`, and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Reviewed identities 34389. Not withdrawn, has a GitHub repository from a matching first-party advisory URL or bare homepage or OSV range repo, and no same-repo 40-hex commit URL under strict terminator regex `https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)`.
Minus nextqueue-era list terminals and canonical94 overlap `GHSA-V52W-28XH-V562` yields exclusive no_same_repo_fix 10631.
Frozen later terminals after the nextqueue freeze overlapping the 10631: 51 (pinned from the recovery packet; not recomputed against later 260814/260815 packets). Remaining 10580.
Recoverable remaining with a first-party repository advisory URL plus a same-repository PR, compare/patch, release, or patched-version reference: 2844.

Selector: remaining 10580 recoverable subset ranked by local clone, published on or after 2025-05-01, low PR fanout, signal order PR then compare/patch then release then patched-version, then uppercase GHSA ID. Inspect ranks 281-340. Ranks 1-280 are disjoint by selection identity. Did not pad. Did not infer causality from OSV ranges.

## Conservation

named bucket 10631 = prefix through rank 340 + remainder 10291. Equation 10631=340+10291. Holds.
named bucket 10631 = later_terminals 51 + remaining 10580. Equation 10631=51+10580. Holds.
remaining 10580 = recoverable 2844 + non-recoverable 7736.
recoverable 2844 = prefix 340 + unreviewed recoverable 2504.
assigned 60 = REJECT_ROUTING 60 + ROUTE 0 + unreviewed 0. Equation 60=60+0. Holds. Did not pad.
PASS=0. ROUTE 0. selected 0. rejected 60. unreviewed remainder of named bucket 10291.

## Inspected ranks 281-340 (60)

281. GHSA-JJ7C-X25R-R8R3 repo=noir-lang/noir closer=74d6be658e1a src=release_tag np=1 files=18 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
282. GHSA-JJPJ-P2WH-QF23 repo=n8n-io/n8n closer=49d7e1602875 src=release_tag np=1 files=19 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
283. GHSA-JMQM-F8Q4-V7WX repo=librenms/librenms closer=403fa2ddf262 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING release_tag_not_mechanism
284. GHSA-JP7M-XCGX-57QM repo=n8n-io/n8n closer=2320517c9a1e src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
285. GHSA-JQWR-VX3P-R266 repo=n8n-io/n8n closer=ff05cd3be8c4 src=release_tag np=1 files=20 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
286. GHSA-JR54-JWHJ-55GP repo=nocodb/nocodb closer=4e6037f9fa1e src=release_tag np=2 files=0 nontest=0 members=6 REJECT_ROUTING merge_update_not_mechanism
287. GHSA-JRM4-4PCF-4763 repo=Jo-Jo98/ciguard closer=477c69aca386 src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
288. GHSA-JRPC-7VXP-69P6 repo=http4k/http4k closer=f90e7b85045c src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
289. GHSA-JV9X-W4GM-HWCM repo=kimai/kimai closer=d456cd3ce2ec src=release_tag np=1 files=3 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
290. GHSA-JXC4-54G3-J7VP repo=indico/indico closer=f52d44bedcec src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING release_tag_not_mechanism
291. GHSA-M3XC-H892-GGX6 repo=go-git/go-billy closer=237e529bb8de src=release_tag np=2 files=0 nontest=0 members=2 REJECT_ROUTING merge_update_not_mechanism
292. GHSA-M4W9-HJFW-VWJ4 repo=http4k/http4k closer=f90e7b85045c src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
293. GHSA-M932-CRVM-GCP5 repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
294. GHSA-MF78-3RPF-R784 repo=julien040/anyquery closer=66d5e684cd0a src=release_tag np=2 files=0 nontest=0 members=1 REJECT_ROUTING merge_update_not_mechanism
295. GHSA-MG4F-X9V4-6H2P repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
296. GHSA-MJ87-HWQH-73PJ repo=Kludex/python-multipart closer=28f47859b4a4 src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING release_tag_not_mechanism
297. GHSA-MMGG-M5J7-F83H repo=n8n-io/n8n closer=49d7e1602875 src=release_tag np=1 files=19 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
298. GHSA-MPP2-X7WV-38HV repo=nocodb/nocodb closer=391834484b11 src=release_tag np=2 files=0 nontest=0 members=40 REJECT_ROUTING merge_update_not_mechanism
299. GHSA-MQ3M-F8X3-579W repo=n8n-io/n8n closer=a4d0dfce2940 src=release_tag np=1 files=28 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
300. GHSA-P3RG-HRF9-W9GJ repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
301. GHSA-P462-PRXW-MJX4 repo=NASA-AMMOS/AIT-Core closer=dc6215bb2c61 src=release_tag np=1 files=3 nontest=1 members=0 REJECT_ROUTING release_tag_not_mechanism
302. GHSA-P4MJ-98MV-XQ26 repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
303. GHSA-P8WX-5F39-W3X4 repo=nocodb/nocodb closer=93adcf0cdc77 src=release_tag np=2 files=0 nontest=0 members=5 REJECT_ROUTING merge_update_not_mechanism
304. GHSA-P9X3-W98F-7J3Q repo=nocodb/nocodb closer=391834484b11 src=release_tag np=2 files=0 nontest=0 members=40 REJECT_ROUTING merge_update_not_mechanism
305. GHSA-PF2Q-PXHF-HGMW repo=n8n-io/n8n closer=aa3d214338d6 src=release_tag np=1 files=35 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
306. GHSA-PGQF-926R-548M repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
307. GHSA-PH6F-2CVQ-79HQ repo=MagicMirrorOrg/MagicMirror closer=fb41d24ef522 src=release_tag np=1 files=61 nontest=33 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
308. GHSA-PJ2R-F9MW-VRCQ repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=5 members=0 REJECT_ROUTING filename_overlap
309. GHSA-PM35-FQVH-CQ5G repo=n8n-io/n8n closer=25d74f918253 src=release_tag np=1 files=22 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
310. GHSA-PR33-38XX-6R26 repo=http4k/http4k closer=7adc55e0662f src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
311. GHSA-PV5W-4P9Q-P3V2 repo=kysely-org/kysely closer=d13d90b724bf src=release_tag np=1 files=4 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
312. GHSA-PV9Q-275H-RH7X repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=5 members=0 REJECT_ROUTING filename_overlap
313. GHSA-Q3J5-8VRG-4P9Q repo=n8n-io/n8n closer=a4d0dfce2940 src=release_tag np=1 files=28 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
314. GHSA-Q423-49RW-G9MH repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
315. GHSA-Q437-G7FV-2JVV repo=Netflix/lemur closer=4afd730de39f src=release_tag np=2 files=0 nontest=0 members=2 REJECT_ROUTING merge_update_not_mechanism
316. GHSA-Q4F6-JM68-57WW repo=netty/netty closer=fca0764703b3 src=release_tag np=1 files=47 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
317. GHSA-Q5R4-47M9-5MC7 repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=5 members=0 REJECT_ROUTING filename_overlap
318. GHSA-Q5XF-XHWF-CWQF repo=n8n-io/n8n closer=7786117e9766 src=release_tag np=1 files=35 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
319. GHSA-Q6RC-2CGV-63H7 repo=miurahr/py7zr closer=e278bc05cc93 src=release_tag np=1 files=1 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
320. GHSA-QF2F-QH6P-7V89 repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
321. GHSA-QH43-XRJM-4GGP repo=kimai/kimai closer=999d820d4ca1 src=release_tag np=1 files=82 nontest=43 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
322. GHSA-QHXG-623C-CFJM repo=nocodb/nocodb closer=93adcf0cdc77 src=release_tag np=2 files=0 nontest=0 members=5 REJECT_ROUTING merge_update_not_mechanism
323. GHSA-QQHF-PM3J-96G7 repo=mindsdb/mindsdb closer=1ac0d8f3dcda src=release_tag np=2 files=0 nontest=0 members=17 REJECT_ROUTING merge_update_not_mechanism
324. GHSA-QVJF-922G-PJ44 repo=getkirby/kirby closer=2b37e83368ea src=release_tag np=1 files=3 nontest=3 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
325. GHSA-QW48-84F6-28GV repo=mkh-user/graphite closer=e37aa3b9952e src=release_tag np=1 files=4 nontest=4 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
326. GHSA-QW64-3X98-G7Q2 repo=go-git/go-billy closer=237e529bb8de src=release_tag np=2 files=0 nontest=0 members=2 REJECT_ROUTING merge_update_not_mechanism
327. GHSA-QWGJ-RRPJ-75XM repo=MervinPraison/PraisonAI closer=b4e3a8a84ade src=release_tag np=1 files=14 nontest=5 members=0 REJECT_ROUTING filename_overlap
328. GHSA-QXWQ-Q265-HC44 repo=nocodb/nocodb closer=391834484b11 src=release_tag np=2 files=0 nontest=0 members=40 REJECT_ROUTING merge_update_not_mechanism
329. GHSA-R2X7-427F-RQ69 repo=lin-snow/Ech0 closer=b934467d26b9 src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
330. GHSA-R3W8-2C5R-H9J9 repo=getkirby/kirby closer=274dca6df93d src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
331. GHSA-R5FR-9GMV-JGGH repo=kanidm/kanidm closer=7d4108698cae src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
332. GHSA-R5J5-Q42H-FC93 repo=mautic/mautic closer=4c29f1e00d82 src=release_tag np=2 files=0 nontest=0 members=1 REJECT_ROUTING merge_update_not_mechanism
333. GHSA-R633-FCGP-M532 repo=gtsteffaniak/filebrowser closer=09713b32a5f6 src=release_tag np=1 files=5 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
334. GHSA-R9GP-7F88-9R54 repo=Netflix/lemur closer=4afd730de39f src=release_tag np=2 files=0 nontest=0 members=2 REJECT_ROUTING merge_update_not_mechanism
335. GHSA-R9X3-WX45-2V7F repo=MervinPraison/PraisonAI closer=d80bff2d9aee src=release_tag np=1 files=20 nontest=13 members=0 REJECT_ROUTING filename_overlap
336. GHSA-RCPH-X7MJ-54MM repo=nocodb/nocodb closer=391834484b11 src=release_tag np=2 files=0 nontest=0 members=40 REJECT_ROUTING merge_update_not_mechanism
337. GHSA-RFPP-2HGM-GP5V repo=indico/indico closer=c6dabbe3dc75 src=release_tag np=1 files=2 nontest=1 members=0 REJECT_ROUTING release_tag_not_mechanism
338. GHSA-RH79-75QM-GWJR repo=go-gitea/gitea closer=b969123b7fac src=release_tag np=1 files=1 nontest=1 members=0 REJECT_ROUTING no_atomic_pr_member_marker_on_mechanism_hunk
339. GHSA-RHJ6-R49H-5932 repo=getkirby/kirby closer=274dca6df93d src=release_tag np=1 files=2 nontest=0 members=0 REJECT_ROUTING release_tag_not_mechanism
340. GHSA-RJR7-JGGH-PGCP repo=go-chi/chi closer=3b171578ca44 src=release_tag np=1 files=7 nontest=3 members=0 REJECT_ROUTING ai_on_fix

ROUTE 0. REJECT_ROUTING 60. Did not pad. Shared SHA is not identity dedupe. Slice unique and disjoint from ranks 1-280 by selection identity. Closers were recovered only from first-party advisory release/tag refs; this slice has no advisory PR refs. Tag commits that are version metadata, empty merges, AI-on-fix, or filename-overlap history without exact hunk reversal are not seven-gate proof.

## Routing rule

ROUTE requires a named exact closer object and a recognized atomic source_matcher hit before that closer on a plausible same-mechanism non-test hunk, plus landed topology and a released vulnerable artifact. Reject AI-on-fix, shared SHA, filename overlap, PR branding, squash trailer transfer, OSV introduced, nearby history, carrier-only trailers, sibling file, old bug, comment-only overlap, and test-only closers. Inspected ranks 281-340 produced 0 ROUTE rows. No PASS proposal.

## Blockers

- Inspected ranks 281-340 produced 0 ROUTE rows. No PASS proposal.
- Canonical94 stays 94 HOLD. Greater-than-200 remains unsupported.
- Recovered release/tag objects without a pre-closer same-mechanism AI hunk are not seven-gate proof.

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
