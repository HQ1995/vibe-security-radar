# cf2 fresh-delta post-a42c

Verdict first: **0 PASS_PROPOSAL**. **0 upgrade PASS**. **0 net-new PASS**. Inspected **29** github-reviewed identities in `a42c436..6253da86`. **24 REJECT**. **5 UNKNOWN**. Bound 40 not reached. packet_delta **0**. Canonical85 stays **85**. Foundation stays **165**. Publication and greater-than-200 remain **HOLD**. Worker PASS is proposal only. Seven gates must be exact PASS after replay; none are.

## Policy correction

Modified advisory paths are not skipped for foundation membership. Those rows are an **upgrade** track: inspect whether the official update closes a prior NARROW/UNKNOWN identity or release gate. Canonical85 counted IDs stay excluded from **net-new** counting. Upgrades are reported separately from new identities.

In this delta, **zero** of the 15 modified paths are foundation rows and **zero** are canonical85 counted IDs. All 15 were still scanned for identity/release-closing payload. origin/main remains `6253da86d07848917009b6e81740ffbed19e349f`.

## Advisory-database heads

- Old / frozen: `a42c436870111aa3f221257c9d56126a93173ccc` 2026-08-13T20:57:17Z Publish GHSA-p28v-f755-9qrg
- New / origin/main: `6253da86d07848917009b6e81740ffbed19e349f` 2026-08-14T19:54:17Z Publish GHSA-p6jf-79j3-33f3
- Range commits: 24
- github-reviewed JSON identities: 34389 frozen, 34403 current
- Added reviewed (net-new identities): 14
- Modified reviewed (upgrade scan): 15
- Deleted reviewed: 0
- Exact changed paths: 29 (listed in assignment.jsonl)

Pinned source clone `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database` stayed at `a42c436870111aa3f221257c9d56126a93173ccc`. Owned blob:none clone lived under `/tmp/herdr-260814-cf2-fresh-delta-grok46-xhigh/` and is deleted at handoff.

## Upgrade track (15 modified paths)

Foundation-modified IDs: none. Canonical85-modified IDs: none. Upgrade PASS_PROPOSAL: none.

Modified rows whose official update could have closed identity or release, and why they still fail seven-gate PASS after replay:

| ID | Payload | Why not upgrade PASS |
| --- | --- | --- |
| GHSA-HHPQ-7WG4-36JM | Added 2.11.1 plus commit/PR/release URLs | Closers are Mark Story. Local tags 2.11.1/3.3.6/4.1.1 absent. AI hunk FAIL. |
| GHSA-355H-QMC2-WPWF | Added fixed 11.0.29, 10.0.28, 9.4.60 | No listed SHA. Extra jetty tags absent locally. UNKNOWN, never PASS. |
| GHSA-CX4M-2P55-RW7J | Added fixed 1.9.5 | No listed SHA. 1.9.5 tag absent. UNKNOWN, never PASS. |
| GHSA-W22P-4X9F-486V | Added jenkinsci/github-plugin URL | Identity naming improved. No SHA, no clone. UNKNOWN, never PASS. |

Related counted identity (not an upgrade of that row): GHSA-4C8G shares repo `fastify/fast-uri` with canonical85/foundation GHSA-7P8R. Different GHSA and mechanism. 0542a216 is not an ancestor of 2a6d357. 7P8R stays excluded from net-new counting.

## Net-new track (14 added + 15 modified non-foundation)

None of the 29 IDs are in canonical85 or foundation. CVE aliases were not counted. Recorded REJECT identities still received a row: GHSA-29RF, GHSA-9QRM, GHSA-XVCM. GHSA-FRVJ is in foundation and is absent from this delta.

## Method

For each new or modified active github-reviewed GHSA, parse first-party fix refs from the advisory JSON, prefer existing caches, then bounded smart-HTTP fetches into owned `/tmp` repos. Search closer source-file history for explicit AI trailers. An AI-marked squash carrier does not transfer authorship. An advisory-listed closer is not an origin. Same-file AI is routing only. Incomplete rem requires an AI security-boundary rewrite whose residual the closer amends; preserving an older bug fails. Missing objects stay UNKNOWN. Seven-gate PASS is exact PASS on identity, AI hunk, topology, but-for, fix reversal, release, and uniqueness after local replay.

## PASS_PROPOSAL

Net-new: none. Upgrade: none.

## Counterevidence (strongest near-misses)

| ID | Track | Verdict | Why not PASS |
| --- | --- | --- | --- |
| GHSA-8G5P-JXP9-457C | net-new | REJECT | Claude 1f1dc16 adds a skip-TLS forecaster caller; inspector still hardcodes true on a human helper. |
| GHSA-8RW6-P7M8-63JP | net-new | REJECT | Array-index leak loop in output.rs is Tobie; Claude is on squash PR #81/#116 carriers. |
| GHSA-C9CV-MQ2M-PPP3 | net-new | REJECT | Claude hit is a console-warning prefix on router.ts, not navigateTo. |
| GHSA-V5M8-5455-QW2X | net-new | REJECT | GetSourceDownloadURL is Cosmin; Claude only adds owner name fields. |
| GHSA-9HGC-G3W5-67CM | net-new | REJECT | ICACF-15 / DNS pin commits are human Signed-off-by. |
| GHSA-HHPQ-7WG4-36JM | upgrade-scan | REJECT | New 2.11.1/commit refs; human Mark Story closer. |
| GHSA-XVCM-6775-5M9R | upgrade-scan | REJECT | Recorded AI-on-closer; delta is a typo. |
| GHSA-29RF-F4VV-PVQ6 | net-new | REJECT | Recorded human RC-only closer. |
| GHSA-4C8G-83QW-93J6 | upgrade-scan | REJECT | Not an ancestor of counted 7P8R SHA 0542a216; no AI on index.js. |
| GHSA-36JR-MH4H-2G58 | upgrade-scan | REJECT | CWE reorder only. |

UNKNOWN rows are GHSA-355H, GHSA-W22P, GHSA-CX4M, GHSA-QCXQ, GHSA-VGWF: no recoverable introducing hunk in this packet. Extra fixed versions or repo URLs do not mint PASS.

## Conservation

29 assigned = 29 reviewed + 0 unreviewed. net_new PASS_PROPOSAL=0. upgrade PASS_PROPOSAL=0. packet_delta=0. cve_aliases_counted=false. canonical85_overlap=0. foundation_modified=0.

## Claim boundary

This packet does not admit cases. Current leader-accepted strict count remains 85 at canonical85 HOLD. L0 claim source stays canonical84 ledger unless a new canonical directory is built. Greater-than-200 remains unsupported.
