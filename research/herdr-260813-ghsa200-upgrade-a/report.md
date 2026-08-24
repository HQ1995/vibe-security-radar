# Upgrade lane A — ordinals 1-110 NARROW, UNKNOWN, and CONFIRM/MEDIUM

Date: 2026-08-13

Lane: `autoresearch/herdr-260813-ghsa200-upgrade-a/`

Worker PASS is a proposal. It is not ledger admission.

The strict released baseline is **48**, not 65. More than 200 unique released GHSA cases requires at least **153** net new admissions.

## Answer

Assigned in ordinals 1-110: every NARROW, UNKNOWN, or CONFIRM/MEDIUM row.

`cases.jsonl` contains **exactly** the 58 ordinals in `leader/baseline.json` `upgrade_shards.upgrade_a.ordinals`, in that order, including unchanged failures. Coverage was not limited to one-gate rows.

| Class in 1-110 | Assigned | Terminal verdict |
|---|---:|---|
| NARROW | 53 | 4 proposed PASS, 29 remain NARROW, 20 BLOCKED on GHSA/API fetch |
| UNKNOWN | 5 | 5 remain UNKNOWN |
| CONFIRM/MEDIUM | **0** | none in lane |
| **Assigned total** | **58** | **58** |

CONFIRM/HIGH in 1-110: 27 rows, all seven gates already PASS in fp211. They are part of the existing 48-bound set, not upgrade targets.

CONFIRM/MEDIUM globally: 14 rows, all ordinals **114+**. They are out of this lane. No in-lane CONFIRM/MEDIUM row was skipped.

Independent re-evaluation of the 58 assigned rows proposes **4** strict released promotions. **29** stay NARROW. **5** stay UNKNOWN. **20** are BLOCKED because this lane could not recover a first-party GHSA object (GitHub API 403/429). **0** REJECT.

First-party GHSA/API fetch failures stay BLOCKED/UNKNOWN. They are never inferred PASS.

BLOCKED ordinals: 77, 79, 80, 82, 85, 86, 87, 88, 91, 95, 96, 97, 98, 99, 100, 101, 102, 103, 105, 108.

Proposed PASS case IDs (leader must replay):

| Ordinal | Case | Repository | Why the missing gate closed |
|---:|---|---|---|
| 1 | GHSA-FMFG-9G7C-3VQ7 | homeassistant-ai/ha-mcp | Count the Claude-marked squash carrier `39806871` as the atomic origin of `ha_url` to `{ha_url}/api/config`. Parent has no `provider.py`. Tag `v6.7.2` still has the form field; `v7.0.0` contains `dc8eaa16` and does not. Member blob inequality no longer defines topology once the released squash itself carries the AI footer. |
| 20 | GHSA-XW8C-RRVX-F7XQ | Jo-Jo98/ciguard | Drop `osv.py` / `f08e6549` from the origin set. Tag `v0.6.0` contains Claude `d42195e1` `endoflife.py` unbounded `resp.read()` and does not contain `osv.py`. Fix `17a119fe` in `v0.8.2` adds `MAX_RESPONSE_BYTES`. |
| 92 | GHSA-WV46-V6XC-2QHF | openclaw/openclaw | After fetching missing member `ce12b909`, blobs still differ. The released squash `9a3800d8` independently has Co-Authored-By Claude Opus 4.6, adds `resolveChatUserId` nickname matching, is in `v2026.3.2`, and is reversed by `7ade3553` (`dangerouslyAllowNameMatching`) in `v2026.3.22`. |
| 93 | GHSA-RG8M-3943-VM6Q | openclaw/openclaw | After fetching missing member `fbfe2f15`, blobs still differ. Squash `49c60e90` has Co-authored-by Claude Opus 4.5, adds `ThreadStarterBody` (parent has none), is in `v2026.2.12`, and is reversed by sender-allowlist `8a563d60` in `v2026.3.31`. |

## Source revisions and hashes

Frozen inputs (replay asserts these bytes):

| Artifact | sha256 |
|---|---|
| `CONTRACT.md` | `2dcf018d7fad06991c8fb5eb1c63758900207c2f85858ee6805d81041958058b` |
| `leader/baseline.json` | `0939c995b14b419128dc47e4ad767fb136f714bd6f71e028b2528cc4afa8d6d2` |
| `fp211/final_mechanisms.jsonl` | `0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2` |
| `fp211/public_cases.jsonl` | `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257` |
| `fp211-canonical/ledger.jsonl` | `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6` |

Git objects used by the four proposals:

| Ordinal | Object | Revision |
|---|---|---|
| 1 | candidate/carrier | `39806871c9720bf8afdcf3e061095c0dd63dea7f` |
| 1 | fix | `dc8eaa16a8550f885614655f14b6fd9fe429b278` |
| 1 | vulnerable tag `v6.7.2` | `ce61f0040d7110be57f7b998ecefee0d2a6e69af` |
| 1 | fixed tag `v7.0.0` | `77e86c21ab43977b52fba43632cdf831cf1082d8` |
| 20 | candidate | `d42195e10be0d7d9bfb4ec45fecfb83521d3fc67` |
| 20 | excluded osv origin | `f08e654974f208f90ef6015928ef651982f3224a` |
| 20 | fix | `17a119fe43dd956ef463c1c575a463ffd9a8d95b` |
| 20 | vulnerable tag `v0.6.0` | `e7a41d4b7320a428868497914bde52d67b447659` |
| 20 | fixed tag `v0.8.2` | `ca5accfeabb96028ec9a07295573ebeeeb09ae0f` |
| 92 | candidate/carrier | `9a3800d8e6e69bc0a125dca5760d47515e746454` |
| 92 | supporting member | `ce12b9092f03d85603f0b6b8193d512260a65dab` |
| 92 | fix | `7ade3553b74ee3f461c4acd216653d5ba411f455` |
| 92 | vulnerable tag `v2026.3.2` | `85377a28175695c224f6589eb5c1460841ecd65c` |
| 92 | fixed tag `v2026.3.22` | `4c016f51fc83865edfeda93e4f1e59118f6df0a8` |
| 93 | candidate/carrier | `49c60e9065d98a6848e62c717315eb91eeaa6038` |
| 93 | supporting member | `fbfe2f15fc316904972711b3391031d6c99682b4` |
| 93 | fix | `8a563d603b70ef6338915f0527bee87282c3bad5` |
| 93 | vulnerable tag `v2026.2.12` | `ed0a4cb3611d764773ee7c2ac6ee309750175192` |
| 93 | fixed tag `v2026.3.31` | `ef21ed5a60e31e862db9776f023e84de1d4f4c20` |

On-disk first-party GHSA JSON for the four proposals (not live API): `GHSA-fmfg-9g7c-3vq7`, `GHSA-xw8c-rrvx-f7xq`, `GHSA-wv46-v6xc-2qhf`, `GHSA-rg8m-3943-vm6q` under `/tmp/ghsa200-worker-clones/upgrade-a/pages/ghsa/`. None is withdrawn.

Executable replay: `bash autoresearch/herdr-260813-ghsa200-upgrade-a/replay.txt`

## Method

1. Read `CONTRACT.md` and freeze fp211 `final_mechanisms.jsonl` (`0d76a1a8…`) plus the canonical overlay ledger and `leader/baseline.json`.
2. Select every ordinal <= 110 with verdict NARROW, UNKNOWN, or CONFIRM/MEDIUM. That is 53+5+0=58 rows. Prioritize 17 rows with exactly one non-PASS gate. Census the 14 global CONFIRM/MEDIUM ordinals and leave 111-211 untouched.
3. Clone or copy repositories only under `/tmp/ghsa200-worker-clones/upgrade-a/`. Fetch global and repository GHSA JSON. Fetch missing OpenClaw members `ce12b909` and `fbfe2f15` into the lane clone.
4. Re-run parent/candidate/carrier/fix/tag ancestry, blob identity, AI footers, and npm packuments. Do not inherit the baseline verdict.
5. Promote only when all seven gates close on an explicit scope. Contributor/new-surface rows may PASS only if deleting the AI delta materially shrinks that scoped mechanism; none of those rows closed every gate in this lane.
6. Emit a terminal row for every assigned ordinal.

## Preserved UNKNOWN (5)

- **35** Coolify `GHSA-4MPW-WCJ4-V9PP`: Conductor auto-commit origin, no AI hunk.
- **51** OpenClaw `GHSA-VJP8-WPRM-2JW9`: `Generated by staged fix workflow` is not relevant-hunk AI proof.
- **53** wacrm `GHSA-8JQH-598V-RFXC`: identity/topology/release still unpublished-artifact / fix-merge traps.
- **56** Taylored `GHSA-8G98-M4J9-QWW5`: Jules origin exists; npm 7.0.5/7.0.7/7.0.8 have time keys and no tarballs; tag `8.2.4` already contains the fix.
- **84** Taylored `GHSA-VH5J-5FHQ-9XWG`: incomplete `/get-patch` race; npm 8.1.2/8.1.3 missing tarballs.

## One-gate rows that stayed NARROW (examples)

- **10** Hermes `/api/session`: foreign `state.db` read is a real AI contributor; parent sidecar IDOR remains.
- **21** SharpCompress: parent already extracted via `WriteToDirectory`.
- **25** Titra: parent already ran unsanitized `timeEntryRule` on vm2.
- **29** OpenClaw `/v1/responses`: new route on already-captured `resolvedAuth`.
- **30** Dynatrace MCP: Copilot timeframe is a new interpolation beside parent list-problems/list-exceptions. npm `@dynatrace-oss/dynatrace-mcp-server@1.2.0` / `2.1.1` gitHeads exist, so release is not the blocker.
- **74** Claude HUD: `234d9aad` realpath plus mode `0o600` does not root-constrain `transcript_path`.
- **78** OpenClaw CDP: CNA names `/json/version` second-hop; AI added direct WS.
- **107** Ironclaw: listed member is not an ancestor of `ironclaw-v0.29.1`; GHSA is generic `classify_command_risk` injection.
- **110** SolidCAM: Claude on a binary-only `v1.0.0` bump; no recoverable C# DTD hunk. Repo GHSA exists; global GHSA 404.

## CONFIRM/MEDIUM census (out of lane)

fp211 `final_mechanisms.jsonl` has 14 CONFIRM/MEDIUM mechanisms: ordinals 114, 122, 127, 128, 130, 131, 132, 134, 136, 138, 139, 141, 142, 143. None is <= 110. This lane emits no CONFIRM/MEDIUM terminal row because none is assigned here.

## Claim boundary

These four PASS rows are proposals, not admissions. If later admitted they would be 4 of the 153 net new released cases required to exceed 200 above the 48-case lower bound. The leader must replay first-party GHSA identity, git topology, but-for, minimum fix reversal, released containment, and uniqueness against every already accepted case before counting.
