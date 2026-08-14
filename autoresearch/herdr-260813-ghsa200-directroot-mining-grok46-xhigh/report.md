# Direct-root GHSA mining

**Status: TERMINAL / HOLD. Hard checkpoint. Discovery and analysis stopped. Proposed PASS = 1. Countable PASS = 0. REJECT = 29.**

Worker PASS is a proposal only. Publication and any more-than-200 claim remain HOLD. `causal_admission` is false. No further candidates will be inspected.

This lane starts from first-party GitHub-reviewed repository advisories with exact fix commits, then traces the fix-parent deleted hunks with git log/blame onto an AI-marked first-parent commit. GitHub-unreviewed 2025-2026 objects that mention a repository advisory URL all name a *different* GHSA identity (684 aliases, 0 same-id first-party rows) and are not counted.

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Shared tracked files were not edited. No commit, push, or credential output.

## Provenance (two hashes, two roles)

- **Frozen conservation inputs:** `CONTRACT.md` `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`, leader `baseline.json` `d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132`, fp211 public cases `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`, fp211 ledger `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`, fp211 final mechanisms `0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2`, netnew22 `result.json` `c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829` (21 KEEP identities), netnew22 `cases.jsonl` `d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889`. Frozen routing indexes: GN `ai-commit-scans.jsonl` `a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a`, AF `ai-commits.jsonl` `9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0`, OZ `ai_mine.jsonl` `047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a`. Replay fails if any of these bytes move.
- **Current overlap check:** live `scripts/publication_adjudications.json` after `5620e01` is SHA-256 `9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f`. `GHSA-Q855-8RH5-JFGQ` is absent. This check does not re-select the reviewed set. Pending Actual/B3/Gogs case files are pinned in `replay.sh` as current overlap only.

## Exclusion (not counted, not proposed)

| Set | Count |
|---|---:|
| Strict 48 baseline | 48 |
| Frozen netred 21 KEEP | 21 |
| Pending Actual / B3 / Gogs | 5 |
| fp211 public-case identities | 212 |
| Unique discovery-exclude union | 215 |

Pending identities: `GHSA-7GH7-258J-4MPQ`, `GHSA-6P9M-Q3JP-47H4`, `GHSA-G3XQ-3GMV-QQ8G`, `GHSA-PV2J-RGHR-V5R9`, `GHSA-F38V-77QJ-H4JQ`.

## Conservation

| Set | Count |
|---|---:|
| github-reviewed 2025+2026 JSON parsed | 12817 |
| First-party window active (published >= 2025-05-01, not withdrawn) | 8757 |
| With exact same-repo commit refs | 4652 |
| Eligible after discovery-exclude | 4507 |
| Rank pool (clone + AI-marked commits present) | 3473 |
| File-history / blame hits (routing) | 830 |
| Deep-reviewed here | 30 |
| Remaining ranking hits UNREVIEWED | 800 |
| Rank-pool misses (no AI history on fix files) UNREVIEWED | 2643 |
| Eligible skipped (no AI commits or clone missing) UNREVIEWED | 1034 |
| github-unreviewed same-id first-party | 0 |

Proven equalities: 30 + 800 + 2643 = 3473; 3473 + 1034 = 4507; 1025 + 9 = 1034. Unreviewed rows are UNREVIEWED, not REJECT. REJECT applies only to the 29 reviewed non-PASS identities.

## Terminal outcomes

| Worker verdict | Rows |
|---|---:|
| PASS (proposal only, uncounted) | 1 |
| REJECT | 29 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |

### Proposed PASS

**GHSA-Q855-8RH5-JFGQ** (`homeassistant-ai/ha-mcp`) — `AI_DIRECT_ROOT`.

Claude-marked squash `9783f346795be919bffda8a6475ae716a9e3580c` (one parent `8ba80aee`) adds `src/ha_mcp/settings_ui.py`. Under `is_addon` it registers unauthenticated `mcp.custom_route("/", ...)` and `/api/settings/*` so Home Assistant ingress can serve the Open Web UI button. The parent tree has no that file. First-party advisory `work/pages/ghsa-q855-8rh5-jfgq.json` (SHA-256 `fa423727d9fe61f903e744547f85e41dd1020ac79473b8d807c023dbda9a0346`) names exactly those bare-root routes.

Minimum fix `9f5b085ad4a7b38b067c9da0dc5b45462c4d796e` wraps the root mounts in `_ingress_only` (Supervisor `172.30.32.2`). Tag `v7.5.0` / PyPI `ha-mcp` 7.5.0 wheel member `ha_mcp/settings_ui.py` git blob `46d32362fbed4d0706bf70601cbfbbf2dfc69b08` still blames the `custom_route("/")` lines on `9783f346` and does not contain the fix. Tag `v7.7.0` / PyPI 7.7.0 blob `36479aaa873cba5d0cad41d21327f01646c7bb72` blames `SUPERVISOR_INGRESS_IP` / `_ingress_only` on `9f5b085a`. Both GitHub releases are `prerelease=false`. Advisory `introduced:0` and first_patched `7.10.0` are not used as origin proof; git ancestry is.

All seven gates PASS for this scope. Countable PASS remains 0 until leader admission.

### REJECT (29)

High-signal blame hits failed but-for, uniqueness, or atomic origin: LobeHub CLI XOR copy of an old server bypass; Locutus parse_str test sharing counted `GHSA-VC8F`; MCP Python session/OAuth siblings; LightRAG incomplete CORS; clasp docs-only Jules commit; Go MCP case-insensitive `encoding/json`; Gogs type-decouple / sanitizer / rename; Gradio 6.0 mega-squash; Fiber cache review; oh-my-posh extra.go; Gitea Actions/CodeQL siblings; Vikunja notification wording; ruby-jwt version bump.

Nine further rows had AI file-history on the fix files but **zero** blamed lines on the deleted hunks. File history without hunk identity is not a proposal.

REJECT identities (29): `GHSA-5MWJ-V5JW-5C97`, `GHSA-4MPH-V827-F877`, `GHSA-J975-95F5-7WQH`, `GHSA-6X6H-QQR7-855W`, `GHSA-HQJG-PWW4-PCGQ`, `GHSA-WVJ2-96WP-FQ3F`, `GHSA-268J-37XF-PP52`, `GHSA-3W28-36P9-W929`, `GHSA-3QHF-M339-9G5V`, `GHSA-JMH7-G254-2CQ9`, `GHSA-35HP-HQMV-8QG8`, `GHSA-6XJ8-QV9J-XCJQ`, `GHSA-JPW9-PFVF-9F58`, `GHSA-FJ8V-HJWV-QM88`, `GHSA-FW57-JGCH-PGF3`, `GHSA-89MR-XQFV-758M`, `GHSA-C39W-43GM-34H5`, `GHSA-45Q4-X4R9-8FQJ`, `GHSA-C32J-VQHX-RX3X`, `GHSA-777R-4V59-6486`, `GHSA-VFGX-5Q85-58Q3`, `GHSA-RFR2-MQ9M-X2QX`, `GHSA-954P-556P-R752`, `GHSA-28GM-JRMW-XX93`, `GHSA-G754-HX8W-X2G6`, `GHSA-FC6G-2GCP-2QRQ`, `GHSA-X2HW-PX52-WP4M`, `GHSA-M98R-6667-4WQ7`, `GHSA-FPW6-HRG5-Q5X5`.

The 800 remaining ranking hits are UNREVIEWED, listed in `work/unreviewed-hit-ids.txt`. They are not REJECT. `replay.sh` is fail-fast, offline, and English-only.

## Claim boundary

- Countable PASS requires all seven gates **and** leader admission.
- Proposed PASS: **1**. Countable PASS: **0**.
- Publication HOLD. A more-than-200 claim is not supported here.
- OSV `introduced`, commit subjects, later AI review, carrier/member authorship transfer, old-bug preservation, aliases, and unrelated sibling fixes were not promoted.
- This worker did not edit tracked canonical files, commit, or push.
