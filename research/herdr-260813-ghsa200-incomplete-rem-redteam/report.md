# Red-team: upgrade-b AI_INCOMPLETE_REMEDIATION PASS ordinals

**Status: `REDTEAM_COMPLETE`.** Worker PASS rows were hypotheses. Independent first-party GHSA fetch and Git replay from `/home/hanqing/.cache/ghsa200-worker-clones/incomplete-rem-redteam`. A KEEP here would still only be a proposal. **No KEEP.**

| Ordinal | GHSA | Worker | Red-team |
|--------:|------|--------|----------|
| 127 | GHSA-5C6W-WWFQ-7QQM | PASS | **NARROW** |
| 128 | GHSA-4MR5-G6F9-CFRH | PASS | **NARROW** |
| 130 | GHSA-QF5V-M7P4-95RP | PASS | **NARROW** |
| 131 | GHSA-R48C-V28R-PF6V | PASS | **NARROW** |
| 134 | GHSA-WPXJ-VHFP-HHVM | PASS | **NARROW** |
| 138 | GHSA-R9MR-M37C-5FR3 | PASS | **NARROW** |
| 139 | GHSA-94P4-4CQ8-9G67 | PASS | **NARROW** |
| 141 | GHSA-3RP5-JJMW-4WV2 | PASS | **NARROW** |
| 142 | GHSA-539M-9XH6-Q6RR | PASS | **NARROW** |
| 143 | GHSA-P538-C434-8V24 | PASS | **NARROW** |
| 170 | GHSA-V396-V7Q4-X2QJ | PASS | **NARROW** |
| 180 | GHSA-3WXW-XV34-2FRG | PASS | **NARROW** |
| 192 | GHSA-2X93-H3HG-2XFP | PASS | **NARROW** |
| 195 | GHSA-9C3V-684M-579C | PASS | **NARROW** |

Contract test used: the counted residual must be created or structurally required by the AI remediation. Reverting the AI hunk must remove that residual rather than merely reopen a broader old hole. Risk-reducing incomplete hardening is not causal.

## Shared finding

Every assigned PASS is a real AI-marked security attempt plus a later same-mechanism completion that ships in a later tag. Parent trees already admitted the named residual (or, for 170, a later non-AI checker rewrite created it). Reverting the AI rem broadens the old vulnerability. `but_for_gate` is NARROW on all 14. Other gates are recorded independently and do not promote the row.

## Ordinal 127 — NARROW

Repo and global GHSA-5c6w-wwfq-7qqm / CVE-2026-47390: PraisonAI spider_tools SSRF via alternate loopback encodings; `praisonaiagents <= 1.6.39` patched `>= 1.6.40`.

`claude[bot]` `3cd664bf` adds `_validate_url` hostname list plus `ipaddress.ip_address(hostname)`. Parent spider file exists without that validator. `v4.6.39` contains the candidate and not `179cab02`. `v4.6.40` adds int/hex parsing.

Hex encodings already fetched on the parent. Revert restores unrestricted SSRF.

## Ordinal 128 — NARROW

Repo and global GHSA-4mr5-g6f9-cfrh / CVE-2026-47392: `print.__self__` sandbox leak. Same SHAs as 127, different first-party GHSA.

Parent `execute_code` used full `__builtins__`. The AI sandbox is incomplete new hardening. Revert restores unrestricted exec. Distinct identity from 127.

## Ordinal 130 — NARROW

Repo and global GHSA-qf5v-m7p4-95rp / CVE-2026-50570: incomplete capability denylist, `SYS_TIME`; `<= 1.24.0` patched `1.25.0`.

Claude trailer is on member `2db76f65` (not a `v1.24.0` ancestor) and on squash `e484df84` (is an ancestor). Released `dangerousCapabilities` omits `SYS_TIME`. Parent has no that file. Revert restores privileged/SYS_ADMIN as well. Allowlist `2569b42b` is first in `v1.25.0`.

## Ordinal 131 — NARROW

Repo and global GHSA-r48c-v28r-pf6v / CVE-2026-44430: 6to4/NAT64/site-local SSRF; `< 1.7.7` patched `>= 1.7.7`.

Member `257eb178` is not a `v1.7.5` ancestor. Carrier `1201cbd8` is `v1.7.5` and Claude-marked. Parent has no `isBlockedIP`. Revert restores unguarded dials including RFC1918. `f5f40bd9` is first in `v1.7.7`.

## Ordinal 134 — NARROW

Published repo GHSA-wpxj-vhfp-hhvm / CVE-2026-33632. Global `/advisories` 404 reproduced. Identity uses the repo object.

Claude `a3d1733d` expands AUTH_* intercepts and still omits `AUTH_CLONE` / `AUTH_EXCHANGEDATA`. Parent was AUTH_OPEN-only, so clone was already a bypass. `v4.2.3-d488a1e` residual; `v4.2.4-6181c4a` / `6181c4a2` completes. Revert returns to OPEN-only.

## Ordinals 138, 142, 143 — NARROW (shared GPT 5.6 origin `701ce32f`)

Three non-aliased GHSAs. Parent has no `_option_candidates`, no archive denylist, and no `iter_items`/`count` unsafe-option checks. `701ce32f` introduces those gates incompletely. Revert removes the new gates entirely.

- 138: key-only `_option_candidates`; `e8d0fbf7` / `3.1.54` adds value tokens. Residual tag `3.1.53`.
- 142: new archive denylist omits `--add-file`; `7a4f5dcb` / `3.1.57`. Residual `3.1.56`.
- 143: `iter_items` guarded, `Commit.count` not; `38553b6f` / `3.1.56`. Residual `3.1.55`. Parent count was already unguarded.

## Ordinal 139 — NARROW

GHSA-94p4-4cq8-9g67: incomplete fix of clone URL env expansion. GPT 5.6 `8ac5a305` sets `expand_vars=False` on clone only. `remote.py` still `Git.polish_url(url)` on parent and candidate. Revert re-opens clone expansion. `86341745` / `3.1.55` closes Remote/Submodule. Git residual includes `3.1.54` even though GHSA array says `<= 3.1.53`.

## Ordinal 141 — NARROW

GHSA-3rp5-jjmw-4wv2: unquoted `]` after CR/LF/NUL guard. GPT 5.5 `54538428` adds the charset helper. Parent has none. Unquoted `]` was already possible. `1ed1b924` / `3.1.53` adds the bracket walk. Distinct from GHSA-MV93.

## Ordinal 170 — NARROW

GHSA-v396-v7q4-x2qj names joined short options on GitPython `= 3.1.50` patched `3.1.51`.

GPT 5.4 `c9a26789` switches clone checking onto shlex tokens. At that commit, `check_unsafe_options` still uses `startswith`. `-uVALUE` is already rejected. The 3.1.50 exact-canonical matcher is `142195888e713542189533a52cdfc333f05c3af6` by `w <w@mac.lan>` with no AI marker. Reverting only `c9a26789` leaves that matcher; `-uVALUE` still bypasses. `56806080` / `3.1.51` closes joined shorts. Worker candidate is not but-for of the advisory residual.

## Ordinal 180 — NARROW

Repo GHSA-3wxw-xv34-2frg. Global 404 reproduced. GPT 5.6 `3af0c251` adds kwargs-only `--file`/`-F` check. Parent `create()` had no check; positional path/reference already supplied `--file`. `3.1.58` residual; `1b0d2d9b` / `3.1.59` includes `[path, reference]`. Revert removes kwargs rejection too.

## Ordinal 192 — NARROW

Repo GHSA-2x93-h3hg-2xfp. Global 404 reproduced. `[AI]` `b75ad800` adds snapshot/tab SSRF checks on an existing `agent.snapshot.ts`. Current-tab miss remains. `v2026.5.22` has candidate not fix; `v2026.5.26` has `06047005`. Revert leaves snapshots unchecked.

## Ordinal 195 — NARROW

Repo and global GHSA-9c3v-684m-579c: SSE redirect Authorization. `[AI]` `47eb2d48` scrubs streamable-HTTP only. Parent already built `SSEClientTransport` without that scrub. `v2026.6.1` residual; `v2026.6.5` / `3c6259eb` extends fetch-guard. Revert restores HTTP forwarding too.

## Sources

| Repo | HEAD | Committer date |
|------|------|----------------|
| praisonai | `0e55b360566e16d797bfc81658a4f21527ef05e6` | 2026-04-01T21:01:39+01:00 |
| fission | `a106aa583733511db51aad79c4d9ff0ab6af1243` | 2026-07-24T19:16:27+05:30 |
| mcp-registry | `29e32c39dcb5e0e2b43974089d959fcc4794eb6d` | 2026-07-13T05:03:10-04:00 |
| clearancekit | `d94d921492481d05d53143a9ca1c501b3ddd9163` | 2026-07-25T19:25:03+01:00 |
| GitPython | `f44c1fb0e5dc3b3f0df58c7834ceed336f0d36fc` | 2026-08-11T15:54:56+02:00 |
| openclaw | `b3d5265f58522bab67e06168d436b3b328cbae60` | 2026-08-13T14:02:39-07:00 |

Clones and advisory JSON: `/home/hanqing/.cache/ghsa200-worker-clones/incomplete-rem-redteam/{clones,pages}/`. Hypothesis input: upgrade-b `cases.jsonl` SHA-256 `163ef8a6f7f14c410710c7ebcfe9913ddbb0ef4fcdbd0aa0b6c07e8c3eb59745` as recorded in that worker's `result.json` when these 14 PASS rows were extracted.
