# Patch-delta review of assigned AI_INCOMPLETE_REMEDIATION proposals

Schema: every `AI_INCOMPLETE_REMEDIATION` row records `remediation_patch_delta_gate` in addition to the seven legacy gates. KEEP requires `remediation_patch_delta_gate=PASS` and `but_for_gate=PASS`, with `but_for_gate` interpreted by the patch-delta rule. NARROW/REJECT/UNKNOWN record the corresponding non-PASS patch-delta value. Substantive verdicts are unchanged.

**Status: `COMPLETE`.** Independent first-party GHSA fetch and Git/tag replay from `/home/hanqing/.cache/ghsa200-worker-clones/increm-patchdelta-odd`. Worker KEEP is a proposal, never admission. Causal class is `AI_INCOMPLETE_REMEDIATION` on every row; none is labeled direct root.

Inputs: leader `CONTRACT.md` sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`; upgrade-b `cases.jsonl` sha256 `50493a20909eef41ac835042207a6e5b32fcd82f8c9486185de2e3e62d5cd84f`. Assigned ordinals exactly `[127, 131, 139, 141, 143, 195]`.

Patch-delta KEEP requires: AI-authored guard/parser/normalizer/denylist/allowlist; a released artifact contains that attempt without final closure; the first-party GHSA names a residual **in that boundary**; a later same-mechanism fix **directly amends** the AI-added boundary for the omitted case; identity/topology/release/uniqueness pass. Reverting to a broader old vulnerability is not a failure. AI fixing surface A while leaving unrelated old surface B untouched is not countable. Old incomplete-rem-redteam NARROW rows are counterevidence only.

| Ordinal | GHSA | upgrade-b | This review | remediation_patch_delta_gate | but_for_gate |
|--------:|------|-----------|-------------|-----------------------------:|:------------:|
| 127 | GHSA-5C6W-WWFQ-7QQM | PASS | **KEEP** | PASS | PASS |
| 131 | GHSA-R48C-V28R-PF6V | PASS | **KEEP** | PASS | PASS |
| 139 | GHSA-94P4-4CQ8-9G67 | PASS | **NARROW** | NARROW | NARROW |
| 141 | GHSA-3RP5-JJMW-4WV2 | PASS | **KEEP** | PASS | PASS |
| 143 | GHSA-P538-C434-8V24 | PASS | **NARROW** | NARROW | NARROW |
| 195 | GHSA-9C3V-684M-579C | PASS | **NARROW** | NARROW | NARROW |

## Ordinal 127 - KEEP

Repo and global GHSA-5c6w-wwfq-7qqm / CVE-2026-47390: PraisonAI `spider_tools` SSRF via alternate loopback encodings; `praisonaiagents <= 1.6.39` patched `>= 1.6.40`.

`claude[bot]` `3cd664bf` adds `_validate_url` exact-hostname list plus `ipaddress.ip_address(hostname)`. Parent has no that validator. GitHub Release / tag `v4.6.39` contains the candidate and not `179cab02`. `179cab02` (Cursor trailer) rewrites the **same** validator into `_host_is_blocked` with `int(host)` / `int(host, 16)` and is first in `v4.6.40`.

The GHSA names hex/int/dotted encodings that bypass **this** hostname list. That is an omitted case in the AI-added denylist, not an untouched sibling fetcher. Rollback would restore unrestricted SSRF; that is allowed.

## Ordinal 131 - KEEP

Repo and global GHSA-r48c-v28r-pf6v / CVE-2026-44430: HTTP namespace-verification dials of 6to4/NAT64/site-local IPv6; `< 1.7.7` patched `>= 1.7.7`.

Origin is Claude-marked tag commit `1201cbd8` (equals `v1.7.5`), which authors `isBlockedIP` without `2002::/16`, `64:ff9b::/96`, `64:ff9b:1::/48`, `fec0::/10`. Parent `http.go` has `http.Client` and no `isBlockedIP`. Squash member `257eb178` is not a tag ancestor; `http.go` blob `e40dd2a6` != shipped `7d73d523`. `v1.7.6` still has that incomplete blob. `f5f40bd9` extends **the same** `isBlockedIP` function and is first in `v1.7.7`.

The GHSA names those omitted prefixes in that blocklist. Rollback would restore unguarded dials including RFC1918; that is allowed.

## Ordinal 139 - NARROW

GHSA-94p4-4cq8-9g67 is explicitly an incomplete fix of clone-only `expand_vars=False`. GPT 5.6 `8ac5a305` guards `Repo._clone`. Parent `Remote.create` already called `Git.polish_url(url)` with default expansion. `86341745` sets `expand_vars=False` on Remote/Submodule callers; it does not amend the clone False already present.

The first-party advisory calls this the **sibling caller the fix missed**. Contract: AI fixing surface A while leaving unrelated old surface B untouched is not countable. Git `3.1.54` still lacks the sibling fix even though the GHSA array says `<= 3.1.53`.

This clone cannot read `git/objects/submodule/base.py` blob `d183672` at `8ac5a305` (missing promisor object). `git/remote.py` sibling evidence is complete.

## Ordinal 141 - KEEP

GHSA-3rp5-jjmw-4wv2: config section injection via unquoted `]` after a CR/LF/NUL name guard. GPT 5.5 `54538428` introduces `_assure_config_name_safe`. Parent has none. `3.1.52` contains that helper. GPT 5.6 `1ed1b924` walks unquoted `]` **inside the same helper** and is first in `3.1.53`.

The GHSA says the `[\r\n\x00]` guard does not stop a same-line section break. That is an omitted parser case in the AI-added boundary, not a sibling API. Distinct from GHSA-mv93 (newline injection); same SHA as that complete fix does not merge mechanisms. Rollback would drop CR/LF/NUL rejection too; that is allowed.

## Ordinal 143 - NARROW

GHSA-p538-c434-8v24 names `Commit.count()` `--output` with **no** `check_unsafe_options` while sibling `iter_items` is guarded. GPT 5.6 `701ce32f` adds `unsafe_git_rev_options` and wires `iter_items` only. Parent `count` already forwarded `**kwargs` into `rev_list`. `38553b6f` wires the sibling method.

The advisory calls this a distinct uncovered sink. That is surface A versus old surface B. Shared SHA `701ce32f` with other GitPython GHSAs is not an alias. Residual tag `3.1.55`; fix `3.1.56`.

## Ordinal 195 - NARROW

Repo and global GHSA-9c3v-684m-579c: MCP SSE redirects could forward Authorization. `[AI]` `47eb2d48` adds `fetchStreamableHttpWithRedirectScrub` only on `StreamableHTTPClientTransport`. Parent already built `SSEClientTransport` with `fetchWithUndici`; the candidate leaves that SSE block unchanged. `v2026.6.1` has the candidate not `3c6259eb`. `v2026.6.5` rewrites `mcp-http-fetch.ts` / `fetch-guard.ts` rather than amending an omitted case inside the streamable-HTTP helper.

AI fixing HTTP while leaving the old SSE transport untouched is not countable.

## Sources

| Repo | HEAD | Committer date |
|------|------|----------------|
| praisonai | `0e55b360566e16d797bfc81658a4f21527ef05e6` | `2026-04-01T21:01:39+01:00` |
| mcp-registry | `29e32c39dcb5e0e2b43974089d959fcc4794eb6d` | `2026-07-13T05:03:10-04:00` |
| GitPython | `f44c1fb0e5dc3b3f0df58c7834ceed336f0d36fc` | `2026-08-11T15:54:56+02:00` |
| openclaw | `b3d5265f58522bab67e06168d436b3b328cbae60` | `2026-08-13T14:02:39-07:00` |

Clones and advisory JSON: `/home/hanqing/.cache/ghsa200-worker-clones/increm-patchdelta-odd/{clones,pages}/`. Origin `git fetch` from GitHub failed in this environment with unresolved-delta pack errors; clones were created from the existing `/home` incomplete-rem-redteam object store, then GHSA/release JSON was refetched independently with `gh api`. Needed SHAs and tags resolved locally.

This packet proposes **three KEEP** rows and preserves **three NARROW**. It does not admit a 200-case claim.
