# Red-team: upgrade-a PASS ordinals 1, 20, 92, 93

**Status: `REDTEAM_COMPLETE`.** Worker PASS rows were hypotheses. Independent first-party GHSA fetch and Git replay. A KEEP here is still only a proposal.

| Ordinal | GHSA | Worker | Red-team |
|--------:|------|--------|----------|
| 1 | GHSA-FMFG-9G7C-3VQ7 | PASS | **KEEP** |
| 20 | GHSA-XW8C-RRVX-F7XQ | PASS | **NARROW** |
| 92 | GHSA-WV46-V6XC-2QHF | PASS | **KEEP** |
| 93 | GHSA-RG8M-3943-VM6Q | PASS | **KEEP** |

Clones: `/tmp/ghsa200-worker-clones/red-upgrade-a/clones/{ha-mcp,ciguard,openclaw}`. Advisory JSON: `/tmp/ghsa200-worker-clones/red-upgrade-a/pages/`. Openclaw worktree checkout failed on `/tmp` disk; objects and `git show`/`blame` were sufficient.

## Ordinal 1 — KEEP (proposal)

First-party repo advisory GHSA-fmfg-9g7c-3vq7 / CVE-2026-32111 names `homeassistant-ai/ha-mcp`, pip `ha-mcp` `<=6.7.2` patched `7.0.0`, not withdrawn. The write-up’s first path is the consent-form `ha_url` GET `{ha_url}/api/config` error oracle.

Squash `39806871` (2026-01-17) has Claude Code / `Co-Authored-By: Claude` footers. Parent `f3f5d6c9` has no `provider.py`. `v6.7.2` blame of `_validate_ha_credentials` / `GET {ha_url}/api/config` is still `39806871`. Fix `dc8eaa16` removes user-supplied `ha_url` and the validator; `v7.0.0` contains that fix and not the form field.

Counterexamples tested: member `aae7acba` is not a `v6.7.2` ancestor; member/carrier/tag `provider.py` blobs all differ. Five later commits edit the file; they do not re-author the blamed sink. Official text also names REST/WebSocket paths; `1399f5a` (Claude) later made tokens unsigned base64 JSON. Those paths are outside the consent-form scope. KEEP is for that scope only.

## Ordinal 20 — NARROW

First-party GHSA-xw8c-rrvx-f7xq / CVE-2026-44219 names both `endoflife.py` and `osv.py` unbounded `resp.read()`, range `>=0.6.0, <=0.8.1`, patched `0.8.2`.

`d42195e1` is Claude Opus 4.7 and adds `endoflife.py` with unbounded `resp.read()`. Parent lacks the file. `v0.6.0` contains that commit and not `osv.py`. `f08e6549` is also Claude Opus 4.7 and adds the same primitive in `osv.py`. `v0.8.1` (last named vulnerable tag) contains both files unbounded. Fix `17a119fe` caps both, and also patches symlink discovery, Dockerfile user, and security headers.

The worker closed release_gate by dropping `osv.py` so the first tag would contain the whole origin set. That is not official-mechanism identity. File-level endoflife origin remains real; GHSA-level DIRECT_ROOT KEEP is refused. `identity_gate`, `release_gate`, and `uniqueness_gate` stay NARROW.

## Ordinal 92 — KEEP (proposal)

First-party GHSA-wv46-v6xc-2qhf / CVE-2026-35670: Synology Chat reply rebound through username resolution; npm `openclaw` `< 2026.3.22` patched `>= 2026.3.22`. Named fix `7ade3553`.

Parent webhook handler sends to `payload.user_id` only. Squash `9a3800d8` adds `resolveChatUserId` nickname-then-username matching and has `Co-Authored-By: Claude Opus 4.6`. `v2026.3.2` `client.ts` blob equals the squash blob; blame of the matcher is `9a3800d8`. Fix `7ade3553` returns `payload.user_id` unless `dangerouslyAllowNameMatching`. `v2026.3.22` contains the fix.

Counterexamples: member `ce12b909` is not a tag ancestor; its `client.ts` blob differs. Squash text mentions a Windows-test follow-up and a harden credit; those do not rewrite the blamed matcher. `630f1479` is release-prep, not a second reversal. Distinct from GHSA-rg8m.

## Ordinal 93 — KEEP (proposal)

First-party GHSA-rg8m-3943-vm6q / CVE-2026-41376 (CVE on the global object; repo advisory omits CVE): Matrix thread-root and reply context bypass sender allowlist; `<=2026.3.28` patched `>= 2026.3.31`. Named fix `8a563d60`.

Squash `49c60e90` has `Co-authored-by: Claude Opus 4.5`. Parent has thread-root IDs but no `ThreadStarterBody` / `fetchEventSummary`. `v2026.2.12` blame of `ThreadStarterBody` is `49c60e90`. Fix `8a563d60` drops thread-root (and reply) context when the sender fails the allowlist. `v2026.3.31` contains the fix.

Counterexamples: member `fbfe2f15` is not a `v2026.2.12` ancestor; member/squash/tag `handler.ts` blobs differ. Later `53273b49` (sender spoofing) causes the tag/squash blob mismatch and does not author `ThreadStarterBody`. `reply-context.ts` is absent from the squash and from `v2026.2.12`; it is a later surface also touched by the fix and is out of this row’s scope.

## Sources

| Repo | HEAD | Date |
|------|------|------|
| ha-mcp | `851c1866a93aa88dbb708938da171d74d2ed965b` | 2026-08-12T19:39:51-04:00 |
| ciguard | `1b6eeb790b94de44e7d9e19a672658c23a4d17df` | 2026-05-15T22:59:25+01:00 |
| openclaw | `faa62024123c2a7abbc61de44613c4b11ba61a5d` | 2026-08-13T13:17:36-07:00 |

Hypothesis input: `herdr-260813-ghsa200-upgrade-a/cases.jsonl` SHA-256 `7bebb1a6eebe7ea01339abaec72e26f93233659dc90f2b850a443d0a7d0d652b`. Page SHA-256 values are in `result.json`.
