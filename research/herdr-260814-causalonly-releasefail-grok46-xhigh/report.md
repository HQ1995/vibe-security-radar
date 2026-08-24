# Causal-only review despite release FAIL

TERMINAL. Assigned 3, reviewed 3, CAUSAL_ONLY_PASS 1, REJECT 2. Conservation 3=3+0. Canonical88 remains 88 HOLD. Packet delta 0. Release stays FAIL on every row. No seven-gate countable PASS. No canonical edit.

This packet independently hostile-reviewed GHSA-HR7P-WG7R-HG9M, GHSA-98HH-7GHG-X6RQ, and GHSA-C65F-X25W-62JV from first-party advisory objects and local git history. Prior census and worker gates were routing hypotheses only. CAUSAL_ONLY_PASS required exact PASS on identity, AI hunk, topology, scoped but-for, complete fix reversal, and uniqueness. Release mapping was recorded and never upgraded.

## Per case

1. GHSA-HR7P-WG7R-HG9M REJECT. First-party GHSA-hr7p-wg7r-hg9m for flytohub/flyto-core names `${env.VAR}` interpolation in `variable_resolver.py` as the secret-read. Parent 21d5f5d092 already returns `os.getenv(env_var)` for `var_type == 'env'`. Claude-marked 68af171d adds `module_policy.py` denylist `env.get` and does not touch the resolver. That is old interpolation plus a new incomplete denylist, not AI authorship of the causal hunk. Incomplete-remediation patch-delta is real (d5f89d7130 adds `is_env_var_allowed` and wires the resolver) but the residual is the untouched parent hole. Tags: v2.26.4 peeled 50d0d327 lacks both SHAs; v2.26.6 peeled 2471c6e7 already contains both.

2. GHSA-98HH-7GHG-X6RQ CAUSAL_ONLY_PASS. First-party GHSA-98hh-7ghg-x6rq for openclaw/openclaw names Discord text `/approve` bypassing `channels.discord.execApprovals.approvers`. Claude Opus 4.5 atomic 483fba41 adds `commands-approve.ts`; parent fe7436a1 lacks that file. The new handler resolves exec approvals after `isAuthorizedSender` only. The same commit forwards DM buttons to `config.approvers`; that is a new sibling notify path, not a parent old bug. Closer 355abe5eba adds `isDiscordExecApprovalApprover` on the text handler. GHSA-mqpw-46fh-299h shares the `/approve` file for a gateway `operator.write` scope hole with a different fix SHA; shared file is not uniqueness. Local clone has zero tags containing either SHA, so release stays FAIL.

3. GHSA-C65F-X25W-62JV REJECT. First-party GHSA-c65f-x25w-62jv names PyPI openssl-encrypt and standalone `server/key-server` plus `server/telemetry-server` CORS `['*']` with `allow_credentials=True`. Claude Sonnet 4.5 first-adds those config defaults in 4c7ae852 then fafdfeed. Git hunk identity is real and the closer 809416b7 flips those defaults to `[]`. `setup.py` `find_packages()` ships `openssl_encrypt` and `openssl_encrypt_server`; `server/__init__.py` is absent. At the closer, unified `openssl_encrypt_server/config.py` already defaults CORS empty. The named public identity does not contain the AI servers. Cross-bound identity fails. Ranked SHA 57e618d32e is a different GHSA. Closer is also Claude-marked and is not origin. Zero local tags. Release stays FAIL.

## Uniqueness

None of the three are in canonical88 strict_released_case_ids (88, including GHSA-8RW6-P7M8-63JP). OpenClaw GHSA-mqpw-46fh-299h is a different `/approve` mechanism. Shared SHA is not a duplicate.

## Boundary

Prefer no PASS over weak evidence. Worker CAUSAL_ONLY_PASS is proposal-only and is not publication. This packet did not edit canonical ledgers, did not commit or push, and did not store durable pages, clones, packages, or caches.
