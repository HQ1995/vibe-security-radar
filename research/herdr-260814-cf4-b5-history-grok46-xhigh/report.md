# CF4 b5 history lane

Verdict first: **0 PASS_PROPOSAL**. Frozen **7** actual AI-history hits. Shortfall **5**. Inspected prefix **600**. Stop rule **max_inspect_600**. Did not pad. packet_delta **0**. Canonical strict count remains **88** HOLD. Worker PASS is proposal only; this packet emits none.

## Universe and bound

Authoritative github-reviewed subtree: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` path `advisories/github-reviewed`.

Unreviewed subtree only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226` path `advisories/unreviewed`.

Union by uppercase GHSA ID; reviewed f2c6 wins on collision (30 collisions). Unreviewed rows were not dropped. Bucket is integer sha256 of uppercase GHSA ID modulo 6 equals 5. Remaining after structured exclusions and withdrawn: **57199** (4214 reviewed, 52985 unreviewed).

Rank remaining rows by reviewed first, exact repo advisory or fix commit, published 2025-2026 first, local clone plus real fix object, then GHSA ID. Inspect at most the top 600. Prefix first ID `GHSA-227R-W5J2-6243`, last ID `GHSA-3434-HC3M-8MMM`. Prefix git objects 334. Stop after 12 actual atomic AI-history hits or 600 inspected. Reached 7 hits and stopped at 600. Shortfall 5. Never padded.

Method: for each inspected row with a real first-party fix object, walk fix-touched file history backward up to 200 first-parent commits and peel PR members where local. Admit only production source_matcher atomic AI commits that introduced a fixed dependency, config, integration, endpoint, parser, auth seam, unsafe default, or incomplete remediation. Ancestry-only scoring was not used. New caller, unrelated ancestor, AI-on-fix, shared SHA, blob equality, metadata-only dependency, and incomplete hardening that only reduced old risk fail.

Equation **7=7+0**. Prefer 0 PASS.

## Per identity

1. GHSA-49G7-2WW7-3VF5 glances. REJECT. Claude MCP extra overlaps pyproject.toml. DuckDB CREATE TABLE {plugin} is already on the merge parent. Human member f3e94930 quotes identifiers. v4.5.1 vs v4.5.2.

2. GHSA-69J8-PRX2-VX98 mattermost. REJECT. Claude errcheck overlaps oauth_test.go. Parent oauth.go already has unvalidated redirect_to. Closer 13cd76009d31 is unmarked. v10.9.4 vs v10.9.5.

3. GHSA-6MW6-MJ76-GRWC gitoxide. REJECT. Copilot zip swap is Cargo.lock plus gix-archive. Copilot f9051e775cf8 is the TimeBuf UTF-8 closer member (AI-on-fix). Listed SHA 76376ef5e97c is a human merge. gix-date-v0.11.1 vs gix-date-v0.12.0.

4. GHSA-9JPJ-CPH8-W449 langflow. REJECT. Claude release merge overlaps Docker/pyproject, not projects.py. Parent already calls encrypt_auth_settings. Listed closer is a human SDK megapatch. Tag names 1.9.0 vs v1.9.0 disagree; release stays UNKNOWN.

5. GHSA-PGQP-8H46-6X4J mlflow. REJECT. Copilot RUF051 is pyproject lint. Closer b0ffd289e9b0 adds fastapi_security.py and is unmarked. v3.4.0 vs v3.5.0.

6. GHSA-WM96-9GFH-VVGQ hermes-agent. REJECT. Cursor nix shared-state overlaps config.py, not execute_code. Closer 285bb2b9150b is unmarked. No tags contain the closer.

7. GHSA-WVCV-9XPM-7MQC mattermost. REJECT. Copilot plugin toast API overlaps plugin_api.go. Closer f5fe8ded6b63 hardens command.go trigger uniqueness and is unmarked. Not an ancestor of v11.5.2. Shared repository with 69J8 is routing.

## Claim boundary

No worker PASS. Leader admission is unchanged. Publication and more-than-200 stay HOLD. This packet does not edit canonical88, web, or scripts. No durable pages, clones, packages, notes, or helper scripts remain in the owned directory. Temporary clones and pages were not retained.
