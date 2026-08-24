# Near-closed released wave I

TERMINAL. Assigned 3 first-party identities on fp211 ordinals 55, 60, and 70. Reviewed 3, PASS_PROPOSAL 0, NARROW 3, REJECT 0. Conservation 3=3+0. Canonical90 remains 90 HOLD. Packet delta 0. No causal or publication admission.

This packet independently reopened fp211 ordinals 55, 60, and 70. Inherited overlay is routing only. All seven contract gates were rebuilt from first-party advisories and Git/release artifacts. Scoped contributor is allowed only for an explicitly advisory-covered added surface. PASS requires every gate PASS for the counted scope. Worker PASS is proposal-only; this packet emits none.

## Per case

1. GHSA-C339-W3CQ-2RJR ordinal 55 NARROW but_for_gate. Published repo advisory names missing isInstanceAdmin() on Settings/Updates. Global GHSA is 404; the repo object is published and not withdrawn. Atomic Haiku acff543e (n_parents=1, parent 4a4d64ac) wraps Server::findOrFail(0) in if (! isCloud()). Parent Updates.php already lacked isInstanceAdmin. Merge carrier 009b4e7d has no AI trailer; authorship is not transferred. Member is an ancestor of the carrier and of v4.0.0-beta.461 peel 04e71916. Updates blob 01a67c38 is equal at member, carrier, and 461. Closer 0fed5532 adds isInstanceAdmin and is first contained in v4.0.0-beta.471 peel 914d7e0b. isCloud is not an advisory-named surface. Deleting the AI change leaves the named missing-admin hole.

2. GHSA-Q6QF-4P5J-R25G ordinal 60 NARROW but_for_gate. Reviewed GHSA-q6qf / CVE-2026-32002 names the sandboxed image tool missing tools.fs.workspaceOnly. Atomic Opus 8d74578c (n_parents=1, parent f7123ec3) deletes the primarySupportsImages===true return-null gate. Parent and candidate image-tool.ts both have zero workspaceOnly hits. v2026.2.22 peel a54dc7fe contains the candidate and still lacks workspaceOnly. Closer dd9d9c1c threads workspaceOnly and is an ancestor of v2026.2.23 peel b8176005. Shared SHA 8d74578c on ordinal 77 GHSA-W4H3 is a distinct native-media UNC mechanism. Vision reachability is not the named origin.

3. GHSA-Q5PP-GVJG-H7V4 ordinal 70 NARROW but_for_gate. Reviewed GHSA-q5pp / CVE-2026-45539 names Path.glob / Path.read_text in find_agent_files and copy_agent on .apm/agents sources. Copilot 810d87b2 (n_parents=1, parent d92a3d08) adds integrate_package_agents_claude. Parent already has the named finder/copy sinks and already dual-targets .claude/agents when .claude exists. Candidate find_agent_files and copy_agent equal the parent. GHSA PoC mkdir .claude, so the parent dual-target already covers the observed .claude/agents deploy. Member is an ancestor of merge 84abb22c and of v0.12.4 peel 6aceef72. Closer f85b9f54 routes the parent finder through find_files_by_glob and is contained in v0.13.0 peel 92165163. A new call site of a parent helper is not origin of the named symlink dereference.

## Uniqueness

None of the three IDs is in canonical90 strict_released_case_ids (90, including GHSA-8RW6-P7M8-63JP). CVE aliases are stored and not counted. Q6QF is not merged with GHSA-W4H3.

## Boundary

Worker PASS is proposal-only. This packet proposes none. Canonical90 was not rebuilt. No live autoresearch scan, canonical edit, commit, or push. Expansion stopped. Did not pad.
