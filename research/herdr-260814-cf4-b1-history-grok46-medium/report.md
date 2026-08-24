# CF4 B1 history-lane packet (proposal only)

Verdict: **0 PASS_PROPOSAL / 12 REJECT / TERMINAL**. Canonical88 stays 88. Countable pass 0. Greater-than-200 remains unsupported. Worker PASS is proposal only. Publication stays HOLD.

## Bound

Eligible remaining bucket-1 after structured exclusions and canonical88: **56903**.

Rank: github-reviewed first, then exact repo advisory or fix commit, then published 2025-2026, then local clone plus real fix objects, then GHSA ID.

Inspect cap 600. Stop rule: stop earlier after 12 atomic AI-history hits. Inspected prefix **163**. Stop reason: stop_after_12_atomic_hits. Shortfall **0**. Did not pad. Did not scan the rest of the eligible set. Did not re-review the completed CF4-b1-blame 12.

Atomic hit means production `source_matcher` on a non-closer commit in the 150 first-parent window (or squash/PR member, or exact GIT introduced event) that added hunks on official-fix source files. That is a freeze signal, not seven-gate PASS.

## Sources

github-reviewed subtree: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`.

unreviewed subtree only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`.

Union by uppercase GHSA ID; reviewed f2c6 wins on collision (135 collisions). Unreviewed identities were eligible and ranked after reviewed rows; none entered the inspected prefix of 163.

## Conservation

Exclusion parse of structured `case_id`, `ghsa_id`, `reviewed_case_ids`, `assigned_ids`, `strict_released_case_ids` across prior herdr/orchestrator terminal artifacts plus canonical88. Free-text mentions were not excluded. CF4-b1-blame 12 are inside that exclusion set and were not re-reviewed.

Assigned 12 = reviewed 12 + unreviewed 0. PASS_PROPOSAL 0.

## REJECT (all 12)

Identity holds as github-reviewed GHSA cases. Uniqueness holds. AI hunk, topology, and scoped but-for fail: history matcher hits are same-file ancestors, style/lint, other endpoints, AI-on-fix follow-up, or a listed introducer SHA. Prefer zero PASS.

1. GHSA-46R5-X6JQ-V8G6 mlflow AJAX logged-model auth. Closer 005b959c is Claude-coauthored (AI-on-fix). History hits are other auth routes.
2. GHSA-6465-JGVQ-JHGP sentry-javascript header leak. Listed a820fa289 is the 10.11.0 introducer feat, not a closer. Cursor ANR deprecation is unrelated.
3. GHSA-64RR-PP78-62WW nukeviet Request XSS. Copilot PHP 8.5 HttpException refactor. Closer is VINADES. No local tag contains the closer.
4. GHSA-6XPM-GGF7-WC3P mcp-remote command injection. Claude OAuth/prettier and Jules debugLog on utils.ts. Closer 607b226a human encodeURIComponent. Tag v0.1.16.
5. GHSA-8C7Q-86FQ-VVMH mlflow MPU auth. Copilot scoring TypeError in the same auth file. Closer d7290811 human. Tag v3.11.0rc1.
6. GHSA-8M59-7XV8-735H marimo file_key XSS. Copilot docstring style. Closer fdd55c8c human. 0.23.8 lacks closer; 0.23.9 contains it.
7. GHSA-C67J-W6G6-Q2CM langchain dumps/loads injection. Copilot ancestors are prompts/messages/log_stream/lock. Closer 5ec0fa69 human.
8. GHSA-CWFJ-642J-GFH4 mattermost search read permission. Aider Flag post API on post.go. Closer 0481bd1f human. Tag v11.4.0.
9. GHSA-FMQF-PMCM-8CX9 mattermost Jira comment membership. Claude playbooks Makefile bump. Closer b57c297c human. Tag v11.3.0.
10. GHSA-GQ3W-7JJ3-X7GR mlflow file_store traversal. Claude walrus lint. Closer 5bf2ec2b human. Tag v3.8.0rc0.
11. GHSA-GRP3-H8M8-45P7 glances Cassandra CQL. Claude 1563ff8e is a child of closer d339181f (sys.exit to logger.error). AI-on-fix. Tag v4.5.4.
12. GHSA-JH6H-V6MP-H22V milvus RBAC MD5 truncation. Claude SuffixSnapshot removal. Closer 3d932f1c human. No product tag contains the closer.

OSV introduced values, shared SHA, AI-on-fix, same repository, same file, new caller of an old bug, refactor preservation, and incomplete hardening are routing, never proof.

## Claim boundary

Canonical strict released first-party GHSA floor remains 88 HOLD. This packet emits no admission. No commit, push, or edits outside this directory. Local caches read-only. Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
