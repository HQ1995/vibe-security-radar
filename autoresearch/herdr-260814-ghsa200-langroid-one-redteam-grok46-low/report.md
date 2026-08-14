# GHSA-PMCH-G965-GRMR red-team — KEEP proposal (HOLD)

Independent hostile review of exactly one batch11 PASS row. Source worker verdicts and prose were not trusted. KEEP is a proposal, never leader admission. Publication stays HOLD. Canonical73 is not rebuilt. Greater-than-200 stays unsupported.

Reviewed: 1. Unreviewed: 0. KEEP proposal: 1. NARROW: 0. REJECT: 0.

## Verdict

**KEEP** `AI_INCOMPLETE_REMEDIATION` for `GHSA-PMCH-G965-GRMR` (alias `CVE-2026-50180`). All seven contract gates plus `remediation_patch_delta_gate` are PASS at this scope. Countable remains false until the leader admits the row.

## Hostile attacks and results

1. **Pre-AI COPY PROGRAM versus GHSA-named residual.** `GHSA-MXFR-6HCW-J9RQ` / `CVE-2026-25879` is reviewed, not withdrawn, PyPI `langroid < 0.63.0`, first patched `0.63.0`. It names unrestricted `SQLChatAgent.run_query` and `COPY ... FROM PROGRAM`. Parent `763d5cba` (`60933b48^`) has no `_DANGEROUS_SQL_PATTERNS` and no `_validate_query`; tag `0.62.0` sql blob `e8d817ae` equals that parent file. `GHSA-PMCH-G965-GRMR` is a different reviewed identity: PyPI `langroid <= 0.63.0`, first patched `0.64.0`, summary names `_validate_query` missing the `pg_read_file` family. Cross-binding the two GHSAs fails identity.

2. **Is `60933b48` an explicit security attempt on the same query-validation boundary?** Yes. It is single-parent. Subject: `Add SQL query validation to mitigate CVE-2026-25879 (#1025)`. Body: `Co-authored-by: Claude <noreply@anthropic.com>`. First-parent introduces the denylist and `_validate_query`. That is a guard/denylist rewrite on the GHSA-named boundary, not a later review of a human patch.

3. **Residual in released 0.63.0.** Independent eval of the 17 AI patterns: `COPY ... PROGRAM` and `pg_read_server_file` BLOCK; `SELECT pg_read_file(...)`, `pg_stat_file`, `pg_ls_logdir`, `pg_ls_waldir`, `pg_current_logfile` ALLOW. Tag `0.63.0` peels to `fee670d5`. That commit is version text only (`pyproject.toml`), parent `60933b48`. sql blob at the tag equals the AI blob `887a10a4`. PyPI wheel and sdist `sql_chat_agent.py` hash to the same git blob. GitHub Release `0.63.0` asset digest matches the PyPI wheel (`8a91de0e...`). Fix `00b7dd7b` is not an ancestor of `0.63.0`.

4. **Closer amends the AI denylist, not a sibling.** `00b7dd7b` is single-parent of `56e2756e`. First-parent diff touches only `sql_chat_agent.py` and `test_sql_chat_security.py`. It deletes the three per-name regexes blamed to `60933b48` at `0.63.0` and inserts family-prefix `pg_(read|stat|ls|current_logfile)`. Blame of that regex at tag `0.64.0` is `00b7dd7b`. `56e2756e` is file-tool path traversal (`GHSA-FG23`); it does not change the sql blob.

5. **Release commits are version text.** Rejecting on that fact alone would be wrong: containment is the peeled tag tree plus PyPI/GitHub artifacts, not the bump diff. `84d2aff0` (`0.64.0`) is also version text only, parent `00b7dd7b`, sql blob `a55f6d34` equal to the closer and to the 0.64.0 wheel/sdist.

6. **Identity not cross-bound.** Global GHSA type `reviewed`, `withdrawn_at` null, `source_code_location` `langroid/langroid`, package `langroid` on pip/PyPI. Repo advisory state `published`. Distinct from `GHSA-MXFR`, `GHSA-X34R` (pandas eval, already in canonical overlay as NARROW), and `GHSA-FG23`.

## Gates

| Gate | Result |
|---|---|
| identity_gate | PASS |
| ai_hunk_gate | PASS |
| topology_gate | PASS (single-parent candidate and closer; no authorship transfer; AI ancestor of closer and of 0.63.0) |
| but_for_gate | PASS under patch-delta (incomplete remediation) |
| fix_reversal_gate | PASS |
| release_gate | PASS (artifact blobs, not bump text) |
| uniqueness_gate | PASS (not in canonical73 / fp211 public / publication ledger) |
| remediation_patch_delta_gate | PASS |

## Hold

This packet does not admit the case. The leader must re-verify before any ledger rebuild.
