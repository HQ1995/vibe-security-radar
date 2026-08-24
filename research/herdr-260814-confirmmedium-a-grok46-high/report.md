# Hostile audit: fp211 CONFIRM/MEDIUM ordinals 114, 128, 139

Verdict-first: **0 PASS_PROPOSAL**. GHSA-P52P-4VMG-4VQ3 **NARROW**, GHSA-4MR5-G6F9-CFRH **NARROW**, GHSA-94P4-4CQ8-9G67 **REJECT**. Conservation **3=3+0**. Canonical91 strict count remains **91**. Publication **HOLD**. Worker PASS is proposal-only; this packet emits none.

fp211 CONFIRM/MEDIUM, upgrade-b, and incomplete-rem-redteam are routing only. They are not evidence. Canonical91 is exclusion/authority. CVE aliases are not counting units. `na_fails`. Prefer no PASS over a weak confirmation.

| Order | ID | Ordinal | Repo | Terminal | Failed gates |
|---|---|---:|---|---|---|
| 1 | GHSA-P52P-4VMG-4VQ3 | 114 | nesquena/hermes-webui | NARROW | identity |
| 2 | GHSA-4MR5-G6F9-CFRH | 128 | MervinPraison/PraisonAI | NARROW | topology, but-for |
| 3 | GHSA-94P4-4CQ8-9G67 | 139 | gitpython-developers/GitPython | REJECT | but-for (untouched sibling) |

## GHSA-P52P-4VMG-4VQ3

Identity NARROW: local advisory is unreviewed (`github_reviewed=false`, `affected=[]`). Details name ungated POST `/api/settings` `_set_password`. References point at nesquena/hermes-webui PR 3964/3973, commit `1126e541`, and tag `v0.51.358`. That commit is the closer merge, not the origin. No package range. Repo advisory is absent. CVE-2026-49973 is an alias.

AI hunk PASS: atomic Claude Opus 4.6 member `b8b62722` adds `save_settings` `_set_password` persist. Parent `1c6db07c` has none.

Topology PASS on the rebuilt sets, not on the inherited carrier. Member parent_count=1 and is an any-parent ancestor of `v0.51.357`. Merge `51bcf8fe` (#34) is the first-parent pickaxe hit. Inherited carrier `1126e541` is a two-parent merge of closer `f2ef2851` onto `v0.51.357` and is the peel of `v0.51.358`. That is a fix merge, not an origin squash. `carrier_set` is empty. Authorship is not transferred.

But-for PASS at the `_set_password` persist: removing `b8b62722` removes the first-user password write. Later PBKDF2 rewriting of the hash does not restore a parent that lacked the field.

Fix-reversal PASS: `f2ef2851` (parent equals `v0.51.357` peel `5dceb299`) adds `if requested_password and not auth_enabled_before` plus `_onboarding_gate_allows`. `v0.51.357` routes.py blob `f7833569` lacks that gate. Closer/v0.51.358 blob `6b6ddcbb` has it. config.py blob `a12c3ef1` is unchanged across 357/fix/358.

Release PASS at the git tag pair: `v0.51.357` contains the member and not the closer. `v0.51.358` contains the closer merge.

Uniqueness PASS: absent from canonical91 strict 91.

Not countable: identity remains unreviewed with empty `affected`.

## GHSA-4MR5-G6F9-CFRH

Identity PASS: github-reviewed first-party GHSA for MervinPraison/PraisonAI / PyPI `praisonaiagents` and `PraisonAI`. Mechanism is `execute_code` `print.__self__` sandbox escape. Aliases CVE-2026-47392.

AI hunk PASS: atomic `claude[bot]` `3cd664bf` replaces full `__builtins__` with `safe_builtins` including real `print`. Parent `25de69d3` uses unrestricted `__builtins__`. The same commit also adds `spider_tools` SSRF checks.

Topology NARROW: `python_tools.py` blobs are four-way unequal. Parent `0c07d1fa`, candidate `fcaf2927`, `v4.6.39` `c4ba5d97`, closer/`v4.6.40` `83c5d833`. The released residual is not the AI blob. `v4.6.39` already contains a later AST `_blocked_attrs` denylist.

But-for NARROW: parent already admitted C-builtin `__self__` leakage via full `__builtins__`. GHSA Gap 1 names the later `_blocked_attrs` set, which the AI commit does not introduce. Closer `179cab02` (parent equals `v4.6.39` peel `402d7ed9`) adds `'__self__'` to that later AST layer and comments GHSA-4mr5. Patch-delta requires the later fix to amend the AI-added `safe_builtins` boundary. It does not. Reverting `3cd664bf` restores unrestricted exec, broader than the named residual. Rollback reopening the parent hole is not by itself a failure for incomplete rem, but an untouched later denylist plus an old hole is not residual but-for of the AI delta.

Fix-reversal PASS at commit scope: `179cab02` inserts `'__self__'` into `_SANDBOX_BLOCKED_ATTRS`.

Release PASS: git `v4.6.39` / PyPI `praisonaiagents 1.6.39` lack the closer; `v4.6.40` / `1.6.40` contain it. Advisory ranges match.

Uniqueness PASS: distinct from counted canonical91 GHSA-5C6W-WWFQ-7QQM (same SHAs, `spider_tools` SSRF) and GHSA-PV2J-RGHR-V5R9 (closer SHA used later as a `str.format` origin). Shared SHA is not duplication.

Not countable: released residual is a later AST rewrite of an old exec hole, not the exact AI sandbox delta.

## GHSA-94P4-4CQ8-9G67

Identity PASS: github-reviewed first-party GHSA for gitpython-developers/GitPython / PyPI GitPython. Summary is environment-variable exfiltration via `Repo.create_remote()` / `Remote.add()`, named as an incomplete fix of GHSA-rwj8-pgh3-r573.

AI hunk PASS: atomic GPT 5.6 `8ac5a305` sets clone `expand_vars=False`. Files are `git/cmd.py`, `git/repo/base.py`, `git/util.py`, `test/test_clone.py`. Trailer names GHSA-rwj8.

Topology PASS: parent_count=1. Candidate is an ancestor of `3.1.52`-`3.1.55` and of closer `86341745`. `git/remote.py` blob `0c3dbfe1` is identical on parent, candidate, `3.1.52`, `3.1.53`, and `3.1.54`. Closer/`3.1.55` blob `e2d5cbc1` differs. Closer parent equals `3.1.54` peel `e59d9bab`.

But-for FAIL: the AI clone commit does not edit `Remote.create`. The sibling already expanded URLs on the parent. Closer `86341745` sets `expand_vars=False` on `Remote.create` and `Submodule.add` and does not amend the clone path. Contract: a fix to surface A followed by a fix to pre-existing surface B is not incomplete-remediation causality. The residual is an untouched sibling path. Reverting `8ac5a305` re-opens clone expansion (GHSA-rwj8) and leaves the named Remote residual in place.

Fix-reversal PASS for the named Remote residual only: `86341745` writes `Git.polish_url(url, expand_vars=False)` in `git/remote.py`. That does not rescue AI but-for.

Release PASS: git/PyPI `3.1.54` contains the candidate and not the closer; `3.1.55` contains the closer. Advisory `last_known_affected <= 3.1.53` understates git: `3.1.54` is still residual.

Uniqueness PASS: distinct from GHSA-rwj8 (clone, not in canonical91) and from counted GitPython rows GHSA-R9MR, GHSA-3RP5, GHSA-539M, GHSA-3WXW. Absent from canonical91 strict 91.

REJECT: sibling completion of a pre-existing Remote hole is a false confirmation of AI incomplete-remediation causality.

## Claim boundary

No worker proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical91. Publication and more-than-200 stay HOLD.
