# GHSA-8CCJ canonical auth-bypass evidence

Status: one unapplied full-row ledger update for
`alias-8eff3fc4b483b48c2ceb498e`. This lane did not apply the patch, export the
ledger, run the publisher, edit generated site data, or commit.

## Primary evidence and causal topology

- The GitHub-reviewed advisory record
  `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/06/GHSA-8ccj-p46r-jwqq/GHSA-8ccj-p46r-jwqq.json`
  identifies `GHSA-8CCJ-P46R-JWQQ` / `CVE-2026-57132`, the
  `PRAISONAI_CALL_AUTH=disabled` early return in
  `src/praisonai/praisonai/api/agent_invoke.py`, and unauthenticated agent
  invocation as the disclosed mechanism. It is not the unrelated Sandlock
  fallback finding previously named by the row's wave-04 gate source.
- Local Git pickaxe over
  `.ai-slop/state/repos/mervinpraison_praisonai` finds
  `179cab02dbec0c1e9b601507a65908e079876004` as the first commit to add both
  `PRAISONAI_CALL_AUTH` and `_CALL_AUTH_DISABLED`. Its parent
  `402d7ed9fc5926babaa70c97a6ee5353e3d0dd62` has neither string. The commit
  adds the process-wide flag and returns from `verify_token` before bearer,
  basic, query-token, or equality checks.
- The introducing commit message contains the exact AI marker
  `Co-authored-by: Cursor <cursoragent@cursor.com>`. Its tree is carried onto
  the default branch by merge commit
  `b0d8f777528f3253a0cfb0a3ef65455da6ae32f6` (PR #1684); the candidate and
  carrier have the same `agent_invoke.py` blob
  `dac034426cc5a28ebebc23042dbaefb8029c9eab`.
- Candidate `179cab02d` is an ancestor of final fix
  `51fe7f9cbb66b2608aead948ddecacfdd1a94d8e`. The fix removes the implicit
  localhost default, rejects disabled mode when bind metadata is absent or
  non-loopback, and records the actual bind host in both call-server startup
  paths. Its parent still defaults a missing `PRAISONAI_CALL_BIND_HOST` to
  `127.0.0.1` and neither startup path records the host.

Canonical edge:

`179cab02d` (PR member) -> `b0d8f7775` (merge carrier) -> `51fe7f9cb` (final fix)

## Release boundary

- Merge carrier `b0d8f7775` first appears in tag `v4.6.40`.
- `51fe7f9cb` is absent from `v4.6.79` and contained in `v4.6.80`; those are
  therefore the repository-proven last vulnerable and first final-fix tags
  stored by this patch.
- The reviewed advisory instead records `< 4.6.61` / fixed `4.6.61`, but the
  clone has no `v4.6.61` tag. Release commit `2a855c470` in `v4.6.62` added an
  earlier localhost restriction, while the final fix did not ship until
  `v4.6.80`. Because the advisory range and repository's final-closure tags do
  not line up, the independently established `release=NARROW` gate is retained.

## Stored exact hunks

Every code block in the JSONL is one complete hunk from `git diff
--no-ext-diff --unified=3 <parent> <commit>`; no object joins discontiguous
headers.

| Role | File | Header | Old/new lines |
|---|---|---|---:|
| candidate | `src/praisonai/praisonai/api/agent_invoke.py` | `@@ -29,14 +29,26 @@` | 14 / 26 |
| fix | `src/praisonai/praisonai/api/agent_invoke.py` | `@@ -38,9 +38,9 @@` | 9 / 9 |
| fix | `src/praisonai/praisonai/api/agent_invoke.py` | `@@ -52,10 +52,13 @@` | 10 / 13 |
| fix | `src/praisonai/praisonai/api/call.py` | `@@ -372,7 +372,9 @@` | 7 / 9 |
| fix | `src/praisonai/praisonai/cli/features/serve.py` | `@@ -894,7 +894,10 @@` | 7 / 10 |

- Candidate selected-hunk SHA-256:
  `b8ec1774dace48e3caa2c71340e0e7bf3535d754d15bcd9f1dfa8966adb3fd7f`.
- Fix selected-hunk SHA-256:
  `5533252079394df33b2420d6395a27e779ff4c0a4b7eefcbf7f5313be37e56af`.
- Each displayed hunk has distinct reader-facing prose, all required anchors
  occur in the corresponding role, and `comparison_hunks` is empty.

## Ledger and validation boundary

- Fresh live basis: revision `3`, change set
  `df53d33c-4109-44a2-9e6e-b607c99658b9`, row checksum
  `73ecdda9bbfdd5df88d86520326349a6576ca04d4b8251a5cd412b7d6961ddab`.
- The patch preserves unrelated live fields, corrects the related partial-wave
  release wording, retains all seven independently verified gate values, and
  replaces only the semantically wrong `gates_source` with this evidence file.
- The companion JSONL is exactly one full-row update with
  `expected_revision=3` and `assessment_ids=[]`.
- Before apply, the final artifact was checked with `json.loads`,
  `scripts.ledger_store.read_patches(require_assessments=False)`, and
  `scripts.ledger_store.validate_update(live, proposed)`; hunk counts, blob
  slices, hashes, topology, anchors, and patch-file witnesses were recomputed
  from local Git.
