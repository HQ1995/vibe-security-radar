# fp-pipeline-precommit-scope audit

Disposition: HOLD
Branch: dev
HEAD: 1287ccdef27085a9f58f20ec1c835fecdea119fa ("Gate publication on causal audit")
main: a4fe1765147a9756c2d19f72f10f6a1ea400e4f2
Pushed: no
Staged: 0

## Conclusion

The false-positive (fp211) pipeline absorption work is already fully committed at HEAD and
un-pushed. The dirty worktree contains ZERO files owned by this work. There is nothing left
to stage or commit for it, and the "necessary English durable reports" ownership boundary is
ambiguous. Marked HOLD.

## Ground truth

- Current branch is `dev`, not `main`.
- HEAD is 1287ccdef27085a9f58f20ec1c835fecdea119fa (Gate publication on causal audit, 2026-08-13 13:28:31 -0400), the absorption commit.
- The fp211 workstream is commits 339c015 .. 1287ccd, all on `dev`.
- `main` HEAD is a4fe1765147a9756c2d19f72f10f6a1ea400e4f2 (unrelated docs change). No fp211 commit is on `main`.
- HEAD is not present on any remote branch (`git branch -r --contains HEAD` is empty) and
  there is no `origin/dev` tracking ref, so the work has not been pushed.
- Nothing is staged.

## Owned file scope (41 files, all committed and clean)

- Category A, new fp211 canonical snapshot: 7 files.
- Category B, publication admission helper + tests: 2 files.
- Category C, effective publication corpus builder + generated corpus + loader/generator/
  evaluator/tests: 11 files.
- Gate script (fp211-audit verify.py, modified in absorption commit): 1 file.
- Category D, English durable reports (fp211-audit markdown): 20 files.

Full explicit list in explicit_paths.txt. Every owned file is clean: no uncommitted diff,
no untracked twin, no staging. Only __pycache__ directories inside the fp211 dirs are
untracked; excluded per instructions.

## Scan of owned files

- Chinese / non-ASCII prose: PASS. Zero CJK ideographs, zero kana. The only non-ASCII is
  typographic punctuation (right-arrow, em-dash, en-dash) in ledger.jsonl, loader.py, and the
  markdown reports. Content is English-only.
- Secrets / credential-like material: PASS. No AWS keys, private-key PEM blocks, GitHub
  tokens/PATs, generic api_key/access_token/secret/password assignments, Bearer tokens, Slack
  webhooks, OpenAI sk- keys, or Google AIza keys.
- Whitespace: PASS. Zero trailing-whitespace lines.
- branch=dev: PASS. Working branch is `dev`; no owned file hardcodes a branch/refs/heads dev
  reference.
- Generated instability: MINOR. Two notes:
  1. source_manifest.json carries `captured_at: 2026-08-13T07:29:00-04:00`, non-deterministic
     on rebuild (snapshot field).
  2. reports/shard-03.md embeds absolute path
     `/home/hanqing/.cache/cve-analyzer/repos/misp_misp` (machine-specific, in a durable report).
  40-hex git SHAs and test-fixture ISO timestamps are stable identifiers, not instability.

## Why HOLD

1. No dirty-worktree file is owned by this work. The entire fp211 workstream is already
   committed at HEAD on `dev` and un-pushed, so a precommit scope has an empty dirty footprint.
2. "Necessary English durable reports" is ambiguous: the 20 reports live inside
   autoresearch/orchestrator-260813-fp211-audit/ (committed in the precursor commits), not in
   docs/. No docs/ durable report was produced for fp211. Whether the full 61-file precursor
   audit directory (shards, crossreviews, adjudications, experience.json, final_mechanisms.jsonl,
   public_cases.jsonl, etc.) is owned by this absorption work versus a separate prior
   "211 false-positive audit" workstream is unresolved.

## Remaining untracked inventory (categories, not full paths)

Untracked (415 total): scripts/cohort_*.py=163, scripts/tests/test_cohort_*=141, autoresearch/herdr-260813-ghsa200-*=30, docs/ durable research reports=30, autoresearch/herdr-260812-* (prior-day audits)=23, autoresearch/orchestrator-2608xx-* runs=10, scripts/cohort/*=9, scripts/*.py=3, other=2, scripts/tests/ other=2, root tmp files=1, scripts/audit_recovery_results/=1
Modified/deleted (51 total): web/data/cves/*.json=37, scripts/cohort_*.py=7, scripts/*.json manifests=3, web/data/ index/stats=2, scripts/cohort/*=1, scripts/tests/test_cohort_*=1
