# Provisional closure commit scope

Snapshot: 2026-08-31, branch `dev`, HEAD `7455d5c61a4`. This is a
path-ownership report only. It does not authorize applying the draft ledger
patches, writing Neon, regenerating the site, or committing the worktree.

## Include in the provisional-closure commit

Stage the final, quiescent versions of these files together:

- `research/provisional-closure-20260831/shard-01.md`
- `research/provisional-closure-20260831/shard-02.md`
- `research/provisional-closure-20260831/shard-03.md`
- `research/provisional-closure-20260831/shard-04.md`
- `research/provisional-closure-20260831/shard-05.md`
- `research/provisional-closure-20260831/gate-source-reconciliation.md`
- `research/provisional-closure-20260831/duplicate-second-review.md`
- `research/provisional-closure-20260831/not-ai-second-review.md`
- `research/provisional-closure-20260831/cve45582-ledger-patch.jsonl`
- `research/provisional-closure-20260831/cve45582-ledger-patch-notes.md`
- `research/provisional-closure-20260831/duplicate-ledger-patches.jsonl`
- `research/provisional-closure-20260831/duplicate-ledger-patches.notes.md`
- `research/provisional-closure-20260831/not-ai-ledger-patches.jsonl`
- `research/provisional-closure-20260831/not-ai-ledger-patches.notes.md`
- `research/provisional-closure-20260831/ready-ledger-patches.jsonl`
- `research/provisional-closure-20260831/ready-ledger-patches-notes.md`
- `research/provisional-closure-20260831/commit-scope.md`

The JSONL files are transaction drafts, not proof that the transactions have
been applied. Their accompanying notes and second-review artifacts belong in
the same commit because they record the evidence boundary and reviewer
decision behind each proposed row.

Some sibling agents were still producing patch drafts when this snapshot was
taken. Do not stage a partially written version; wait for the owning agents to
finish, then re-list this directory before staging.

## Exclude from this commit, but preserve

### Incomplete Round12 campaign

Exclude the entire directory:

- `research/round12-top50-20260830-e6371483-bb5e-46b4-8dbd-5385b370881a/`

It is active, incomplete campaign state rather than provisional-closure
evidence. At this snapshot its 50-row manifest had 49 primary outputs, 10
`invalid-clone-assignment` records, and no `report.md`, `results.jsonl`, or
`worker-roster.jsonl`. Preserve it for its owner; do not delete it and do not
include any subset of it in this commit.

### Parallel summary/readability lane

The following untracked directory belongs to the separate summary-readability
review and must not be mixed into the provisional-closure commit:

- `research/summary-readability-20260831/`

The following tracked modifications are also owned by the parallel
publication/readability work. Commit them separately after that owner finishes
validation; do not stage them for provisional closure:

- `research/gate-campaign-20260830/summaries-by-alias.json`
- `scripts/publish_tp_ledger.py`
- `scripts/site_preflight.py`
- `scripts/tests/test_ledger_store_contracts.py`
- `scripts/tests/test_site_publication_contract.py`
- `scripts/tp_publication_overrides.json`
- `web/src/components/__tests__/ui-regressions.test.tsx`
- `web/src/generated/research-data.json`

Several of those tracked files contain mixed publisher, summary, generated-data,
or test changes. Path-level staging cannot safely split them into this research
commit; leave the full paths unstaged here instead of using broad `git add -A`.

#### GitHub witness retry verdict: DROP

Drop the current `scripts/site_preflight.py` retry diff from the
provisional-closure commit. It is publication-network hardening, not evidence
or transaction material for this closure lane. It also does not implement the
status-specific policy its comment suggests: Python's `HTTPError` reaches the
`OSError` handler through `URLError`, so the loop retries deterministic 404s
and other HTTP failures as well as DNS/TLS failures, `UnicodeError`, and
`ValueError`, rather than only transient 403/429 responses; it also ignores
`Retry-After`.

The diff does retain fail-closed behavior: after four unsuccessful attempts it
returns `None`, and the caller emits a preflight error, so persistent 403/429
responses are not accepted as valid witnesses. Keep this path out of this
commit and handle it as a separate publication-hardening change with a
status-aware bounded retry while preserving that terminal failure.

### Ignored/generated local state

Never add local build/cache output such as `web/.next/`, `web/out/`,
`web/node_modules/`, or Python `__pycache__/` directories.

## Snapshot boundary

There were no staged files at the start of this audit. No canonical ledger,
ledger-history, or site database file was dirty for the provisional-closure
lane; the proposed ledger changes exist only in the JSONL drafts listed above.
Re-run `git status --short` and `git diff --check` after all writers stop and
before staging.
