# Artifacts

Generated ledger data and source accounting. Neon `ledger_rows` is canonical; nothing here
is edited by hand.

- `funnel-account-20260817.jsonl`: the deterministic export of every ledger row, written
  by `scripts/ledger_store.py` after each transaction (`check` compares it with Neon).
- `ledger-history/`: append-only change sets, row versions, scan runs and assessments,
  written by `ledger_store.py export-history`.
- `source-watermark.json`: the verified source-capture cutoff and the full delta chain
  (data in `.ai-slop/sources/`), advanced by radar-incremental's `watermark.py`.
- `funnel-universe-meta-20260826.json`: the policy and census of the original universe.

Earlier books were removed from the working tree; recover them from history, for example
`git show 649505a:artifacts/ledger.jsonl`.
