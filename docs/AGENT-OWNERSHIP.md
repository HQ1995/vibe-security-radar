 # Agent ownership contract (enforced via Herdr)
 
 Updated 2026-08-15 after repeated web-data conflicts. Every live agent must
 read this before editing anything outside its own output dir.
 
 - web/src/generated/research-data.json : single-writer = the leader, via
   scripts/publish_tp_ledger.py ONLY. No agent edits it by hand and no
   agent runs git checkout on it.
 - web/src/app, web/src/components, web/src/lib : owned by the site-fix2 lane.
   Other lanes treat them as read-only.
 - research/ : LOCAL-ONLY (git-ignored, never committed). Lanes keep their
   own result files on disk; nothing under research/ is committed to git.
 - The canonical funnel ledger is Neon Postgres. Lanes write only their owned
   result files; the leader records append-only assessments and lands complete
   verdict batches through `scripts/ledger_store.py assessment-add` / `finalize`.
   Expected revisions, advisory retention, envelope checks, and immutable history
   are enforced transactionally.
 - `artifacts/funnel-account-*.jsonl` is the deterministic GitHub recovery
   export, written only by the leader via `scripts/ledger_store.py export`.
   Never edit it directly. Run duplicate-TP and record gates before `finalize`;
   export/publish only after the Neon transaction succeeds.
 
 Conflict rule: if two lanes need the same file, the leader arbitrates; no
 lane re-does or reverts another lane's committed-in-progress work.
