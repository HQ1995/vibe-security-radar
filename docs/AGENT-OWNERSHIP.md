# Agent ownership contract (enforced via Herdr)

Updated 2026-08-15 after repeated web-data conflicts. Every live agent must
read this before editing anything outside its own output dir.

- web/src/generated/research-data.json : single-writer = the leader, via
  scripts/publish_tp_ledger.py ONLY. No agent edits it by hand and no
  agent runs git checkout on it.
- web/src/app, web/src/components, web/src/lib : owned by the site-fix2 lane.
  Other lanes treat them as read-only.
- archives/legacy-web-data-campaign/ : frozen legacy campaign evidence.
  Do not edit.
- autoresearch/orchestrator-*/ and autoresearch/herdr-*/ : owned by the lane
  that created each dir. Never edit another lane's dir.
- Shared ledgers (foundation.jsonl, canonical*/ledger.jsonl) : leader-only
  writes; lanes read.

Conflict rule: if two lanes need the same file, the leader arbitrates; no
lane re-does or reverts another lane's committed-in-progress work.
