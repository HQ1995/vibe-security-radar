# GHSA-VCV2-R9JH-99M5 canonical code-evidence repair

## Result

This case is **not unresolved**. The missing-diff diagnosis came from routing the
case to `ruvnet/ruflo`. The retained first-party clone is
`.ai-slop/state/repos/ruvnet_agentic-flow`, whose origin is
`https://github.com/ruvnet/agentic-flow`; it is non-shallow and contains both
origin commits, their parents, the carrier, and the atomic fix.

The ledger patch therefore changes the canonical repository to
`ruvnet/agentic-flow`, publishes exact selected hunks from both origins and the
direct fix, and leaves `unavailable_reason` and `unresolved_reason` absent. It
does not copy the obsolete missing-object explanation from
`scripts/site_preflight_allowlist.json`.

## Object and causal checks

- `319c98616bc968b6810c6c0b49e04806e7379530` and parent
  `08c4373f91b634d295f2c632fe345aff986464d3` are present. The commit creates the
  stdio MCP server and passes request-controlled `key` and `namespace` through
  a template string to `execSync`; its message says it was generated with
  Claude Code and carries the Claude co-author trailer.
- `2a1e2777dd6a993f678d9596dd7c6c4fd0c444d9` and parent
  `a380dfde6e6b8a39f8fd4d2581a5f1ff58a1ac9b` are present. This independent
  origin creates the HTTP/SSE server, concatenates remotely supplied tool
  arguments into a shell command, and calls `execSync`; it has the same Claude
  markers.
- Carrier `68e60a86c92db19c62fe175295a21b073033b31f` belongs only to the `319c9861`
  edge. The `2a1e2777` edge remains direct.
- Atomic fix `a0f9c2bf95b6203b3e1b24f92a7e390d6774de13` is present and directly replaces
  the selected sinks with `execFileSync('npx', argv, { shell: false })`.
- The established identity, release, and topology authority is
  `research/orchestrator-260813-fp211-audit/final_mechanisms.jsonl:43`; the prior
  edge repair is documented in
  `research/provisional-closure-20260831/vcv2-topology-edge-ledger-patch.notes.md`.

## Patch contract

- Live base: `alias-8fde3b61bfb7a8b43050519d`, revision `4`.
- The JSONL record contains the complete live row plus the repository correction,
  canonical `code_evidence`, and `code_evidence_source`.
- Staged artifact only: not applied, exported, published, or committed.
