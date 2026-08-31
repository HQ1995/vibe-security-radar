# GHSA-VCV2-R9JH-99M5 topology edge repair

- Class: `alias-8fde3b61bfb7a8b43050519d`; live base revision: `2` (`da7d00db-b73d-413e-9b76-ca34bbc2b62c`).
- The patch preserves the complete live row and adds only `candidate_fix_edges`.
- `319c98616bc968b6810c6c0b49e04806e7379530` is a member of merge `68e60a86c92db19c62fe175295a21b073033b31f`: it is an ancestor of the merge's second parent `cd96f5b7468987bdf6d25fe72326b72428411e19`, but not its first parent `95db7feded456988cb6f976df94e5e74230f5357`. Its edge is therefore `merge_member` through carrier `68e60a86...` to atomic fix `a0f9c2bf...`.
- `2a1e2777dd6a993f678d9596dd7c6c4fd0c444d9` is not an ancestor or descendant of carrier `68e60a86...`. It independently adds the vulnerable `http-sse.ts` `execSync` path and is a `direct_commit` edge to the same atomic fix, with `carrier_sha=null`.
- Both candidates and the carrier are ancestors of `a0f9c2bf95b6203b3e1b24f92a7e390d6774de13`; that fix replaces attacker-influenced shell command strings with `execFileSync` argument arrays.
- Primary evidence: `research/provisional-closure-20260831/shard-02.md:218`, `research/orchestrator-260813-fp211-canonical/ledger.jsonl:43`, and local Git objects in `.ai-slop/state/repos/ruvnet_agentic-flow`.
- Staged artifact only: not applied, exported, published, committed, or reflected in website/generated data.
