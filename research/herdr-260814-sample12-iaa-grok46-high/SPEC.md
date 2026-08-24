# Worker spec: blind 12-row re-review of counted strict cases (IAA sample)

Owner: this directory only. You are an independent reviewer, not the ledger.

## Assigned set (fixed, do not expand)

Twelve counted strict rows, identified by case_id / repository / SHA sets.
Re-derive each gate from first-party evidence only; treat the stored gate
values in the ledger as non-evidence and do not copy them.

1. GHSA-C4HM-4H84-2CF3 ruvnet/ruflo cand 29d52dfc22842b80928d058c88f446993ec4975c fix d00a0a40cd8bdbca877ac7f675f416bdc69accd1
2. GHSA-X9QH-W4C4-54F9 coollabsio/coolify cand 18f30b7fabc54938a031867ad34c39a1e9c7c0d7 fix dc9322b11f5f4ab96e56af0df7d4f877e96e5e4c
3. GHSA-RQP8-Q22P-5J9Q openclaw/openclaw cand 03586e3d0057b5975090d50dadcc5bc95b51f977 fix 980940aa58f862da4e19372597bbc2a9f268d70b
4. GHSA-5RV5-XJ5J-3484 lostisland/faraday cand a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc fix 3f1280c69e93297d574e85a2d462d05ebadf1d09
5. GHSA-G3XQ-3GMV-QQ8G cnighswonger/claude-code-cache-fix cand 7b9322a86a5cae3230c30943bd659d7f67b0387c fix 613e4df30547f3e6baf32d161eddc828f171da17
6. GHSA-W28W-GP39-M4P6 microsoft/prompty cand a0e6108842a3bfc840a33db819a4415fbdac333d fix e4a0ebf49e3a78d5d7796c8480bf9a4f0c54d19e
7. GHSA-C4GH-RV8H-Q9VW microsoft/prompty cand a0e6108842a3bfc840a33db819a4415fbdac333d fix c27402da2487075be577f06aa79df627fb9d6853
8. GHSA-J5QP-P44G-2M49 asymmetric-effort/specifyjs cand 30f9b76f848b681e2806ac6ebcebebb055af3999 fix 25d1fb491d99479efdf501f5f75e0bb80c908f0a
9. GHSA-Q6QC-XP4Q-RJQ5 enderfga/claw-orchestrator cand f82c783607ae0129386cc072160dfcfb151a31fe fix d0b02a800aa0689d9428cc4cc170e0b6589fb2c3
10. GHSA-VJ3G-5PX3-GR46 cand a604df8c83d179a6e9fc07987ebef610faaf4991 carrier 2267d58afcc70fe19408b8f0dce108c340f3426d fix c821099157a9767d4df208c6b12f214946507871
11. GHSA-46Q5-G3J9-WX5C qhkm/zeptoclaw cand 2c9deefbf744089c3041885717b92c6f2fc0bf8c fix bf004a20d3687a0c1a9e052ec79536e30d6de134
12. GHSA-RG8M-3943-VM6Q openclaw/openclaw cand 49c60e9065d98a6848e62c717315eb91eeaa6038 fix 8a563d603b70ef6338915f0527bee87282c3bad5

## Method

Read the seven-gate definitions in
autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md. For each row
check identity, AI hunk provenance (author + trailer + diff), topology,
but-for causality, minimum-fix reversal, released containment, and uniqueness
against first-party advisory + Git history.

## Evidence sourcing - NO GitHub API

The GitHub REST/GraphQL API is rate-limited and must not be used. No gh api,
no curl api.github.com. Use, in this order:

1. Existing local clones: search
   /home/hanqing/.cache/ghsa200-worker-clones/*/<owner>__<repo>.
2. Local advisory data: the frozen advisory-database clones under
   /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database,
   commit-af/advisory-database, and fresh-delta20-grok46-low/advisory-database,
   plus the local OSV caches .ai-slop/cache/osv-advisory-fix-index-v1/ and
   .ai-slop/cache/osv-advisory-observations-v3/.
3. Git smart-HTTP only for missing objects: shallow, blobless, single-repo
   fetch into work/ as in the sibling worker spec. No full clones.

Record, per row: final verdict (CONFIRM, NARROW, FALSE_POSITIVE, UNKNOWN),
each gate outcome, confidence, and FP class if rejected. Then a separate
disagreement section comparing your verdict to the counted status; do not
edit the ledger.

## Outputs (English only)

- result.json: per-row gate matrix, verdicts, counts, terminal=true.
- cases.jsonl: one review row per assigned row.
- report.md: findings, gate failures, disagreement section, FP classes seen.

## Hard constraints

- Never edit anything outside this owned directory; never edit the ledger.
- Never commit/push/reset/checkout in this repository or in clones.
- Do not print or store credentials.
