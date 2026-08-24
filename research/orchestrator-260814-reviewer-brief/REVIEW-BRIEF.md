# Independent reviewer brief: critique the AI-contributed-GHSA research

Read the artifacts below, then write an honest review into review.md in your own
directory. You are an independent critic, not a colleague being polite. Be
specific and evidence-cited.

## Context

Goal: find 200 unique, zero-false-positive GHSAs where AI directly or indirectly
contributed the vulnerable code. Current verified union: 167 (foundation.jsonl).

## Artifacts to read

- docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md (single-source map)
- autoresearch/orchestrator-260814-ghsa200-canvas/STATUS.md
- autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl (167 rows)
- autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md (the 7 gates)
- autoresearch/orchestrator-260814-ghsa200-canvas/sweep/INCREMENTAL.md (pipeline)
- autoresearch/orchestrator-260814-ghsa200-canvas/sweep/gate.py (acceptance gate)
- sweep SPECs: FWD-SPEC.md, DR-SPEC.md, CHAIN-SPEC.md, IRCHAIN-SPEC.md
- autoresearch/orchestrator-260814-irchains-sol/ir-chains.jsonl (chain records)
- sweep pool summaries: fix-marker-scan.json, ai-ancestry-candidates.jsonl,
  ai-ancestry-overlap.jsonl, nofix-advisories.jsonl

## Questions to answer

1. Direction: is the 'exhaust local evidence + monthly delta' strategy right? What
   should be prioritized next to reach 200 without false positives?
2. Method: are the 7 gates sound? Is the zero-FP claim defensible given leader
   replay only checks mechanical properties (trailer, ancestry, reversal overlap,
   releases)? What gaps remain in the verification?
3. Accuracy: spot-check 10 random foundation rows (AI identity, mechanism, fix)
   against the git objects in /home/hanqing/.cache/ghsa200-sweep-fetch and the
   advisory-database clones under /home/hanqing/.cache/ghsa200-worker-clones.
   Report false positives or weak rows you find.
4. True-positive misses: which candidate lanes are under-covered? Be concrete
   about signal sources we should add (e.g., non-github-reviewed GHSAs, AI-tool
   bot identities we are not matching, fix refs we skip, windows we ignore).

## Constraints

Read-only outside your own dir; no GitHub API; no commits; no credential
printing. Review.md must separate observed fact from inference.
