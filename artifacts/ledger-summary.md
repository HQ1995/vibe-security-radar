# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-16 (census + live GHSA tail merged). Updated 2026-08-16.

## Funnel: all CVE+GHSA -> open-source repo -> code-writing AI commits

1. Total deduped CVE+GHSA (ACTIVE/PUBLISHED, WITHDRAWN/REJECTED excluded):
   84,060 census + 3,304 tail (08-10..16) = 87,364
   (caveat: tail not yet alias-deduped against census members)
2. With an open-source repo: 40,179 + 530 = 40,709
3. Repo has 2025+ code-writing AI commits (bot-excluded): 2,903 repos
4. Narrowed advisory classes: **14,068**

Artifacts:
- artifacts/funnel-narrowed-20260816.jsonl
- artifacts/code-writer-repos-20260816.json

Fail-closed exclusions: fetch-failed repos, non-github host UNSCANNABLE,
tail repos resolved from references only (no OSV GIT join on tail).

