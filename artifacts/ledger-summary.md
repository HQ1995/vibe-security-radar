# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-09 (official census). Last updated: 2026-08-16.

## Funnel: all CVE+GHSA -> open-source repo -> code-writing AI commits

1. Total deduped CVE+GHSA (ACTIVE/PUBLISHED, WITHDRAWN/REJECTED excluded): 84,060
2. With an open-source repo (GHSA+CVE+OSV union): 40,179
   - without any repo: 43,881
3. Repo has 2025+ code-writing AI commits (email+message markers,
   dependency bots excluded, changed_files code check): 2,903 repos
4. Narrowed advisory classes: **13,791**

Artifacts:
- artifacts/funnel-narrowed-20260816.jsonl (class_id, repo)
- artifacts/code-writer-repos-20260816.json (verified repo list)

Lower-bound caveats (fail-closed):
- 1,194 repos with AI-marker hits failed the code-check fetch -> excluded
- 562 + 376 repos UNSCANNABLE at host level -> excluded
- census window ends 2026-08-09; 08-10..16 delta not yet merged

