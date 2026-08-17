# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-16 (census + live GHSA tail merged). Updated 2026-08-16.

## Funnel: all CVE+GHSA -> open-source repo -> code-writing AI commits

1. Total deduped CVE+GHSA (ACTIVE/PUBLISHED, WITHDRAWN/REJECTED excluded):
   84,060 census + 3,304 tail (08-10..16) = 87,364
   (caveat: tail not yet alias-deduped against census members)
2. With an open-source repo: 40,709
3. Repo has 2025+ code-writing AI commits (bot-excluded): **3,580 repos**
   (was 2,903; +677 verified in the 08-16 failed-repo re-scan)
4. Narrowed advisory classes: **23,705** (was 14,068; +9,637)

The +9,637 delta is dominated by git.kernel.org (7,804 classes): the code-writer
set had always contained verified kernel.org/stable/linux, torvalds/linux,
android kernel/common and codelinaro kernels, but the class->repo join previously
matched github.com references only, so non-github classes could never join.
The join now uses the full host/owner/repo identity map (GHSA+CVE+OSV).

## Failed-repo re-scan (2,138 repos that were previously unresolved)

- 1,236 marker hits -> stage-2 code-file verification:
  - 681 CODE_AI -> added to code-writer repos
  - 521 NO_HITS, 73 DOCS_ONLY -> excluded with reason
- 816 RESOLVED_NO_MARKER: repo reachable, no AI-marker commits since 2025-05-01
  (mostly empty repos / repos frozen before the window)
- 86 NO_GIT_HOST, each with a host-level reason: 48 github ls-remote 404
  (deleted/private/moved; git redirects renames, so 404 means gone), 21 gerrit
  + 11 googlesource case-mismatches resolved via official directory listings
  (37 re-scanned, 16 marker hits -> stage 2), remainder: private gitlab
  instances / dead hosts
- FETCH_FAIL: 0 after the treeless fallback ladder (shallow-info-broken hosts
  like git.drupalcode.org resolved via full treeless fetch)

Evidence: artifacts/host-reasons-20260816.txt (one row per repo, per-identity
reason; no UNKNOWN verdicts).

Artifacts:
- artifacts/funnel-narrowed-20260816.jsonl
- artifacts/code-writer-repos-20260816.json
- artifacts/host-reasons-20260816.txt
