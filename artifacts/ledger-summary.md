# Vibe Security Radar — research total account

Window: 2025-05-01 .. 2026-08-16 (census + live GHSA tail merged). Updated 2026-08-17.

## Funnel: all CVE+GHSA -> open-source repo -> code-writing AI commits

1. Total deduped CVE+GHSA (ACTIVE/PUBLISHED, WITHDRAWN/REJECTED excluded):
   84,060 census + 3,304 tail (08-10..16) = **87,364**
2. With an open-source repo (GHSA+CVE+OSV identity union): **41,990**
   (9,512 distinct repos; mapping includes CVE-reference repos, some of which are
   PoC/writeup repos rather than the project itself - quality refinement open)
3. Repo has 2025+ code-writing AI commits (bot-excluded): **3,683 repos**
4. Narrowed advisory classes: **23,868**

## Screening coverage (all repos in the class map now have verdicts)

- Repos with a verdict: 9,512/9,512 (100%). Of these:
  - CODE_AI verified: 3,683 (stage-2 code-file check, bot emails excluded)
  - excluded with reason in the rescan waves: 1,783 NO_MARKER + 521 NO_HITS
    + 73 DOCS_ONLY (the remainder of the 9,512 was excluded by the original
    2026-08 AI scan: repos scanned with no marker hits)
  - unreachable over git, each with a host-level reason: 283 (deleted/private/moved
    github repos, dead gitlab instances, unmappable reference URLs)
- Stage-2 totals across all rescan waves: 784 CODE_AI, 543 NO_HITS, 86 DOCS_ONLY
- Per-repo audit trail: artifacts/host-reasons-20260816.txt (no UNKNOWN verdicts)

## Chromium dedicated scan (2026-08-17)

214 chromium-family records (CVE+GHSA+OSV) -> 21 canonical chromium repos.
11 repos have verified 2025+ AI code commits (chromium/src 3,246 marker commits,
chromiumos kernel, v8, angle, pdfium, boringssl, infra, ffmpeg, webm/libvpx,
android pdfium/cts). Record verdicts: 111 CODE_AI, 103 NO_AI.
2025+ records: 8 -> 6 CODE_AI. These OSV ids are not census alias members,
tracked in artifacts/chromium-ai-scan-20260817.jsonl.



## Funnel account: analysis status of the 23,868 classes (2026-08-17)

One row per class in artifacts/funnel-account-20260817.jsonl.

- DOSSIER (deep causal dossier exists): 88
  - B2_NOT_AI 84, B3_BLOCKED 4
- LEDGER_TOUCHED (some member has ledger research, not necessarily causal):
  6,350
  - RECOVERED_VERSION 2,996 (fix version found, no causal AI verdict)
  - B2_NOT_AI 1,298 (adjudicated not-AI)
  - SKIP 697, REVIEW 624
  - B3_BLOCKED 535 (analysis attempted, evidence blocked)
  - B1_AI_FAULT 104 (AI at fault)
  - NONE 96
- PENDING (repo found, repo verified AI code-writing, vuln-level analysis not
  started): 17,430
  - 7,795 of them git.kernel.org (stable/linux wide-marker repo: per-vuln
    introduce-commit -> AI blame tracing still to be done)
  - 193 android/codelinaro googlesource repos
  - remainder across ~1,000 other repos

Honest gaps inside PENDING: the AI-commit link is established at repo level
only. For each class we still owe: locate introduce commit -> check whether
that commit/author is AI -> locate fix -> adjudicate. Kernel classes are the
biggest method question (wide-marker noise on 100k-commit repos).

## Open work (honest gaps)

- 87,364 - 41,990 = 45,374 classes with no repo mapping: mostly closed-source,
  but GHSA records should be deterministically repo-matched (many still have
  package/reference URLs we have not fully mined). Next major block.
- PoC-noise cleanup: classes whose only repos are researcher PoC repos should be
  re-classified as no-project-repo rather than with-repo.
- Tail (08-10..16) not yet alias-deduped against census members.

Artifacts:
- artifacts/funnel-narrowed-20260816.jsonl
- artifacts/code-writer-repos-20260816.json
- artifacts/host-reasons-20260816.txt
- artifacts/chromium-ai-scan-20260817.jsonl
