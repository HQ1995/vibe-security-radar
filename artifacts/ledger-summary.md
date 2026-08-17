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



## Funnel account: unified status of the 23,868 classes (2026-08-17)

Absorbs website foundation research (fp211 gates), ledger verdicts, and
dossiers into one per-class status. One row per class in
artifacts/funnel-account-20260817.jsonl.

- TP_SITE_STRICT: 116 (narrow70 deep-dive + second opinions + settled co-author policy)
- TP_SITE_NARROW: 29 (remaining gate gaps, not attribution debates)
- TP_B1: 87 (ledger B1_AI_FAULT only)
  -> TP total: 232 classes

Settled policy 2026-08-17: commit carrying co-authored-by/assisted-by/AI-author
markers counts as AI-written (see docs/tasks/ai-pattern-methods-20260817.md).
- NOT_AI: 1,391 (narrow70 second opinions downgraded 1 more)
- BLOCKED: 535 (B3_BLOCKED, evidence insufficient)
- PARTIAL: 4,280 (RECOVERED_VERSION 2,976, SKIP 690, REVIEW 614)
- PENDING: 17,430 (repo-level AI verified only, vuln-level analysis not started)

narrow70 deep-dive (2026-08-17): 70 cases re-analyzed with full lineage +
AI-code judgment (flash workers), then double-reviewed by grok-4.6 and
gemini-3.7-flash second opinions (per-case, evidence packs). Adjudicated:
33 STRICT, 31 NARROW, 6 B2_NOT_AI. Manual verification on the 18 reviewer
disagreements: openclaw guard-removal and guard-simplification commits
confirmed; mruby (Matz primary author, Rovo co-author only) and feishu
(sync of pre-existing upstream code) downgraded to NARROW.
Evidence: .ai-slop/state/narrow70/review/adjudicated.jsonl
- 1 conflict: GitPython GHSA-539m (site STRICT AI_INCOMPLETE_REMEDIATION vs
  ledger B2 narrow-scope; kept site verdict, noted in the account row)

## TP reconciliation (2026-08-17)

Two parallel TP books existed and never merged - the source of the number confusion:

- Website "191 cases" = ghsa200-canvas foundation.jsonl curated showcase set
  (fp211 tiers: CONFIRM 12 / STRICT 84 / NARROW 95). Only 8 of them are
  ledger-B1.
- Ledger B1_AI_FAULT = 118 unique case ids (167 verdict rows) from the mining
  waves (tp-mining-wave1, laneA/B, repo-batch dossiers).

Unified registry artifacts/tp-registry-20260817.jsonl:
- union = 301 unique case ids
  - ledger-B1 only: 110
  - foundation STRICT only: 68
  - foundation NARROW only: 66
  - CONFIRM only: 6
  - overlapping/mixed: ~51
- 248 of 301 map inside the 23,868 funnel classes; 53 outside (window/no-repo).
- Class-level inside 23,868: 104 classes carry a B1; a class-level tiered count
  is in artifacts/funnel-account-20260817.jsonl.

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
