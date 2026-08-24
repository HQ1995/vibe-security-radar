# Incomplete-remediation unseen20 (grok46-high)

**Verdict: TERMINAL. PASS_PROPOSAL = 0. Countable PASS = 0.**

Worker PASS is proposal only. This packet proposes no admissions.
Canonical91 stays 91. Publication and greater-than-200 remain HOLD.

Assigned 3. Reviewed 3. Unreviewed remainder 0. Equation 3=3+0 holds.
Bound was 20. The pattern pool exhausted at 3 without padding.

## Universe

Current first-party reviewed GHSAs: github-reviewed subtree at
/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
HEAD f2c6ab3202aeafb36fbea6e76d892532acfca1a6 (34389 files).

Excluded canonical91 strict 91 plus every identity with a terminal verdict
in herdr-260813, herdr-260814, orchestrator-260813, and orchestrator-260814
packets (assignment.jsonl, cases.jsonl, result.json identity fields).
Exclusion union 10118. Remaining active reviewed 23549 (890 withdrawn leftover
not counted). May-2025+ remainder 1586. Remainder with exact commit SHA and a
local clone: 657.

## Method

Priority: atomic AI-authored security attempt that predates the advisory closer,
with patch-delta causality. Later-fix blame (closer deleted lines blame onto a
distinct AI guard that the closer amends) is the strongest routing signal.
Ancestral AI security commits with file overlap are next. Ancestry without
shared paths is weak routing only.

IR-language later-fix probes: 155, hits 0.
File-overlap ancestral AI security attempts: 0.
Ancestral AI security attempts without file overlap: 3. Those three were
frozen. Same-repo leftovers were not padded. Local caches read-only. No GitHub
REST. No credentials. No durable clones or pages in the owned directory.

PASS requires seven exact PASS plus patch-delta. Rollback reopening a broader
old hole is not, by itself, success. A sibling fix on a different path fails.

## Per case

1. GHSA-5XRP-6693-JJX9 REJECT. github-reviewed CVE-2026-1470, npm n8n unsafe
   workflow expression evaluation. Claude-marked atomic d4ef191b is a Chat
   Trigger XSS / parameter-validation attempt and is an ancestor of closer
   25c4b960. Overlap with 25c4b960, 30383d86, and aa4d1e58 is empty; those
   SHAs edit expression-sandboxing.ts. Distinct from GHSA-JH8H. 0 tags.
   identity PASS, uniqueness PASS, ai_hunk FAIL, topology NARROW, but_for FAIL,
   fix_reversal FAIL, release UNKNOWN.

2. GHSA-7JCP-V9W4-WJMG REJECT. github-reviewed CVE-2026-7374, kubevirt link
   following. Claude-marked atomic f7bd23b8 preserves PVC contentType on
   restore. Listed closer 011eef81 is a two-parent kubevirt-bot merge of
   PR 17916 editing virt-handler rest console sockets. Zero overlap. Member
   authorship is not transferred. Shared SHA with GHSA-MPMF is not duplication.
   0 tags. identity PASS, uniqueness PASS, ai_hunk FAIL, topology NARROW,
   but_for FAIL, fix_reversal FAIL, release UNKNOWN.

3. GHSA-MPMF-3W4R-QFPF REJECT. github-reviewed CVE-2026-9804, kubevirt link
   following. Same AI candidate f7bd23b8. Atomic closer 6ea563fa is human
   origin rem of VMExport symlink traversal in virt-exportserver. Zero overlap
   with restore.go. That closer does not amend the AI contentType boundary.
   0 tags. identity PASS, uniqueness PASS, ai_hunk FAIL, topology NARROW,
   but_for FAIL, fix_reversal FAIL, release UNKNOWN.

## Conservation

frozen=3 reviewed=3 unreviewed=0 PASS_proposal=0 REJECT=3
pattern_hits=3 later_fix_hits=0 file_overlap_ancestral_hits=0
Worker PASS is proposal only. This packet proposes none.
