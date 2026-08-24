# Independent review: AI-contributed-GHSA research

Date: 2026-08-14. Scope: the artifacts listed in
`autoresearch/orchestrator-260814-reviewer-brief/REVIEW-BRIEF.md`, plus local git
objects and advisory snapshots under `/home/hanqing/.cache/ghsa200-sweep-fetch`
and `/home/hanqing/.cache/ghsa200-worker-clones`. No GitHub API or commits were
used.

## Verdict

**HOLD.** `foundation.jsonl` is a useful union of adjudicated hypotheses, but it is
not yet a claim-grade, leader-verified, zero-false-positive countable ledger.

- Observed fact: the file contains 167 rows and 167 unique GHSA IDs.
- Observed fact: `STATUS.md` says 165 while the brief says 167.
- Observed fact: only 93/167 rows have all seven gate values equal to `PASS`; 74
  rows—every one from `source=fp211_audit`—contain at least one `NARROW`, `NA`, or
  `UNKNOWN` gate.
- Observed fact: only 4/167 rows have `counted=true`; 163 have `false`.
- Observed fact: compact foundation rows omit contract-required aliases, mechanism
key/scope, release evidence, counterevidence, replay commands, and baseline-overlap
disposition.
- Inference: the defensible current statement is “167 unique adjudicated hypotheses,
93 of which are all-PASS in the compact projection,” not “167 verified countable
cases.”

## 1. Direction

Local-evidence exhaustion followed by bounded monthly deltas is the right direction,
but only after repairing the ledger and verifier. The local pools are already large:

- Observed fact: `fix-marker-scan.json` has 17,757 unique advisory rows, 5,414
  repositories, 17,584 fetched rows, and 1,688 AI-marker fixes.
- Observed fact: `ai-ancestry-candidates.jsonl` has 4,558 unique case/ancestor pairs
  across 1,323 repositories; only one case is already in foundation.
- Observed fact: `ai-ancestry-overlap.jsonl` has 753 cases with candidate/fix file
  overlap, all disjoint from foundation.
- Observed fact: `nofix-advisories.jsonl` has 4,119 unique GHSAs; 4,099 are disjoint
  from foundation.

Priorities:

1. Split foundation into immutable all-PASS/countable, scoped-NARROW, and proposal
   rows; reconcile the 165/167 discrepancy before more admissions.
2. Adjudicate the 753 overlap cases first, replacing filename equality with exact
   hunk/same-invariant analysis.
3. Mine the 1,688 AI-authored fixes for incomplete remediation and chain hops, but
   do not treat an AI-authored fix alone as evidence that AI introduced a flaw.
4. Use the 4,119 no-fix pool as a bounded, repo-clustered lane rather than a blind
   full scan. Local concentrations include OpenClaw (174), PraisonAI (128), n8n
   (114), ImageMagick (103), and Open WebUI (77).
5. Add a distinct unreviewed-advisory lane: 4,114/4,119 no-fix rows are locally
   present as GitHub-reviewed, so that pool does not cover the global unreviewed
   population.
6. Keep monthly deltas, but advance `adb_head` only after every emitted row reaches
   terminal disposition. The current incremental script advances state before
   adjudication.

## 2. Method and seven gates

The seven gates are conceptually sound. The implementations do not prove them.

| Gate | Contract soundness | Current gap |
|---|---:|---|
| Identity | Sound | `gate.py` never opens or validates the advisory identity; withdrawn/cross-bound checks are absent. |
| AI hunk | Sound | It regexes the entire commit message, not the vulnerable hunk; generic `assisted-by:` or incidental tool text can pass. |
| Topology | Sound | Only candidate→fix ancestry is checked; carrier, squash member, import, and reintroduction topology are absent. |
| But-for/material delta | Sound | No implementation in `gate.py`; foundation omits scope and counterfactual evidence. |
| Fix reversal | Sound | Any shared filename passes, even if candidate and fix alter unrelated hunks. |
| Release | Sound | There is no tag, package gitHead, artifact, or version containment check. |
| Uniqueness | Partially sound | Only duplicate `case_id` is rejected; aliases and cross-GHSA same-mechanism collisions are ignored. |

Additional facts:

- `leader_replay.py` computes candidate→fix ancestry but omits ancestry from its
  `verified` expression; resolvable objects plus an AI-message regex suffice.
- Its regex accepts bare `Co-Authored-By:` and `Authored-by:`, including humans.
- `incremental.py` term-gates advisories on AI wording before git-history recall.
- FWD examines at most six recent AI commits, then instructs a case-level
  `FALSE_POSITIVE/no_ai_origin`; this is bounded absence, not counterevidence.
- DR rejects a whole case when its one supplied ancestor is unrelated, even though
  another AI ancestor may exist.

Inference: “zero known false positives” may describe corrections already found, but
“zero false positives” is indefensible until all countable rows retain replayable
semantic evidence and bounded negatives remain `UNKNOWN`.

Minimum closure:

1. Bind each row to an immutable advisory/source hash.
2. Use a strict AI-identity allowlist and bind the AI hunk to the release carrier.
3. Replay member→carrier→vulnerable release and fix→fixed release separately.
4. Represent reversal as exact invariant/hunk reversal, not common filename.
5. Store package gitHead or tag-peeled release evidence.
6. Enforce alias-aware mechanism-fingerprint uniqueness.
7. Reserve `FALSE_POSITIVE` for affirmative counterevidence; use `UNKNOWN` for
   bounded misses.

## 3. Ten-row accuracy spot check

Selection method: fixed seed `random.Random(20260814)`, shuffle, first ten rows.
No demonstrated false positives appeared. Five rows are weak; one is misclassified.

| GHSA | Result | Evidence and caveat |
|---|---|---|
| GHSA-MGXW-V6RH-WCV6 | WEAK | Claude commit `d2b27f6f` adds profile APIs, but the audit says the parent already had `/api/sessions/search`; candidate is only new-surface, and topology/but-for are `NARROW`. |
| GHSA-4MR5-G6F9-CFRH | KEEP | `claude[bot]` commit `3cd664bf` adds restricted builtins; v4.6.39 omits `__self__`, while `179cab02`/v4.6.40 blocks it. |
| GHSA-425G-FJHQ-5H92 | KEEP, class error | Claude commit `a3d7f417` directly introduces the jsonschema-missing print-and-return branch later changed to raise by `6e7f938`; `AI_DIRECT_ROOT` is more accurate than `AI_INCOMPLETE_REMEDIATION`. |
| GHSA-42M6-XH7C-6XM4 | WEAK | Claude provider commits expose a new credential-bearing surface, but deleting them leaves the human-introduced shared `ProviderHTTPClient` callers; but-for/topology are `NARROW`. |
| GHSA-X9QH-W4C4-54F9 | KEEP | Claude Code commit `18f30b7f` first interpolates raw version into Docker build; `dc9322b1` adds strict validation and `escapeshellarg`. |
| GHSA-F2FQ-4RMP-9X8C | WEAK | Claude commit restores 2FA/lockout but omits failed-login accounting; release remains `NARROW` because partial carrier placement and advisory wording conflict. |
| GHSA-VVGP-4C28-M3JM | KEEP | Cursor commit `4a7b813a` adds trusted-proxy skip; `ec45c317` requires operator role; npm release evidence distinguishes vulnerable and fixed versions. |
| GHSA-7F6V-3GX7-27Q8 | KEEP | Copilot member `3e176213` inserts unescaped Swagger JSON into a script; carrier `4f28b695` reaches v1.8.3 and fix `4f0efa8a` reaches v1.13.9. |
| GHSA-5WP8-Q9MX-8JX8 | WEAK | Claude members add empty-allowlist passthrough, but a multi-purpose squash carrier lands it and member-to-fix topology remains `NARROW`. |
| GHSA-H4RQ-P45C-642R | WEAK | Claude adds token Users API, but it inherits a pre-existing unvalidated `StoreUserRequest`; fix also repairs the older session surface. Count only new-token scope. |

Totals: 4 KEEP, 1 KEEP with class-label error, 5 WEAK, 0 demonstrated false
positives.

Independent parallel five-row sample: 4 KEEP, 1 WEAK. GHSA-JX5R-P82P-2P8M is weak
because the advisory covers three GET-delete pages while the candidate adds only
`FundRaiserDelete.php`. GHSA-FWPR-59HH-GR98 also has unresolved fixed-release
semantics: no local tag contains its fix and advisory wording is contradictory.

Inference: the dominant residual problem is scope inflation and topology/release
ambiguity, not fabricated AI identity.

## 4. True-positive misses and lanes

Concrete under-covered or mislabeled lanes:

1. **Unreviewed advisories:** the no-fix pool is overwhelmingly GitHub-reviewed;
   harvest global/unreviewed advisories separately.
2. **Advisories without AI prose:** reverse-route every new repo/fix into local git
   history; advisory wording should not control recall.
3. **AI-authored fixes:** 1,688 are already local; mine for incomplete remediation,
   bypass chains, and earlier AI origins without counting fix authorship alone.
4. **3,805 ancestry candidates outside overlap:** dispatch by path/mechanism
   proximity, not filename equality alone.
5. **Search ceilings:** ancestry is bounded to 150 commits and dates from 2025-05-01;
   add bounded exceptions for older vulnerable windows.
6. **Multiple AI ancestors:** DR's one-edge rejection is insufficient; consider all
   AI-changed paths associated with the fix invariant.
7. **No-fix releases:** use package gitHeads, wheels/sdists, tags, and release
   manifests to reconstruct containment when no commit ref exists.
8. **AI identities:** add explicit GitHub App identities (`claude[bot]`, Copilot
   agents), generated-with variants, and verified bot users; never infer from style.
9. **Skipped fix refs:** preserve all commit and PR references; the current delta
   takes only the first commit-looking URL.
10. **Repo-adjacent cases:** once one accepted case exists, enumerate adjacent
    security hunks and residual bypasses; use this as recall, not proof.
11. **Chains:** `ir-chains.jsonl` resolves 44/51 originals and leaves 7 UNKNOWN;
    those must not be downgraded to HUMAN.

## Bottom line

Do not spend the next cycle chasing 33 rows. First split and freeze the claim, then
repair semantic replay. After that, the highest-yield zero-FP path is exact-hunk
adjudication of the 753 overlap cases, followed by all-AI-ancestor handling,
package release containment, repo-adjacent discovery, and a true unreviewed-advisory
lane.
