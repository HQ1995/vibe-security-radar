# Independent review: AI-contributed-GHSA research

Date: 2026-08-14. Reviewer scope: the artifacts named in `REVIEW-BRIEF.md`; local
git objects and advisory snapshots under `/home/hanqing/.cache/ghsa200-sweep-fetch`
and `/home/hanqing/.cache/ghsa200-worker-clones`; no GitHub API, commits, or edits
outside this directory.

## Verdict

**HOLD.** The 167-row file is a useful union of adjudicated hypotheses, but it is
not presently a claim-grade, leader-verified, zero-FP countable ledger.

- Observed fact: `foundation.jsonl` has 167 rows and 167 unique GHSA IDs.
- Observed fact: `STATUS.md:8` says 165; the brief says 167. The status page is stale.
- Observed fact: only 93/167 rows have all seven gate values equal to `PASS`; 74
  are all from `source=fp211_audit` and contain one or more `NARROW`, `NA`, or
  `UNKNOWN` gate values.
- Observed fact: only 4/167 rows set `counted=true`; 163 are `false`. The file
  therefore cannot itself substantiate a “current verified union: 167”.
- Observed fact: the compact foundation rows omit contract-required aliases,
  mechanism key/scope statement, release evidence, counterevidence, replay
  commands, and baseline-overlap disposition (`CONTRACT.md:85-89`).
- Inference: the defensible statement is that the file contains 167 unique
  adjudicated GHSA hypotheses, of which 93 are marked all-PASS in this compact
  projection. Calling the full 167 “leader-verified” conflates source-layer
  hypotheses with strict countable admissions.

## 1. Direction

The **local-first plus monthly-delta** direction is right, but only after the
ledger claim is repaired. The available local pools are too rich to abandon for
net-new crawling:

- Observed fact: `fix-marker-scan.json` contains 17,757 unique advisory rows,
  5,414 repositories, 17,584 fetched rows, and 1,688 fixes carrying an AI marker.
- Observed fact: `ai-ancestry-candidates.jsonl` contains 4,558 unique case/ancestor
  pairs across 1,323 repositories; only one case is already in foundation.
- Observed fact: `ai-ancestry-overlap.jsonl` leaves 753 cases with candidate/fix
  file overlap, all disjoint from foundation.
- Observed fact: `nofix-advisories.jsonl` contains 4,119 unique GHSAs; 4,099 are
  disjoint from foundation.
- Inference: local candidate supply is not the immediate constraint. The constraint
  is adjudication/replay integrity and the recall/precision of routing.

Priority order:

1. **Freeze and rename the claim.** Split foundation into (a) immutable
   all-PASS/countable rows, (b) NARROW scoped hypotheses, and (c) proposal/replay
   rows. Reconcile 165/167 and stop `STATUS.md` from describing all rows as
   leader-verified.
2. **Work the 753 file-overlap cases first**, but only after replacing filename
   overlap with exact-hunk/same-invariant adjudication. They already have fix,
   candidate, repository, and local topology evidence.
3. **Do not interpret all 1,688 AI-authored fixes as AI-vulnerability evidence.**
   They are high-recall material for AI-carried fixes, adjacent incomplete
   remediation, and same-commit origins, but an AI-authored fix usually weighs
   against introducing the vulnerability unless the same commit also creates or
   weakens a boundary.
4. **Escalate a bounded slice of the 4,119 no-fix pool** by repo clustering and
   recent-AI-commit maps, not a blind full scan. Top local concentrations are
   OpenClaw (174), PraisonAI (128), n8n (114), ImageMagick (103), and Open WebUI
   (77). These concentrations are useful for evidence amortization, not evidence
   themselves.
5. **Add unreviewed/non-GitHub-reviewed GHSA coverage.** `nofix-advisories.jsonl`
   is overwhelmingly GitHub-reviewed (4,114/4,119 local files found), so the
   global unreviewed population remains a separate under-covered lane.
6. **Keep monthly deltas**, but make `adb_head` advance only after every emitted
   row reaches a terminal disposition. The current `incremental.py:81-84` writes a
   manifest and advances state before dispatch/adjudication.

## 2. Method and seven gates

The seven gates are conceptually sound and appropriately stricter than ancestry,
subject marker, or filename overlap. The implementation does not yet prove them.

| Gate | Sound in contract? | Current verification gap |
|---|---:|---|
| Identity | Yes | `gate.py` does not open advisory identity at all; withdrawn/cross-bound checks are absent. |
| AI hunk | Yes | `gate.py:42-45` regexes only the full commit message and does not bind the marker to the vulnerable hunk. |
| Topology | Yes | `gate.py:49-55` checks only candidate→fix ancestry; carrier/squash/import topology is absent. |
| But-for / material delta | Yes | `gate.py` has no implementation; foundation omits the scope and counterfactual evidence needed to audit it. |
| Fix reversal | Yes | `gate.py:57-62` equates any shared filename with reversal; unrelated hunks in the same file can pass. |
| Release | Yes | `gate.py` never checks a tag, package gitHead, artifact, or version. |
| Uniqueness | Partially | `gate.py:37` rejects only duplicate `case_id`; aliases and same-mechanism cross-GHSA collisions are not checked. |

Additional replay defects:

- Observed fact: `leader_replay.py:63-66` computes ancestry but omits it from
  `verified`, which requires only candidate/fix resolvability plus a message regex.
- Observed fact: its AI regex accepts bare `Co-Authored-By:` and `Authored-by:`,
  including human co-authors, contrary to `INCREMENTAL.md:45-47`.
- Observed fact: `incremental.py:63` routes only advisories containing AI terms,
  so advisories that omit AI wording never enter the manifest even when their git
  history contains an AI identity.
- Observed fact: FWD examines at most six recent AI commits, then instructs
  `FALSE_POSITIVE/no_ai_origin` if none matches (`FWD-SPEC.md:7,14,18-24`); that is
  bounded absence, not affirmative counterevidence.
- Observed fact: DR labels the whole case `FALSE_POSITIVE/wrong_edge` when its one
  supplied ancestor is unrelated (`DR-SPEC.md:14-25`); another AI ancestor may exist.
- Inference: zero known FPs is not the same as zero FPs. The latter is not defensible
  until semantic replay is deterministic, all countable rows retain evidence, and
  negative lanes preserve bounded search ceilings as `UNKNOWN`.

Minimum closure:

1. Bind a canonical advisory snapshot hash to every row.
2. Replay AI identity from a strict allowlist, and prove the exact candidate hunk is
   present in the release carrier.
3. For every class, prove same-invariant candidate→carrier→vulnerable release and
   fix→fixed release topology. Do not collapse member ancestry into carrier identity.
4. Represent exact reversal as changed lines/invariant, not common filename.
5. Store explicit vulnerable/fixed artifact evidence, including package gitHead or
   tag-peeled containment.
6. Make uniqueness alias-aware and mechanism-fingerprint-based across accepted rows.
7. Treat a lane's bounded negative as `UNKNOWN`; reserve `FALSE_POSITIVE` for
   affirmative counterevidence (pre-existing sink, human-only shared transport,
   unrelated sibling hunk, withdrawn/cross-bound identity).

## 3. Ten-row accuracy spot check

Selection method: `random.Random(20260814).shuffle(rows); rows[:10]`, fixed and
recorded before lookup. Verdict definitions: **KEEP** means the sampled identity,
mechanism, and fix direction are supported at the row's own scope; **WEAK** means
the row needs narrowing or has an open topology/release issue; no row was proven
false positive.

| GHSA | Result | Evidence and caveat |
|---|---|---|
| GHSA-MGXW-V6RH-WCV6 | WEAK | Claude commit `d2b27f6f` adds profile APIs, and the advisory covers cross-profile sessions search. The audit itself says the parent already had `/api/sessions/search`, candidate is only new-surface/contributor, fix member `8d8ae89d` is not the released carrier blob, and topology/but-for are `NARROW`. Keep only a narrowed new-profile-surface claim. |
| GHSA-4MR5-G6F9-CFRH | KEEP | `3cd664bf` is authored by `claude[bot]`, introduces restricted Python builtins including `print`; v4.6.39 lacks `__self__` blocking, while `179cab02`/v4.6.40 adds `__self__` to the sandbox blocklists. Ancestry and version containment are preserved. |
| GHSA-425G-FJHQ-5H92 | KEEP, classification error | Candidate `a3d7f417` is Claude-attributed and first adds `validate_against_schema`; it explicitly prints and returns when jsonschema is absent. Fix `6e7f938` changes that exact branch to raise `JSONValidationError`. Because the candidate directly introduces the fail-open boundary, `AI_DIRECT_ROOT` is more accurate than the stored `AI_INCOMPLETE_REMEDIATION`. |
| GHSA-42M6-XH7C-6XM4 | WEAK | Candidate `8348c85` is Claude-attributed and adds OpenRouter using credential-bearing URLSession; fix `08c171b` guards redirects. The audit itself records that deleting all provider commits leaves the human-introduced shared `ProviderHTTPClient` callers, and but-for/topology are `NARROW`. This is a new-surface contributor only, not transport origin. |
| GHSA-X9QH-W4C4-54F9 | KEEP | Claude Code commit `18f30b7f` first adds `buildHelperImage`, interpolating raw `dev_helper_version` into a Docker command; fix `dc9322b1` adds a strict tag regex and `escapeshellarg`. Local diff and ancestry support direct origin. |
| GHSA-F2FQ-4RMP-9X8C | WEAK | Claude commit `cbea916e` restores the 2FA/lockout gate but invalid OTP can throw without incrementing failed logins; `07be35d7`/`32599b3d` close that accounting residual. Release remains `NARROW`: the audit says the partial carrier is first in 7.3.1 while advisory wording says 7.5.1, and fix/tag placement needs canonical release replay. |
| GHSA-VVGP-4C28-M3JM | KEEP | Cursor commit `4a7b813a` adds trusted-proxy pairing skip; `ec45c317` requires the operator role. The prior independent release replay found npm 2026.2.24 contains carrier but not fix, and 2026.2.25 contains fix. The vulnerable hunk and fix invariant match the advisory. |
| GHSA-7F6V-3GX7-27Q8 | KEEP | Copilot member `3e176213` adds Swagger UI and embeds `stringifyJSON(swaggerConfig)` directly in a script; the fix escapes `<`, `>`, `&`, apostrophe, and slash in JSON before embedding. Squash member is absent from tags, but carrier `4f28b695` is in v1.8.3 and fix is in v1.13.9. This correctly handles member→carrier topology. |
| GHSA-5WP8-Q9MX-8JX8 | WEAK | Claude members add the shell allow/block boundary and empty-allowlist passthrough; `68916c3e` closes it. The audit itself records that the allowlist member is not an ancestor of the fix because a multi-purpose squash carrier lands it, leaving topology `NARROW`. Blob-equal transfer is plausible, but the row is not all-PASS strict. |
| GHSA-H4RQ-P45C-642R | WEAK | Claude member `4b0938dd` adds token Users API, but it inherits a pre-existing unvalidated `StoreUserRequest`; fix `84822f40` allowlists role for the shared request, including the older session surface. Audit counterevidence says removing the token controller leaves the same session API hole. Keep only a narrowed new-surface scope. |

Sample totals: 4 KEEP, 1 KEEP with classification error, 5 WEAK, 0 demonstrated
false positive. The dominant pattern is not fabricated AI causality; it is
over-broad GHSA-level counting for contributor/new-surface rows.

Independent parallel sample (5 rows, seed `260814`): 4 KEEP and 1 WEAK. The weak
case, GHSA-JX5R-P82P-2P8M, covers three GET-delete pages while the Claude candidate
adds only `FundRaiserDelete.php`; it must be counted at that one sub-mechanism, not
as the whole GHSA. A release caveat also remains for GHSA-FWPR-59HH-GR98: candidate
equals `v0.4.0`, no local tag contains the fix, and the advisory's affected/fixed
wording is contradictory.

Inference: sampling increases confidence that many core mechanisms are real, but
also confirms why the 74 NARROW rows cannot be silently upgraded to strict. The
most likely residual error mode is scope inflation, followed by topology/release
ambiguity—not absent AI identity.

## 4. True-positive misses and lane coverage

Concrete under-covered or mislabeled lanes:

1. **Non-GitHub-reviewed advisories.** The no-fix pool is 4,114/4,119 locally
   present under `github-reviewed`; a distinct unreviewed/global advisory harvest
   is needed.
2. **Advisories without AI terms.** `incremental.py:63` term-gates the delta.
   Add reverse routing: enumerate every new advisory's repo/fix, scan commit
   identities and relevant ancestry, then adjudicate. Advisory prose should not
   control recall.
3. **AI-authored fixes (1,688 local hits).** Mine them for AI incomplete
   remediation, bypassed AI security fixes, and fixes that expose an earlier AI
   origin. Never count fix AI identity alone.
4. **The 3,805 candidate ancestry rows outside file-overlap.** These are skipped by
   the overlap shortcut despite having a fix and AI ancestor. Dispatch by mechanism
   keywords/path distance, not filename equality alone.
5. **Ancestors older than 150 commits or before 2025-05-01.** Current scans impose
   both ceilings. Add bounded exceptions for repos/eras known to use AI tooling and
   for advisories whose vulnerable version window predates the cutoff.
6. **Multiple AI ancestors.** DR's single-ancestor rejection is too broad. Expand
   to all AI-changed paths sharing the fix invariant, ranked by hunk/path/mechanism.
7. **No-fix releases.** FWD requires a later local reversal, but many advisories
   disclose only versions or packages. Add package-version gitHead, wheel/sdist
   comparison, release manifests, and tags—not GitHub API use—to reconstruct fixes.
8. **AI identities absent from the narrow regex.** Explicit GitHub App identities
   (`claude[bot]`, Copilot agent), `Generated with` variants, Anthropic/OpenAI bot
   trailers, and repo-configured bot users need a versioned allowlist. Do not infer
   AI from style or generic `Co-Authored-By`.
9. **Fix refs currently skipped.** `incremental.py:65-68` takes only the first
   commit-looking reference and does not retain PRs as candidate member pointers.
   A PR can resolve to several members or a different carrier; preserve all refs.
10. **Repo-adjacent discovery.** Once one accepted row exists in a repo, enumerate
    adjacent security hunks and same-boundary residual bypasses (the sample found
    multiple OpenSSL Encrypt and PraisonAI cases sharing fixes/paths). This is a
    recall lane, not proof.
11. **Chain depth.** `ir-chains.jsonl` resolves only 44/51 originals and leaves 7
    UNKNOWN. Treat those as unresolved, not HUMAN; expand only where bounded git
    history and readable diffs justify it.

## Bottom line

- The strategy should remain local-evidence-first, but the first target is not 33
  more rows; it is a canonical split and verifier repair.
- The 7-gate contract is sound. `gate.py` and `leader_replay.py` implement only a
  small candidate-filter subset and are insufficient for admission.
- Ten-row sampling found 0 clear FPs, 5 weak rows, and one class-label error;
  a second five-row sample found 1 weak partial-GHSA row.
- To reach 200 safely, prioritize exact-hunk adjudication of the 753 overlap rows,
  all-AI-ancestor handling, package release containment, repo-adjacent lanes, and
  an unreviewed-advisory source. Do not count the existing 74 non-all-PASS rows.
