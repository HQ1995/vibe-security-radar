# K-N commit-first GHSA discovery (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0.**

Worker PASS is a proposal only. This shard proposes no admissions.

Bound to leader `CONTRACT.md` SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc` from commitfirst-gn freeze.
Independence: first-party github-reviewed JSON, frozen G-N assignment/scans, and clones under `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones` only. Sibling worker conclusions were not used as causal evidence. Shared tracked files were not edited. No commit, push, or credential output.

## Provenance (two hashes, two roles)

The reviewed population is the frozen G-N novel assignment. It is **not** re-derived from the current publication file.

- **Frozen selection input:** `publication_adjudications.json` SHA-256 `bfec060f7705014d11e58dc386294264eac47027cd64d3b934a17422bb1be7a6`, taken from commitfirst-GN `freeze.json` / `assignment-manifest.json`. That is the upstream exclusion hash used to build `assigned.jsonl`.
- **Current overlap check:** live `scripts/publication_adjudications.json` SHA-256 `9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f` after commit `5620e01`, verified on disk. None of the 30 reviewed GHSA identities appear in that live adjudications GHSA set. This check does not change the frozen denominator.

## Verdict

Thirty K-L-M-N first-party GHSA identities were ranked mechanically from frozen AI-commit scans intersected with advisory-cited fix files, then reviewed against all seven gates. None closed every gate.

Exact advisory-SHA AND AI-commit intersections remaining in this K-N unreviewed slice: **0** (those identities were already reviewed in commitfirst-gn and excluded as prior cases). File-overlap ranking is routing, not proof. Remaining K-N assignment rows are **UNREVIEWED**, not REJECT.

## Assignment conservation

Owner rule: first character of repository owner, casefolded, in K-N inclusive, inside the frozen G-N novel assignment.

| Set | Count |
|---:|---:|
| G-N assigned (frozen novel) | 2577 |
| K-N assigned | 1505 |
| G-J remainder of G-N assigned | 1072 |
| K-N already reviewed in commitfirst-gn or final-review identities | 54 |
| K-N explicitly unreviewed before this shard | 1451 |
| Deep-reviewed here | 30 |
| Remaining UNREVIEWED | 1421 |

Proven equalities:

- 1505 + 1072 = 2577
- 54 + 1451 = 1505
- 30 + 1421 = 1451

First-party window partition from freeze (A-F 2423, G-N 2623, O-Z 3680, other 31) still sums to 8757. This shard does not re-parse advisories.

## Selection

Deterministic rank on the 1451 unreviewed K-N rows:

1. exact AI SHA ∩ advisory commit ref (none left)
2. unique advisory-fix SHA cluster
3. density = (frozen AI commits on advisory-fix files excluding cited SHAs) / file count
4. GHSA id tie-break

Top 30 unique fix-SHA clusters were reviewed. n8n 79-file megapatches were not duplicated across sibling GHSAs.

## Terminal outcomes (reviewed)

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 30 |
| UNREVIEWED (not in cases.jsonl as closed gates) | 1421 |

### Closest incomplete-remediation miss

**GHSA-8359-H9FX-J6V9** (`koxudaxi/datamodel-code-generator`): Claude-marked `f6d4cbd3440a` adds `--allow-remote-refs` for HTTP(S) `$ref` and documents that `file://` stays allowed. The GHSA is local `file://` / `../` read. Later unmarked `2ff4a72b4550` adds local path containment. That is surface B (pre-existing local refs), not residual bypass of the AI HTTP gate. `ai_hunk_gate` PASS on the HTTP guard; `but_for_gate` and incomplete-remediation patch-delta FAIL. Clone has no tags, so `release_gate` stays UNKNOWN.

All other reviewed rows fail `ai_hunk_gate` and/or `but_for_gate`: advisory SHAs are unmarked fixes; frozen AI hits on those files are unrelated ancestors, TypeScript moves, Copilot one-line suggestions, or post-hoc hardening of a different GHSA.

## Claim boundary

- Countable PASS requires all seven gates and leader admission.
- Proposed PASS: **0**. Countable PASS: **0**.
- REJECT here is only for the 30 reviewed identities. Absence of review for the other 1421 K-N rows is not negative proof.
- OSV `introduced`, subject tokens, and file overlap are routing only.
