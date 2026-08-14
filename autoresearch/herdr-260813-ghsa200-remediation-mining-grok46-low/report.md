# Remediation-mining GHSA discovery (grok46-low)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc` via commitfirst-gn freeze. Shared tracked files were not edited. No commit, push, or credential output.

## Provenance (frozen vs current, separate roles)

Frozen selection and exclusion inputs were not re-derived from live publication files.

- Frozen: contract, 48-case baseline, fp211 ledger/mechanisms/public_cases, final-review packet, commitfirst-gn assignment/intersections. See result.json frozen_input_hashes.
- Current overlap check only: live scripts/publication_adjudications.json, netred 21 KEEP cases, Actual/Gogs cases.jsonl, B3 notes/package-to-source.json. These hashes do not rebuild the frozen denominator.

Excluded identities: frozen 48 baseline; netred 21 KEEP; Actual/Gogs GHSA-7GH7-258J-4MPQ, GHSA-6P9M-Q3JP-47H4, GHSA-XQJM-27PC-RVWM; B3 KEEP set empty on disk.

## Pattern

High-precision incomplete remediation: an AI-marked commit explicitly attempts a security rem; a later first-party GHSA/fix closes a residual bypass in that same helper; a vulnerable release contains the AI candidate and a fixed release contains the closure. Count by GHSA identity once. Routing is not causality.

## Verdict

Thirty identities were deeply reviewed. Zero closed all seven gates.

Closest misses:

- GHSA-6CQF-375W-639G / GHSA-3PWW-VCVM-3GMJ: Claude 33923a4d (#37698) remediates download token scope. The GHSA residual is RSS/Atom sibling handlers. Advisory text says sibling. but_for_gate FAIL.
- GHSA-6X6H-QQR7-855W: Claude CORS rem chain exists, but PyPI 1.5.3 still has the parent wildcard; 1.5.4 ships the completed helper. No released residual of the AI rem.
- GHSA-7F8R-222P-6F5G: Claude header rem is after the GHSA merge.
- Exact SHA intersections in frozen G-N scans are almost all AI-marked closures (remediation-as-origin).

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 30 |

High-confidence incomplete-language plus exact-ref rem queue for this pattern is exhausted at 30. Remaining first-party GHSAs are UNREVIEWED, not REJECT.

## Claim boundary

Countable PASS requires all seven gates and leader admission. Proposed PASS: 0. Publication remains HOLD. This packet does not support a >200 claim.
