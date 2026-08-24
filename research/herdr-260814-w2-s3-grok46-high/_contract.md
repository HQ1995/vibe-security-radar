# GHSA 200+ Causal-Case Acceptance Contract

## Objective

Build a claim-grade ledger of more than 200 unique GHSA cases in which an
AI-authored atomic change directly introduced, materially contributed to,
reintroduced, or incompletely remediated the advisory's vulnerable mechanism.
The count is by first-party GHSA case, not by CVE alias, commit, edge, or report
row.

## Frozen starting point

- Baseline audit: `autoresearch/orchestrator-260813-fp211-audit/`
- Canonical overlay: `autoresearch/orchestrator-260813-fp211-canonical/`
- 211 mechanism hypotheses and 212 GHSA cases
- 65 `CONFIRM`, 84 `NARROW`, 54 `FALSE_POSITIVE`, and 9 `UNKNOWN` cases
- 149 causal-valid cases at their current scope; 51 `CONFIRM` mechanisms have
  `HIGH` confidence and all gates closed; only 48 also have released
  containment and therefore satisfy this contract's starting lower bound
- Reaching more than 200 strict released GHSA cases requires at least 153 net
  new admissions from upgrades and fresh discoveries
- The existing 200-case claim is explicitly unsupported

## Countable case

A case is countable only when all seven gates are `PASS` for the exact scope
being counted:

1. `identity_gate`: a first-party GHSA object names the affected repository,
   mechanism, and public identity; withdrawn or cross-bound identities are not
   counted.
2. `ai_hunk_gate`: an atomic commit with an explicit AI marker authors the
   relevant vulnerable hunk. PR branding, a later AI review, or an AI carrier
   is insufficient.
3. `topology_gate`: carrier, squash member, import, reintroduction, and fix
   ancestry are resolved without transferring authorship across commits.
4. `but_for_gate`: for origins and contributors, removing the AI change
   eliminates or materially shrinks the exact scoped mechanism. Preserving an
   old bug or merely moving code fails. Incomplete remediation uses the
   patch-delta rule below instead of requiring rollback to eliminate the older,
   broader vulnerability.
5. `fix_reversal_gate`: the minimum first-party fix or fix closure reverses the
   same invariant. A nearby security commit or incomplete reversal fails.
6. `release_gate`: a vulnerable released artifact contains the AI contribution
   and a fixed released artifact contains the reversal.
7. `uniqueness_gate`: the GHSA case is not already counted for the same
   mechanism. Shared SHAs do not imply duplication, and different aliases do
   not imply distinct cases.

`AI_INCOMPLETE_REMEDIATION` is countable under a patch-delta rule. The original
vulnerability need not be AI-origin, and reverting the AI patch may reopen a
broader old vulnerability. The gate passes only when all of the following are
proved:

- the AI-authored change is an explicit security attempt that introduces or
  materially rewrites a guard, parser, normalizer, denylist, allowlist, or
  equivalent security boundary;
- a released artifact contains that attempted remediation without the final
  closure;
- the first-party GHSA explicitly covers a residual bypass in that boundary;
- the later same-mechanism fix directly amends the AI-added boundary to cover
  the omitted case; and
- the residual is not merely an untouched sibling path or unrelated old hole.

Rollback reopening the broader parent vulnerability is not, by itself, a
failure for this class. A fix to surface A followed by an unrelated fix to
pre-existing surface B is not incomplete-remediation causality. The row must
be labeled `AI_INCOMPLETE_REMEDIATION`, not `AI_DIRECT_ROOT`, and still satisfy
identity, AI-hunk, topology, fix-reversal, release, and uniqueness gates.

`AI_NEW_SURFACE_CONTRIBUTOR` and necessary-chain cases are countable only at an
explicit narrowed scope with a demonstrated material delta. Routing signals
such as OSV `introduced`, advisory references, ancestry, commit subjects, or
model votes are never causal proof.

## Worker output contract

Each worker owns only its assigned directory and must create English-only:

- `result.json`: terminal status, input hashes, counts, and blockers
- `cases.jsonl`: one row per reviewed GHSA case
- `report.md`: verdict-first evidence summary
- `replay.txt`: commands sufficient to reproduce every proposed acceptance

Every `PASS` row must contain `case_id`, `aliases`, `repository`,
`mechanism_key`, `scope_statement`, `contribution_class`, `candidate_set`,
`carrier_set`, `minimum_fix_set`, vulnerable/fixed release evidence, all seven
gate values, first-party source references, exact AI marker evidence,
counterevidence, replay commands, and a baseline-overlap disposition.

Workers must preserve `NARROW`, `UNKNOWN`, `BLOCKED`, and `REJECT`. They must not
edit existing tracked files, canonical ledgers, publication data, or other
workers' directories; must not commit or push; and must not print credentials.

## Leader acceptance

Worker `PASS` is a proposal, never admission. The leader will independently
verify source identity, replay Git topology and release containment, compare
mechanism fingerprints against all accepted cases, and run an adversarial
review before rebuilding a canonical ledger. The objective is complete only
when the final verifier proves more than 200 unique released GHSA cases with
all seven gates closed and no unresolved counting ambiguity.
