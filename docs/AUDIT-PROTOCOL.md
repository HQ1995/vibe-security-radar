# Audit protocol

Research each advisory's cause, smallest BIC, minimum fix and AI role. Retain every
case, whatever the verdict.

One fresh-context subagent owns each case; parallelize within host limits. Supply
this protocol, the linked schema and primary sources. Save independent findings
before reading prior verdicts. Prefer local Git and GitHub patch/raw/PR pages;
avoid GitHub API requests while rate-limited.

## Claiming cases

Claim before working a case; one writer per `(class_id, slot)`.

```bash
python3 scripts/claims.py pick  --owner <agent> --scope <batch> --limit N  # next N unclaimed cases
python3 scripts/claims.py pick  --owner <agent> --scope <batch> --class-id-file <ids>  # only that batch
python3 scripts/claims.py claim --class-id <id> --owner <agent>            # one known case
python3 scripts/claims.py list  --scope <batch>                            # who holds what
python3 scripts/claims.py done  --class-id <id> --owner <agent> --result <verdict>
python3 scripts/claims.py release --class-id <id> --owner <agent>          # hand back
```

`pick` claims the next unclaimed cases in ledger order and is atomic, so concurrent
pickers never receive the same case. Records go to the append-only
`artifacts/claims/claims.jsonl`: coordination data, never exported to the ledger or the
site, committed by the leader with the batch. `--scope` is the batch label and `--slot`
(default `main`) the auditor, so one batch in several slots means several independent
audits. Leases last 24h unless `--hours` overrides; an expired claim reads `STALE` and a
takeover records `supersedes`. `first_claimed_at` survives both and is how long a case
has been in flight. Keep each case's report in the batch's research directory and
`done` it with the verdict.

A batch is a file: `class_id` lines, or a round's `assessments-*.jsonl`, whose rows carry
`class_id`. That path plus `--scope` is the identifier to hand a worker; membership lives in the
file, so every picker reads the same batch.

## Handing a case to a worker

This file is the method, not the assignment. A spawned worker also needs, in its own prompt:

- its scope, batch file (class_id lines or a round's `assessments-*.jsonl`), case ids or
  `pick --scope <batch> --limit N`, and its `--slot`;
- the neutral evidence: advisory URL, local checkout, primary patch/raw/PR pages;
- its output directory (`research/<batch>/<case>/`) for the report and snapshots;
- boundaries: no ledger writes, no `web/`, no other agent's files; report an evidence gap
  instead of guessing;
- close-out: `claims.py done --class-id <id> --owner <agent> --slot <slot> --result <verdict>`.

### Independent re-audit

Same assignment in a different `--slot` and output directory, plus the blind rule: do not read
the first pass's report, dossier or ledger verdict until your own verdict is written down. Then
compare and state agreement or disagreement, the decisive evidence, and what evidence would flip
your verdict. Re-derive the classification or report the gap; a copied verdict is not a result.

1. **Cause:** Explain trigger → vulnerable code → security impact, including
   preconditions and counterevidence. Separate distinct mechanisms.
2. **BIC:** Find the smallest original introducing change and compare its immediate
   parent; trace moves and separate introduction from later exposure. For BIC and fix,
   decompose merge/squash history into logically atomic causal changes across PR members
   and hunks/files; distinguish landing commits from those changes. If history is
   unavailable, isolate the causal diff and state the limit on commit-level minimality.
3. **Fix:** Identify the minimum repairing hunks/commit set and explain why it closes
   the defect. Follow partial repairs through the residual defect to closure.
   Verify affected/fixed versions separately; substantiate an unpatched state and
   propose a repair when no fix exists.

   Record the fix side explicitly and consistently:
   - Set fix_ai_marker (state PRESENT/ABSENT/UNKNOWN with per-sha evidence) on the
     fix commit objects. Fix-side AI is informational: it never substitutes for
     BIC-side attribution, and a fix-side marker alone does not change the verdict.
   - If the remediation is partial or a claimed patched release does not contain
     the fix, set remaining_gap and name the still-open surface plus closing commit
     (or none). When evidence/reasoning already uses wording like "remains unbounded",
     "still ships", "not closed", "residual", or "incomplete remediation", remaining_gap
     must not be empty; keep the record consistent with its own evidence.
4. **AI:** Tie AI evidence to causal changes throughout the history, within its
   disclosed scope. A TP requires demonstrated AI contribution to the defect:
   introduction, new exposure or incomplete remediation can qualify after a human
   BIC. Successful repair alone does not qualify; unknown does not mean `NOT_AI`.
   Keep the verdict consistent with this account.

   Record fix_ai_marker on the fix itself, keeping BIC-side and fix-side attribution
   distinct. Placeholder identities (*@localhost, test@test.com, generic Test <...>) are
   not named-human proof and are not commit-object AI attribution; leave EVIDENCE_GAP
   unless a positive marker or recovered named identity closes the case.

   On the BIC side write ai_on_bic as a boolean; omit the field when the marker is
   not established, so an absent read and a negative read stay distinguishable.
   Never write "no", "none" or "unknown" as its value: a non-empty string reads as
   true downstream.
5. **Evidence:** Retain a per-case report and primary-source snapshots with exact
   SHAs, paths/hunks, URLs and capture dates. Explain comparisons, counterevidence,
   uncertainties and their effect on conclusions. Complete available decisive
   checks; preserve findings and explain revisions.

   The per-case report and remaining_gap must agree with the evidence: if the evidence
   shows a residual open surface, say so in the report and in remaining_gap; do not carry
   a closed verdict while the record's own evidence names an unclosed path.

Review causal conclusions before ledger updates or publication; saved reports and
passing format checks do not establish correctness. Keep a batch index of outcomes
and remaining gaps. Follow the [data schema](DATA-SCHEMA.md) and
[write boundaries](../AGENTS.md).
