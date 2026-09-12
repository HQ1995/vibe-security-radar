# Audit protocol

Research each advisory's cause, smallest BIC, minimum fix and AI role. Retain every
case, whatever the verdict.

One fresh-context subagent owns each case; parallelize within host limits. Supply
this protocol, the linked schema and primary sources. Save independent findings
before reading prior verdicts. Prefer local Git and GitHub patch/raw/PR pages;
avoid GitHub API requests while rate-limited.

## Claiming cases

Claim before working a case; one writer per `(class_id, slot)`. `pick` claims the next
unclaimed cases in ledger order and is atomic, so concurrent pickers never receive the
same case. Command list and record location: [AGENTS.md](../AGENTS.md). `--scope` is the
batch label and `--slot` (default `main`) the auditor, so one batch in several slots
means several independent audits. Leases last 24h unless `--hours` overrides; an expired
claim reads `STALE` and a takeover records `supersedes`. `first_claimed_at` survives both
and is how long a case has been in flight.

A batch is a file: `class_id` lines, or a round's `assessments-*.jsonl`, whose rows carry
`class_id`. That path plus `--scope` is the identifier to hand a worker; membership lives
in the file, so every picker reads the same batch.

## Worker brief

Both slots of a re-audit get the same brief; only `<slot>` and `<outdir>` differ. It names:

- claim: `scripts/claims.py pick --owner <agent> --scope <batch> --slot <slot> --limit N`
  (or `claim --class-id X`), then `done --class-id <id> --owner <agent> --slot <slot>
  --result <verdict>` on close-out;
- the case ids and `<outdir>/<class_id>/` for the report and primary-source snapshots;
- neutral evidence only: advisory URL, local checkout, primary patch/raw/PR pages, no prior
  verdict, dossier or the other slot's output;
- boundaries: no ledger writes, no `web/`, no other agent's files, and `EVIDENCE_GAP` rather
  than a guess.

Blind re-audit: the same brief in a different `--slot` and output directory. Do not read the
first pass's report, dossier or ledger verdict until your own verdict is written down. Then
state agreement or disagreement, the decisive evidence, and what evidence would flip your
verdict. A copied verdict is not a result. Compare the slots with
`scripts/compare_slots.py --a <slotA> --b <slotB>`.

0. **Advisory status:** read the advisory record itself (CVE JSON in cveawg, OSV, GHSA)
   before the mechanism. A `REJECTED`, withdrawn or duplicate advisory is
   `FALSE_POSITIVE` and gets no mechanism work. Every record carries
   `advisory_disposition`: `ACTIVE`, `WITHDRAWN`, `REJECTED`, `DUPLICATE`, `UNKNOWN`.

1. **Cause:** Explain trigger → vulnerable code → security impact, including
   preconditions and counterevidence. Separate distinct mechanisms.

2. **BIC:** Find the smallest logically atomic introducing change, which is not always the
   commit it landed in. `landing_commit` is the merge/squash object that carried it;
   `introducer_sha` is the atomic change. Compare its immediate parent; trace moves and
   separate introduction from later exposure. Declare `bic_granularity`:
   - `ATOMIC`: the commit object is the change, so it is not its own `landing_commit`;
   - `SQUASH_DECOMPOSED`: a squash whose members are reconstructable; list their 40-hex
     shas in `decomposed_shas`;
   - `AGGREGATE_MEMBERS_UNREACHABLE`: members still unavailable after one bounded PR-ref
     fetch (`git fetch origin pull/<N>/head`); record the command and what it returned in
     `decomposition_probe`;
   - `NON_GIT_BOUNDARY`: the change predates VCS (SVN/CVS), so `introducer_sha` is null.

   An aggregate commit's trailers, co-authors and badges belong to the aggregate, not to a
   hunk: they are never BIC attribution. If history is unavailable, isolate the causal diff
   and state the limit on commit-level minimality.

3. **Fix:** Identify the minimum repairing hunks/commit set and explain why it closes the
   defect. Follow partial repairs through the residual defect to closure. Verify
   affected/fixed versions separately; substantiate an unpatched state and propose a repair
   when no fix exists.

   - Set `fix_ai_marker` (state PRESENT/ABSENT/UNKNOWN with per-sha evidence) on the fix
     commit objects. Fix-side AI is informational: it never substitutes for BIC-side
     attribution, and a fix-side marker alone does not change the verdict.
   - If the remediation is partial or a claimed patched release does not contain the fix,
     set `remaining_gap` and name the still-open surface plus the closing commit (or none).
     When the evidence already says "remains unbounded", "still ships", "not closed",
     "residual" or "incomplete remediation", `remaining_gap` must not be empty.

4. **AI:** Tie AI evidence to causal changes throughout the history, within its disclosed
   scope, and record how the evidence was admitted (`ai_admissibility`):
   - a marker on the BIC object itself (trailer, co-author, bot author) is decisive;
   - a first-party disclosure bound to that causal change (PR body, release note) is
     admissible once the record says what binds it;
   - repository-level AI activity, changelog habits, labels and org policy are never
     admissible.

   A TP needs demonstrated AI contribution to the defect: introduction, new exposure or
   incomplete remediation can qualify after a human BIC; a successful repair alone does not.
   Label definitions: [DATA-SCHEMA](DATA-SCHEMA.md). When both slots agree on the BIC and
   differ only on the label, ask which change carries the defect, not which one is nearest.

   On the BIC side write `ai_on_bic` as a boolean, or omit it when the marker is not
   established, so an absent read and a negative read stay distinguishable. Never write
   "no", "none" or "unknown" as its value: a non-empty string reads as true downstream.
   `NOT_AI` needs a recovered named human/organization identity on the BIC object, no marker
   on that object, and a spot check of the repo's AI-disclosure convention at that date.
   Reserve `EVIDENCE_GAP` for missing history, a placeholder identity, or an unresolvable
   object. Placeholder identities (*@localhost, test@test.com, generic Test <...>) are not
   named-human proof and not commit-object AI attribution.

5. **Evidence:** Retain a per-case report and primary-source snapshots with exact SHAs,
   paths/hunks, URLs and capture dates. Explain comparisons, counterevidence, uncertainties
   and their effect on conclusions. State `flip_condition`: what evidence would change the
   verdict. Report, evidence and `remaining_gap` must agree; never carry a closed verdict
   while the record's own evidence names an unclosed path.

Check a record before landing it:
`python3 scripts/audit_record_gates.py --strict research/<batch>/<case>.json`. Review causal
conclusions before ledger updates or publication; saved reports and passing format checks do
not establish correctness. Keep a batch index of outcomes and remaining gaps. Follow the
[data schema](DATA-SCHEMA.md) and [write boundaries](../AGENTS.md).
