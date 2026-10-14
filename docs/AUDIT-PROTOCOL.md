# Audit protocol

Contract version: `2026-09-27.3`. Existing batches retain their frozen contracts.

N auditors independently research the same cases. Each auditor completes every step
below; do not divide the research chain between auditors. Work in a fresh context per
case and save your findings before reading any other auditor's report or prior verdict.
Use neutral primary sources, not another agent's conclusions. Retain every case.

For each step, state **what you conclude, what you observed, and where the evidence is**.
If a decisive fact is missing after the bounded probe, name it and the next question;
never fill a field by guessing. Execution failure is not a researched EVIDENCE_GAP.

[Data fields](DATA-SCHEMA.md#audit-records) define the output.
The local [research-work contract](DATA-SCHEMA.md#research-work-contract) separates
supported conclusions from unfinished investigation; record it in the owned sidecar.
[Audit commands](../scripts/README.md) cover claiming, dispatch and submission.
One adjudicator subsequently reviews all reports and completes unresolved research
under [ADJUDICATION-PROTOCOL](ADJUDICATION-PROTOCOL.md).

## Research steps

0. **Advisory status:** read the advisory record itself (CVE JSON in cveawg, OSV, GHSA)
   before the mechanism. State governs: a `REJECTED`, withdrawn or duplicate advisory is
   `FALSE_POSITIVE` and gets no mechanism work, and a live advisory whose own text
   contradicts its label is not thereby dead. A dead alias does not reject a live keyed
   advisory, and two identifiers referring to one vulnerability are not by themselves a
   false positive. A refuted mechanism or wrong-product report needs affirmative primary
   evidence and `false_positive_ground`; inability to establish the mechanism is
   `EVIDENCE_GAP`, never proof of `FALSE_POSITIVE`.
   For a supported FALSE_POSITIVE, causal introducer/repair fields are explicitly
   null (not applicable), as defined by DATA-SCHEMA. Preserve examined objects in
   evidence without assigning them vulnerability roles. An excluded advisory's
   disposition does not change the verdict of its broader live alias cluster.

1. **Cause:** trigger → vulnerable code → security impact, with preconditions and
   counterevidence. Separate distinct mechanisms.
   For resource-exhaustion claims, trace resource accounting from the controlled input
   through allocation or acquisition to release or reuse. Distinguish requested and
   returned lengths from allocated or retained capacity; inspect active limits,
   allocation tiers or pool classes and lifetimes at the affected revision. Bound
   per-operation and repeated-operation costs against legitimate use, without
   inventing runtime measurements.

2. **BIC:** the smallest logically atomic introducing change, which is not always the commit
   it landed in. `introducer_sha` is the atomic change, `landing_commit` the merge/squash
   object that carried it; compare its immediate parent, trace moves, and separate
   introduction from later exposure. Declare `bic_granularity`:

   - `ATOMIC`: the object is a logically atomic causal change, not its own `landing_commit`.
     One parent, an initial commit or a bulk-import label does not establish atomicity.
     A root tree can be the earliest observable boundary: identify the causal path/hunk and
     explain minimality in `landing_note`. Do not infer pre-import origin or authorship
     from that boundary. A known aggregate follows the next two rules.
   - `SQUASH_DECOMPOSED`: members reconstructable; list their 40-hex shas.
   - `AGGREGATE_MEMBERS_UNREACHABLE`: members still unavailable after one bounded PR-ref
     fetch. That probe is the terminus, not the start of a hunt: name the unreachable object
     (subject, path, epoch, first public appearance) and what would flip the read, then land
     the row as `BLOCKED`. For an import without a PR, record the authoritative source-history
     probe and its limit. Push counts and missing public events alone cannot establish
     content identity, atomicity or the absence of earlier history.
   - `NON_GIT_BOUNDARY`: the change predates VCS, so `introducer_sha` is null.

   Membership is located by content identity (`--find-object`, pickaxe on the introduced
   blob), never by PR number or title: the object that landed the content is a carrier, not a
   member, and a member whose added lines the landing tree does not carry is a candidate from
   another epoch. An aggregate's trailers, co-authors and badges belong to the aggregate, not
   to a hunk: they are never BIC attribution. If history is unavailable, isolate the causal
   diff and say what that costs commit-level minimality.

   Compare behavior in the immediate parent and child, not just the first pickaxe hit.
   Check shallow boundaries before treating a root or a failed ancestry walk as evidence.
   Missing local objects are not proof that public history is unavailable: distinguish a
   commit, its trees/blobs and the product repository from a reporter or umbrella clone.
   Recover missing objects through one bounded authoritative probe in an owned scratch
   clone, preserving shared read-only clones; retain its command and output. If the BIC
   itself is unknown, use the explicit nulls allowed for open records by DATA-SCHEMA.

3. **Fix:** the minimum repairing hunks/commit set and why it closes the defect; follow
   partial repairs through the residual defect to closure; verify affected/fixed versions
   separately, and substantiate an unpatched state plus a proposed repair when no fix exists.
   `fix_sha` is the first mechanism-closing change on the default branch, not whichever
   landing a lane named. If a side-branch repair reaches the default branch through a
   merge, identify that integration and compare its default-branch parent with the merged
   content. Later ancestry alone does not make the side-branch commit the default-branch
   closure; retain its member and other landing roles separately. Fix-side AI is informational: it never substitutes for BIC-side
   attribution, and a fix-side marker alone does not move the verdict. If the remediation is
   partial, or a claimed patched release does not contain the fix, `remaining_gap` names the
   still-open surface and its closing commit, or none.

4. **AI:** tie AI evidence to causal changes across the history, within its disclosed scope,
   and record how it was admitted (`ai_admissibility`): first establish that the named object
   carries the causal change at the claimed granularity, then read its actual marker.
   A first-party disclosure bound to that causal change is admissible once the
   record says what binds it; repository-level AI activity, changelog habits, labels and org
   policy are never admissible. A TP needs demonstrated AI contribution to the defect:
   introduction, new exposure or incomplete remediation can qualify after a human BIC, and a
   successful repair alone does not. `NOT_AI` needs a recovered named human/organization
   identity on the BIC object, no marker on that object, and a spot check of the repo's
   disclosure convention at that date - a placeholder, anonymous or unresolvable identity is
   `EVIDENCE_GAP`, not `NOT_AI`. Label definitions: [DATA-SCHEMA](DATA-SCHEMA.md).
   "No marker" is a statement about every local object that carries the causal content,
   including commits no ref reaches (a pre-force-push iteration of the same PR keeps its
   trailer while the landed squash drops it): enumerate local commit objects with
   `git cat-file --batch-all-objects --batch-check`, filtering for commits. Compare
   their trees at relevant historical paths for the exact causal blob or supported
   hunk, then read every matching commit's full metadata. `--find-object` and pickaxe
   select content transitions, not unchanged descendants; neither proves complete
   carrier coverage. Retain the inspected object and path universe. A marker found
   there attributes the content only once the record shows the same blob or hunk on both
   objects; a shallow or promisor clone with no such objects is a clone-state gap, not
   evidence of absence.

   Preserve the exact marker quote and its SHA/source. Read BIC and fix metadata separately;
   never copy a fix's trailer into the BIC evidence. A quote on an aggregate does not become
   hunk attribution merely because the record labels the aggregate ATOMIC.

5. **Evidence:** retain a per-case report and primary-source snapshots with exact SHAs,
   paths/hunks, URLs and capture dates; explain comparisons, counterevidence and how
   uncertainties affect the conclusion. State `flip_condition`: what evidence would change
   the verdict. Report, evidence and `remaining_gap` must agree: never carry a closed verdict
   while the record's own evidence names an unclosed path.

   For each decisive claim retain the command/URL, repository and full object SHA, capture
   time, exit code and raw-output file. Distinguish observed facts from inferred causal
   judgments. The minimum evidence covers mechanism, parent/child behavior, AI provenance,
   repair or confirmed unpatched state, and affected/fixed release membership. "Verified"
   and a PASS field without the underlying observation do not satisfy this requirement.

Finish with a per-case report covering advisory, mechanism, BIC/landing, AI provenance,
fix, versions and residual/flip condition. Link each conclusion to its decisive receipt.
Keep observations separate from inferences. Missing evidence is a qualified research
outcome; a passed format check does not make the conclusion correct.
