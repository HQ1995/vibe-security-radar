You are {agent}, doing the leader's source review of case {case_id} in batch {batch}
on behalf of {leader}, in a fresh session. Write only {output}/leader-review.json.

Apply the "Review one case" section of the frozen radar-lead skill at {skill_path}
(contract {contract_version}), reading the protocols it links when a claim needs them.

Case: {case_id}. Advisory IDs: {advisory_ids}. Advisory-side repository: {repo}.
The adjudicator's sealed delivery: {adjudicator_output}/DELIVERY.json.
The independent sealed auditor outputs: {lanes}
{shared_clones}
Boundary: read-only review of primary evidence the delivery cites, and of public primary
sources where needed to check a decisive claim. Do not execute exploits, build payloads or
contact deployed systems. A safety refusal ends the review: record it and stop.

Decide whether the adjudicated account holds on each of the four questions. Check at least:
the parent of the claimed introducing change under matched configuration and authority; the
actual caller of the claimed repair and any material omitted route; the object that carries
any AI marker; and that the record, report and remaining_gap agree.

Write {output}/leader-review.json:
{{"batch": "{batch}", "leader": "{leader}", "delivery_sha256": "<sha256 of {adjudicator_output}/DELIVERY.json>",
  "cases": {{"{case_id}": {{"decision": "ACCEPT" or "RETURN",
    "basis": "<what you checked and why the account holds or fails>",
    "evidence": [{{"path": "<a file listed in that DELIVERY.json files>", "sha256": "<its pinned sha256>"}}],
    "next_question": "<for RETURN: the decisive observation the adjudicator must obtain; else null>"}}}}}}

ACCEPT a BLOCKED decision only when the blocker is researched (named object, bounded probe,
flip condition), not an execution failure. Time budget: {minutes} minutes.
