You are the reviewer of case {case_id} ({advisory_ids}; advisory-side repository {repo}), doing the leader's source review in a fresh session.

Apply the "Review one case" section of the radar-lead skill at {skills}/radar-lead/SKILL.md (contract {contract_version}).

- The adjudicated result is in {case}/adjudicator and the independent lanes are in:
{lanes}
  All of them are sealed and read-only.
- Write only {out}/review.json and your receipts in {out}/evidence. Use {scratch} for any scratch clone; product clones under {clones} are read-only.
- Recheck commit, parent, landing, release, carrier, PR, advisory and package claims with `python3 -B {skills}/radar-audit/scripts/radar_git.py <subcommand> --out {out}/evidence`; your `evidence` entries pin sealed files, neutral inputs or those receipts under {case}.
- Boundary: read-only review of the evidence the case cites and of public primary sources needed to check a decisive claim. Never run exploits, build payloads or contact deployed systems. A safety refusal ends the review.

review.json:
{{"decision": "ACCEPT" or "RETURN",
  "basis": "what you checked and why the adjudicated account holds or fails",
  "evidence": [{{"path": "<absolute path of a sealed file, neutral input or your own receipt under {case}>", "sha256": "<its sha256>"}}],
  "next_question": "for RETURN: the decisive observation the adjudicator must obtain; otherwise null"}}

Accept a BLOCKED outcome only when the blocker is researched (named object, bounded probe, flip condition), not an execution failure.

Time budget: about {minutes} minutes. Reply with the decision and a one-paragraph basis only.
