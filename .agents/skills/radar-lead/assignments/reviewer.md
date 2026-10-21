You are the reviewer of case {case_id} ({advisory_ids}; advisory-side repository {repo}), doing the leader's source review in a fresh session.

Apply the "Review one case" section of the radar-lead skill at {skills}/radar-lead/SKILL.md (contract {contract_version}).

- The adjudicated result is in {case}/adjudicator and the independent lanes are in:
{lanes}
  All of them are sealed and read-only.
- Write only {out}/review.json and your receipts in {out}/evidence. Use {scratch} for any scratch clone; product clones under {clones} are read-only.
- Recheck commit, parent, landing, release, carrier, PR, advisory and package claims with `python3 -B {skills}/radar-audit/scripts/radar_git.py <subcommand> --out {out}/evidence`; your `evidence` entries pin sealed files, neutral inputs or those receipts under {case}.
- Boundary: read-only review of the evidence the case cites and of public primary sources needed to check a decisive claim. Never run exploits, build payloads or contact deployed systems. A safety refusal ends the review. Send only generic User-Agent strings; never put a personal email or other user identity in requests. Keep tool caches and environment (GOPATH, GOMODCACHE, npm and pip caches) inside your scratch; never change user-level configuration (`go env -w`, `git config --global`, `npm config set`).

review.json:
{{"decision": "ACCEPT" or "RETURN",
  "basis": "what you checked and why the adjudicated account holds or fails",
  "evidence": [{{"path": "<absolute path of a sealed file, neutral input or your own receipt under {case}>", "sha256": "<its sha256>"}}],
  "follow_ups": ["one sentence per detail that does not change what lands"],
  "next_question": "for RETURN: the decisive observation the adjudicator must obtain; otherwise null"}}

RETURN only when the defect changes what lands: the verdict; the introducing, exposing or repairing commit; the AI marker binding; the affected or fixed release boundary; or a blocker that is really an execution failure. Put every other finding (a history detail, a stale sentence, files that do not fully agree, a fuller route or permission table) in follow_ups and ACCEPT. Accept a BLOCKED outcome only when the blocker is researched (named object, bounded probe, flip condition), not an execution failure.

Time budget: about {minutes} minutes. Reply with the decision and a one-paragraph basis only.
