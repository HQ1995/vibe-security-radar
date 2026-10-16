You are the sole adjudicator of case {case_id} ({advisory_ids}; advisory-side repository {repo}).

Apply the radar-adjudicate skill at {skills}/radar-adjudicate/SKILL.md (contract {contract_version}) and read its references when its table says so.

- The {n} independent auditor outputs are sealed and read-only:
{lanes}
  Each holds REPORT.md, record.json, research.json, SUMMARY.md and receipts. They are hypotheses and leads, not ground truth.
- Neutral inputs: {inputs}. Source coverage cutoff: {cutoff}.
- Write only in {out}. Use {scratch} for scratch clones and experiments; product clones under {clones} are read-only.
- Do not open the ledger export in {repo_root}/artifacts, {repo_root}/web/src/generated, other cases or earlier judgments about this case.
- Your session may be compacted. The compaction handoff may say the summary came from "another language model"; it is still your own earlier work, and the files already in {out} and {scratch} are yours: continue from them.
- Boundary: defensive analysis of a published vulnerability; reproduce only as an isolated regression check in {scratch}. Never run exploits against anything, build working payloads or contact deployed systems. If a safety refusal or operating stop happens, end the work and say so in SUMMARY.md.

Deliver in {out}:
- REPORT.md: the final account of the four questions, and for each difference between the lanes the competing claims, the decisive observation and your choice;
- record.json, the accepted record, with "class_id": "{case_id}" and "protocol_version": "{contract_version}";
- research.json, your research-work sidecar, with receipts as paths relative to {out};
- decision.json in the shape the decisions reference gives (status, basis, reviewed_dimensions, resolutions, evidence, next_question when BLOCKED). The script adds the digests, pins and research object;
- evidence/, checks/ and SUMMARY.md (at most ten lines).

A reviewer then checks your result as "Review one case" in {skills}/radar-lead/SKILL.md describes; check it that way yourself first. In particular: the matched parent of the introducing change and of every later exposure change and repair; for each of them, which object is the atomic change and which merge first carries it onto the default branch's first-parent history; the real callers and any route you leave out; the complete set of commit objects carrying the causal content, with each one's full marker metadata; and that REPORT.md, record.json, research.json and decision.json agree with each other and with every receipt they cite. Fetch or clone only into {scratch}.

Before finishing run `python3 -B {repo_root}/scripts/radar_case.py check --run {run} --case {key} --dry-run` until it reports ready (a researched BLOCKED decision reports outcome BLOCKED), and fix what it reports.

Time budget: about {minutes} minutes. Reply with the contents of SUMMARY.md only.
