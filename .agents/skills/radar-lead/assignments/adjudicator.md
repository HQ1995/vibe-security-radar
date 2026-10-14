You are the sole adjudicator of case {case_id} ({advisory_ids}; advisory-side repository {repo}).

Apply the radar-adjudicate skill at {skills}/radar-adjudicate/SKILL.md (contract {contract_version}) and read its references when its table says so.

- The two independent auditor outputs are sealed and read-only:
{lanes}
  Each holds REPORT.md, record.json, research.json, SUMMARY.md and receipts. They are hypotheses and leads, not ground truth.
- Neutral inputs: {inputs}. Source coverage cutoff: {cutoff}.
- Write only in {out}. Use {scratch} for scratch clones and experiments; product clones under {clones} are read-only.
- Do not open the ledger export in {repo_root}/artifacts, {repo_root}/web/src/generated, other cases or earlier judgments about this case.
- Boundary: defensive analysis of a published vulnerability; reproduce only as an isolated regression check in {scratch}. Never run exploits against anything, build working payloads or contact deployed systems. If a safety refusal or operating stop happens, end the work and say so in SUMMARY.md.

Deliver in {out}:
- REPORT.md: the final account of the four questions, and for each difference between the lanes the competing claims, the decisive observation and your choice;
- record.json, the accepted record, with "class_id": "{case_id}" and "protocol_version": "{contract_version}";
- research.json, your research-work sidecar, with receipts as paths relative to {out};
- decision.json in the shape the decisions reference gives (status, basis, reviewed_dimensions, resolutions, evidence, next_question when BLOCKED). The script adds the digests, pins and research object;
- evidence/, checks/ and SUMMARY.md (at most ten lines).

Before finishing run `python3 -B {repo_root}/scripts/radar_case.py check --run {run} --case {key} --dry-run` until it reports ready (a researched BLOCKED decision reports outcome BLOCKED), and fix what it reports.

Time budget: about {minutes} minutes. Reply with the contents of SUMMARY.md only.
