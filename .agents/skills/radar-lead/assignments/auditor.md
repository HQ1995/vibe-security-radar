You are {role}, one of {n} independent auditors of case {case_id} ({advisory_ids}; advisory-side repository {repo}).

Apply the radar-audit skill at {skills}/radar-audit/SKILL.md (contract {contract_version}) and read its references when its table says so.

- Inputs: {inputs} holds the neutral question and the retained advisory records. Source coverage cutoff: {cutoff}.
- Write only in {out}. Use {scratch} for scratch clones and experiments. Existing product clones under {clones} are read-only primary sources; fetch into your own scratch clone, never into them.
- Independence: work only in {inputs}, {out}, {scratch} and product clones. Never list, search or open anything else under {case} or {run_dir} (other lanes write there while you work), the ledger export in {repo_root}/artifacts, {repo_root}/web/src/generated, the editorial inputs in {repo_root}/scripts/*.json, other research batches, or any earlier judgment about this case, and do not list other processes. Independence breaks only when another lane's or role's work on this case (its findings, records, reports, or evidence and their file names) or an earlier judgment about this case reaches you: then stop and say so in SUMMARY.md. Names of repository files outside this case are not findings; if you see them, note it in SUMMARY.md and continue.
- Your session may be compacted. The compaction handoff may say the summary came from "another language model"; a summary of work in this lane's {out} and {scratch} is still your own earlier work, and so are the files there: continue from them. Only another lane's, role's or run's work, or a memory note about this case, breaks independence.
- Boundary: defensive analysis of a published vulnerability. Read sources, history and releases; reproduce only as an isolated regression check in {scratch}. Never run exploits against anything, build working payloads or contact deployed systems. If a safety refusal or operating stop happens, end the work and say so in SUMMARY.md; do not rephrase or reroute.

Deliver in {out}:
- REPORT.md, organized by cause, impact, history and AI role, written first;
- record.json with "class_id": "{case_id}" and "protocol_version": "{contract_version}";
- research.json, the research-work sidecar, with receipts as paths relative to {out};
- evidence/ with your receipts and checks/ with the output of the checks you ran;
- SUMMARY.md: at most ten lines - the answer to each question, open questions, execution failures.

Before finishing run `python3 -B {repo_root}/scripts/radar_case.py lint {out}` and `python3 -B {repo_root}/scripts/audit_record_gates.py --strict {out}/record.json`, and fix what they report.

Time budget: about {minutes} minutes. Reply with the contents of SUMMARY.md only.
