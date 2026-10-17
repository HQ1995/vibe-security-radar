# Submission

What each auditor and the adjudicator deliver, in the directory their assignment owns:

1. Save receipts in `evidence/` as you go: command or URL, repository and full object SHA or
   version, capture time, exit or HTTP status and the raw output. Keep failed probes.
   `radar_git.py --out <your directory>/evidence` writes such a receipt for each query,
   including a failed one.
2. Write `REPORT.md` first, then derive `record.json` and the research-work sidecar
   `research.json` with file writes or a script; never interpolate source text or whole JSON
   documents into shell strings. After a write failure, inspect the files before continuing.
3. Receipts inside `research.json` (and the adjudicator's `decision.json`) are
   `{"path", "sha256"}`, with paths relative to your directory.
4. Run the checks and keep their output in `checks/`:
   - `python3 -B scripts/radar_case.py lint <your directory>`: required files, class ID,
     protocol version, the research-work sidecar and its receipts;
   - `python3 -B scripts/audit_record_gates.py --strict <your directory>/record.json`, and
     with the product clone `--repo <clone>`. They check structure and local objects, not
     truth; never invent a value for a check you could not run, explain it instead;
   - the adjudicator also runs `python3 -B scripts/radar_case.py check --run <run> --case <NNN>
     --dry-run`, the reduction gate over every lane; a researched BLOCKED decision reports
     outcome BLOCKED.
5. Write `SUMMARY.md` (at most ten lines: the answer to each question, open questions,
   execution failures) and reply with it.

The leader then seals your directory: the files become read-only and their hashes are
recorded. A later correction is a labeled continuation; the sealed original is kept.

The [research-work sidecar](research-work.md) keeps supported conclusions apart from
unfinished work. A crash, timeout, rate limit or empty response is an execution failure,
never an EVIDENCE_GAP. Delivering grants no claim, ledger or publication authority.
