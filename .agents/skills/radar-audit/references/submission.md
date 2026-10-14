# Submission


What every worker delivers, inside its owned output only:

1. Check the assignment first: `python3 -B contract/scripts/radar_flow.py inputs <output>/INPUT-BINDING.json --binding <hash>`.
2. Save receipts as you go: command or URL, repository and full object SHA or version,
   capture time, exit or HTTP status and the raw output file. Keep failed probes.
3. Write the report first, then derive `record.json` and the research-work sidecar
   `research.json` with file writes or a script; never interpolate source text or whole JSON
   documents into shell strings. After a write failure inspect the files before continuing.
4. Run the frozen record gates and keep both receipts:
   `python3 -B contract/scripts/audit_record_gates.py --strict <record.json>` and, with the
   product clone, `--repo <clone>`. They check structure and local objects, not truth.
   Never invent a value for a check you could not run; explain it.
5. Check receipts are JSON with the actual `argv`, integer `exit_code` and `outputs`
   (`path`, `sha256`) for saved stdout/stderr.
6. Write the delivery spec (`batch`, `task`, `binding_sha256`, `manifest`, `output`,
   `report`, `records`, `research_work`, `evidence`, `checks`; the adjudicator adds
   `decisions`) with absolute paths inside the output, then
   `python3 -B contract/scripts/audit_delivery.py seal <spec>`. A seal is never overwritten.

The [research-work sidecar](research-work.md) keeps supported
conclusions apart from unfinished work; the gate runs with `--research-contract causal-work-v1`.
Adjudicators also run the reduction gate on the final bytes with every lane's exact
`record.json`, and keep its receipt; a BLOCKED decision makes it exit nonzero by design.
A crash, timeout, rate limit or empty response is an execution failure, never an
EVIDENCE_GAP. A completed command or sealed submission grants no claim, ledger or
publication authority.

