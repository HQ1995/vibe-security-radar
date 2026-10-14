# Reducer decisions

The [adjudication protocol](protocol.md) owns acceptance. You write `decision.json` in your
directory. `python3 -B scripts/radar_case.py check` turns it into the frozen `decisions.json`
beside the case and adds what is mechanical: the reducer and lane names, the SHA-256 of both
auditor records and of your accepted record, pins of the manifest, protocols, record
reference, your assignment and the gate code, and your `research.json` as the `research`
object. It then runs the reduction gate with `--research-contract causal-work-v1`. Decisions
are local research data, never ledger or website data. Receipt paths are relative to your
directory or absolute; every digest is the SHA-256 of the exact bytes.

```json
{
  "status": "ACCEPTED",
  "basis": "State the final causal chain and how counterevidence was resolved.",
  "reviewed_dimensions": ["advisory", "mechanism", "bic", "ai", "fix", "versions", "residual"],
  "resolutions": {
    "fix": {
      "claims": {"auditor1": "What auditor1 concluded about the repair.", "auditor2": "What auditor2 concluded."},
      "observation": "The decisive primary observation.",
      "reasoning": "Why each reading holds or fails.",
      "conclusion": "The final choice.",
      "evidence": [{"path": "evidence/fix-diff.txt", "sha256": "<64 hex>"}]
    }
  },
  "evidence": [{"path": "evidence/source.txt", "sha256": "<64 hex>"}],
  "next_question": null
}
```

This is a shape example, not an acceptable prewritten decision. Every differing dimension
across the auditor records and final synthesis needs its own nonempty resolution.
Generic `evidence` and `reasoning` differences belong to the `mechanism` review dimension;
this requires an explanation of differing observations, not automatic contradiction.
TP cases also need `bic`, `ai` and `fix` resolutions even when lanes agree; review signals require
`residual`, and invalid input records require `input_quality`. The reducer explains
whether each flag is substantive. Receipt files contain observations, commands/URLs,
repository/object, time and exit results; each reasoning claim points to the relevant
part. `reviewed_dimensions` records coverage, not evidence of correctness.

`BLOCKED` requires `next_question` and prevents an all-accepted gate result. Confirmed
unpatched research can be `ACCEPTED` with its qualified repair conclusion. Record
execution and publication status separately. Additional `pins` entries bind staging
payloads, reports and other deliverables. Preserve the full accepted research when
projecting it into the ledger; the gate does not test that projection or live revisions.

The gate checks the hashes of the code it actually ran, and `case.json` records the
repository commit the case ran under. Historical batches keep their original contract.
