# Reducer decisions

The [Adjudication protocol](protocol.md) owns acceptance. New assignments
store its immutable decision object in a dedicated `decisions.json`, optionally
under a `reduction` key. Execution and dispatch state stay in the batch index,
which holds a pointer to the decision file. Do not mix `dispatch` or `allocation`
into frozen decisions. Legacy frozen layouts retain their original checks until
explicit migration. Decisions are not ledger or website data.
`auditors` freezes all N independent lane names before dispatch;
the supplied lanes must match that list. Every case binds each named input plus `accepted`.
All digests are SHA-256 of exact file bytes, including whitespace. Paths are relative
to the decision file, or absolute. Retain source copies; a URL alone is not a receipt.
The baseline envelope below uses legacy prose resolutions; newly adopted research-work
contracts extend it as specified in the next section.

```json
{
  "reduction": {
    "reducer": "reducer3",
    "auditors": ["auditor1", "auditor2", "auditor3"],
    "pins": {
      "manifest": {"path": "../batch.txt", "sha256": "<64 hex>"},
      "audit_protocol": {"path": "contract/.agents/skills/radar-audit/references/protocol.md", "sha256": "<64 hex>"},
      "reducer_protocol": {"path": "contract/.agents/skills/radar-adjudicate/references/protocol.md", "sha256": "<64 hex>"},
      "schema": {"path": "contract/.agents/skills/radar-audit/references/record.md", "sha256": "<64 hex>"},
      "brief": {"path": "contract/brief.md", "sha256": "<64 hex>"},
      "record_gate": {"path": "contract/audit_record_gates.py", "sha256": "<64 hex>"},
      "comparison": {"path": "contract/compare_slots.py", "sha256": "<64 hex>"},
      "reduction_gate": {"path": "contract/audit_reduction_gate.py", "sha256": "<64 hex>"}
    },
    "cases": {
      "alias-example": {
        "sha256": {"auditor1": "<64 hex>", "auditor2": "<64 hex>", "auditor3": "<64 hex>", "accepted": "<64 hex>"},
        "status": "ACCEPTED",
        "reviewed_dimensions": ["advisory", "mechanism", "bic", "ai", "fix", "versions", "residual"],
        "basis": "State the final causal chain and how counterevidence was resolved.",
        "resolutions": {
          "fix": "State all competing repair claims, the decisive primary observation and the final choice."
        },
        "evidence": [{"path": "evidence/alias-example.txt", "sha256": "<64 hex>"}]
      }
    }
  }
}
```

The `reducer_protocol` pin names the adjudication contract; reducer remains the role name.
`--lane NAME=PATH` is repeatable. Legacy `--a`/`--b` commands name lanes `a` and `b`.
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

For frozen gate code, keep `audit_record_gates.py`, `compare_slots.py` and
`audit_reduction_gate.py` together and invoke that copy. The gate checks the hashes of
the code actually used. Historical batches retain their original contract; adoption of
this format must be explicit, not a retroactive claim that old runs followed it.

