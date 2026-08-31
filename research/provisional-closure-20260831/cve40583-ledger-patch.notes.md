# CVE-2026-40583 ledger patch notes

- Patch: `cve40583-ledger-patch.jsonl` (one full-row update, live `expected_revision=1`).
- Disposition: `status=BLOCKED`, `ledger_best=BLOCKED`, `release=FAIL`, and `site_publication.publish=false`; site scope/tier and both release witnesses are null.
- Causal edge: BIC `361e71d4329b672482531122117631ec5358953a` → minimum direct fix `45bcf7064741897319b6196d3d9f9e1307093511`; `2f5a3a237ea519b48d71e6e3093c89f60694c7be` remains follow-up hardening only.
- The live top-level advisory identity is preserved exactly: `advisories=1`, `advisory_ids=["CVE-2026-40583"]`, and `advisory_ids_source=hash_pin_20260826`. The GHSA mapping remains evidence, not an alias mutation in this patch.
- Validation: one physical line; per-line `json.loads`, live-revision check, `ledger_store.validate_update`, `audit_envelope.violations`, and `audit_record_gates.check_record` all pass. SHA-256: `87fc6a48403d299ac07deff7ea3a9e1fb98ae73dfd1f32597a2086bbdfff6cdd`.
- No database, ledger export, site, publisher, or Git commit was changed.
