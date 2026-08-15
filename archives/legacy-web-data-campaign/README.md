# Legacy web-data campaign (frozen, archived 2026-08-15)

Replaced by the new sole pipeline:
`scripts/publish_research_ledger.py` -> `web/src/generated/research-data.json`.

This archive holds the old 36-case web release path and its quality gates:

- `scripts/` - generate_web_data.py, run_data_refresh.py/.sh,
  verify_formal_release.py, evaluate_publication_quality.py,
  evaluate_detector_quality.py, heldout_quality_gate.py, build_recall_audit.py,
  pipeline_funnel.py, refresh_source_inputs.py, run_openclaw_regression.py,
  legacy collision-cache migration scripts, DATA_REFRESH.md, HELDOUT_QUALITY.md.
- `web_data/` - schema/writer/loader module that produced web/data/cves/*.json.
- `heldout_studies/` - heldout selections and labels for the old release path.
- `tests/` - pytest suite for the above.
- `web-scripts/` - publication-contract.mjs, verify-static-release.mjs.

The 36-case output catalog itself lives in archives/legacy-36-web-catalog/.
Nothing in the live pipeline imports any of this. To resurrect, move the
entries back to their original paths (scripts/, scripts/tests/, web/scripts/);
git history also retains the last tracked state. The git-ignored runtime state
under .ai-slop/state/data-refresh/ was left in place.
