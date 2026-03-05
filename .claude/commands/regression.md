# Regression Check

Run regression analysis to detect lost or gained true positives after pipeline changes.

## Steps

1. **Run tests first** to ensure the pipeline is healthy:
   ```
   cd cve-analyzer && uv run pytest tests/ -q
   ```
   If tests fail, stop and fix them before proceeding.

2. **Run the regression check** against the latest baseline:
   ```
   cd cve-analyzer && uv run python regression/check.py
   ```
   This compares the current cache against the latest `regression/baseline-*.md` file.

3. **Analyze the output**:
   - **Regressions**: TPs that were in the baseline but are now missing or lost confirmed BICs. These MUST be investigated — identify what pipeline change caused the loss and fix it.
   - **New TPs**: CVEs in cache with confirmed AI-authored BICs that aren't in the baseline. These are improvements.

4. **If there are regressions**, investigate each one:
   - Check the cached result: `~/.cache/cve-analyzer/results/<CVE-ID>.json`
   - Compare with the baseline entry in `regression/baseline-*.md`
   - Re-analyze the specific CVE: `uv run cve-analyzer analyze <CVE-ID> --no-cache --llm-verify`
   - Determine if the regression is a true loss or expected behavior change

5. **If all regressions are resolved** (or there were none), and there are new TPs, update the baseline:
   ```
   cd cve-analyzer && uv run python regression/check.py snapshot --cache
   ```
   This creates/overwrites `regression/baseline-<today>.md` from the current cache.

6. **Report** a summary: how many regressions found/fixed, how many new TPs, final TP count.

## When to Use

- After modifying the analysis pipeline (`pipeline.py`, `git_ops.py`, `llm_verify.py`, `ai_signatures.py`)
- After re-running batch analysis
- Before committing pipeline changes to main
