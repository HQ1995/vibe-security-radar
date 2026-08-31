# Site publication test-pruning review

Date: 2026-08-30

Scope was intentionally limited to the three test files already changed by this work:

- `scripts/tests/test_ledger_store_contracts.py`
- `scripts/tests/test_site_publication_contract.py`
- `web/src/components/__tests__/ui-regressions.test.tsx`

## Result

The second pass removed only assertions that pinned incidental copy, fixture size, or an implementation tuning value.

| File | Pruned | Deliberately retained |
|---|---|---|
| `test_ledger_store_contracts.py` | No further deletion. | The narrowed `NOT_AI.*site_scope` error match still proves the NOT_AI publication boundary instead of accepting any `ValueError`. |
| `test_site_publication_contract.py` | Removed the mock's positive-timeout assertion; timeout policy is not part of fix-object identity. | One combined sourced-gates root regression, explicit ledger candidate/fix sets overriding stale site evidence, corpus-wide readable summaries, full-SHA/repository URL binding, deduplication, unresolved reasons, IR-chain and unpatched gates, generated publication count, and the final `errors == []` integration gate. |
| `ui-regressions.test.tsx` | Removed seven fixed legend/section-copy assertions, the four-hunk synthetic fallback test with magic counts, and the corpus loop that duplicated Python preflight by matching a retired placeholder sentence. | Dynamic one-role-per-hunk coverage, the rendered hunk explanation, audited `unavailable_reason`, full SHA/source links, causal-chain rendering, unresolved authorship behavior, desktop layout order, and the compact loading-state regression. |

The generated publication status count was explicitly kept:
`sum(stats["publication_statuses"].values()) == len(payload["cases"])`.
It is a publication-quantity gate, not expendable fixture bookkeeping.

## Protected gates checked

No assertion was removed from these boundaries:

- evidence and incomplete-remediation chains;
- complete commit SHAs and role-bound source URLs;
- required `unresolved_reason`;
- `NOT_AI` publication rejection;
- duplicate identity folding and replacement;
- publication quantity and corpus preflight;
- stale cached/tier gates cannot become published PASS gates, and unsourced explicit ledger gates fail;
- publisher root-cause behavior where explicit ledger sets override stale cached evidence.

## Validation

Each affected suite was run directly on NUMA node 1:

- `PYTHONPATH=scripts python3 scripts/tests/test_ledger_store_contracts.py` — 7 passed.
- `PYTHONPATH=scripts python3 scripts/tests/test_site_publication_contract.py` — 46 passed.
- `npm test -- src/components/__tests__/ui-regressions.test.tsx` from `web/` — 28 passed.

No publisher, generated-data, database, or commit operation was performed.
