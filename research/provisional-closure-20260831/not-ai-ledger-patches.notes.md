# NOT_AI ledger patch draft notes

Date: 2026-08-31  
Source review: `research/provisional-closure-20260831/not-ai-second-review.md`

This is a draft only. No Neon mutation, ledger export, generated-data rebuild, site update, commit, or push was performed.

| Case | class_id | expected revision | disposition |
|---|---|---:|---|
| CVE-2025-62615 | alias-0d3bd8c784475190b98074e6 | 1 | NOT_AI |
| GHSA-J383-Q79V-268X | alias-c819cf08c0a8bf17cf425ccc | 1 | NOT_AI |
| GHSA-P6Q4-FGR8-VX4P | alias-c12c46f6239faabff2fc306c | 1 | NOT_AI |
| GHSA-8X5V-CPV7-8JJP | alias-588f479c8353c335cc5aea90 | 1 | NOT_AI |
| GHSA-RFR2-MQ9M-X2QX | alias-7c7ceaa679ef609d302575e1 | 2 | NOT_AI |

## Patch policy

- The full current Neon row is preserved as the base.
- Canonical `status` and `ledger_best` are set to `NOT_AI`.
- `site_scope` and `site_tier` are explicitly cleared to `null`.
- Any top-level site/publication-only fields present are removed: `site_publication`, `publication_status`, `publication_issues`, `candidate_set`, `carrier_set`, `minimum_fix_set`, `contribution_class`, and `gates`.
- Existing historical audit payloads are retained. New `notai_second_review_research` records carry the rechecked BIC, parent, direct fix, AI-marker boundary, but-for conclusion, and release evidence.
- Every original `advisory_ids` member is retained.
- `assessment_ids` is intentionally empty because this artifact is a non-finalizing draft.

Before any later apply, re-check the five optimistic revisions against Neon and run `scripts.ledger_store.validate_update(old, new)`; revisions can become stale.

