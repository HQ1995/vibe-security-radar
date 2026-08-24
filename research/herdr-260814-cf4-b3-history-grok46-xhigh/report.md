# CF4 bucket-3 history freeze

Verdict first: **0 PASS_PROPOSAL**. Frozen inspected count is **1**. That row is **NARROW**. Shortfall **11**. Did not pad. packet_delta=0. Canonical strict count remains **88**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none.

## Bound

Eligible remaining bucket-3 after structured exclusions including CF4-b3-topology: **57437** (4313 reviewed + 53124 unreviewed). Rank: reviewed first, exact repo advisory or fix commit, published 2025-2026 first, local clone plus real fix objects, then GHSA ID. Inspected prefix **600** (cap 600). Stop rule: **prefix_exhausted**. Actual atomic AI-history hits: **1**. Shortfall: **11**. Never pad.

Walked 200 first-parent commits on fix-touched source files plus local PR members/squash carriers. Production matcher `ai-authorship-source-v3`. Hit rule: file-add of a fix-touched source path, advisory-named ident introduction, or incomplete-remediation amendment of an AI guard. Same-file proximity, blob equality, lockfile overlap, and mass rename were not hits. Of 600 ranked rows: 283 walked, 29 no source files, 288 no local fix object.

## Universe and conservation

Advisory split: github-reviewed from `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`; unreviewed subtree only from `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`. Union by uppercase GHSA ID; f2c6 wins on 135 collisions. Freeze-time structured exclusions **8159** IDs including canonical88 and CF4-b3-topology. Equation: 1 frozen = 1 reviewed + 0 unreviewed. Did not pad.

## Per identity

1. GHSA-65H7-C7C4-MGHX mlflow/mlflow. NARROW. github-reviewed CVE-2026-2393. Atomic squash `3094ab60` (#16583) n_parents=1 author Harutaka Kawamura, Co-authored-by Claude, adds `mlflow/webhooks/delivery.py` and https-scheme `_validate_webhook_url`. Parent `4a724add` has neither. Human closer `64aa0ab7` (#20747) adds private-IP `ip.is_global` checks and a delivery-time call; source_matcher empty. identity PASS, topology PASS, but_for PASS at patch-delta, fix_reversal PASS, uniqueness PASS. ai_hunk NARROW: 41-file human squash, trailer is not hunk proof. release NARROW: cand in v3.3.0 not v3.2.0; closer in v3.11.1 not v3.8.1/v3.9.0/v3.10.0; GHSA range introduced 0 / fixed 3.9.0 is false. Prefer zero PASS.

## Claim boundary

No worker proposal changes the count. Current leader HOLD snapshot is canonical strict **88**. This packet does not edit canonical or site files and does not support a greater-than-200 claim.
