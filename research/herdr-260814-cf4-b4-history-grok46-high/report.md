# CF4 bucket-4 history freeze

Verdict first: **0 PASS_PROPOSAL**. Frozen inspected count is **2**. Both are **REJECT**. Shortfall **10**. Did not pad. packet_delta=0. Canonical strict count remains **88**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none.

## Bound

Eligible remaining first-party bucket-4 after structured exclusions including CF4-b4-surface: **529**. Rank: reviewed first, exact repo advisory or fix commit, published 2025-2026 first, local clone plus real fix objects, then GHSA ID. Inspected prefix **529** (cap 600). Stop rule: **prefix_exhausted**. Actual atomic AI-history hits: **2**. Shortfall: **10**. Never pad.

Walked 200 first-parent commits on fix-touched source files plus local PR members/squash carriers. Production matcher `ai-authorship-source-v3`. File-add of the exact fixed path: 0. Tight introduction hits: 0. The two frozen rows are the only matcher-positive atomic commits in that walk; neither introduced the named surface.

## Universe and conservation

Advisory split: github-reviewed from `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`; unreviewed subtree only from `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`. Union by uppercase GHSA ID; f2c6 wins on 135 collisions.

First-party active 17602. Bucket sha256(uppercase GHSA) mod 6 == 4: **2837**. Structured exclusions 24343 IDs including canonical88 and CF4-b4-surface. Eligible **529**. Clone plus real fix objects: 42. Equation: 2 frozen = 2 packet-reviewed + 0 remainder. Did not pad.

## Per identity (all REJECT)

1. GHSA-MGX3-9W7V-8674 trailofbits/fickling. REJECT. Unreviewed, affected=[]. Repo advisory URL names GHSA-cffv, not this ID. Atomic Claude e5e34bbc is a later Billion Laughs guard. Closer 41ce7cb0 is Claude Opus 4.7 AI-on-fix. identity FAIL, ai_hunk FAIL, but_for FAIL. v0.1.11 vs v0.1.12 holds for the closer only.
2. GHSA-RPPV-5944-CRMM nesquena/hermes-webui. REJECT. Unreviewed, affected=[], no repository advisory URL. Atomic Claude 7a80e73e is silent agent errors / model list. workspace.py file-add a4e2174c is unmarked. Closer 2a7a5ddf hinotoi-agent is not a recognized signature. identity FAIL, ai_hunk FAIL, but_for FAIL. v0.50.33 vs v0.50.34 holds for the closer only.

Both fail identity: unreviewed GHSA objects, github_reviewed=false, empty affected, no first-party repository advisory URL matching the identity. First-party release tags admitted them to the search universe only. Unrelated ancestor, AI-on-fix, new caller of an old bug, blob-generic ident overlap, and later human/AI reintroduction do not pass. Prefer zero PASS.

## Claim boundary

No worker proposal changes the count. Current leader HOLD snapshot is canonical strict **88**. This packet does not edit canonical or site files and does not support a greater-than-200 claim.
