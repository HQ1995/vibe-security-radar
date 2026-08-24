# CF4 bucket-2 history freeze

Verdict first: **0 PASS_PROPOSAL**. Frozen inspected count is **3**. All three are **REJECT**. Shortfall **9**. Did not pad. packet_delta=0. Canonical strict count remains **88**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none. H2V8 stays excluded with release UNKNOWN.

## Bound

Eligible remaining first-party bucket-2 after structured exclusions including CF4-b2-remediation and targeted H2V8 closure: **577**. First-party bar: repository advisory URL matching this GHSA, or github.com owner/repo releases/tag on the same repo. Rank: reviewed first, exact repo advisory or fix commit, published 2025-2026 first, local clone plus real fix objects, then GHSA ID. Inspected prefix **577** (cap 600). Stop rule: **prefix_exhausted**. Actual atomic AI-history hits: **3**. Shortfall: **9**. Never pad.

Walked 200 first-parent commits on fix-touched source files plus local PR members/squash carriers. Production matcher `ai-authorship-source-v3`. Do not use ancestry overlap alone. Prioritize introduction of the fixed code or an AI security attempt whose exact residual the closer amends.

## Universe and conservation

Advisory split: github-reviewed from `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`; unreviewed subtree only from `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`. Union by uppercase GHSA ID; f2c6 wins on 135 collisions (23 in bucket 2).

Union bucket-2: **58554**. Structured exclusions 24346 IDs including canonical88, CF4-b2-remediation, and H2V8. Remaining after exclude 54588 (54513 active). First-party eligible **577**. Clone plus real fix objects: 160. Equation: 3 frozen = 3 packet-reviewed + 0 remainder. Did not pad.

## Per identity (all REJECT)

1. GHSA-47XQ-CQ66-M24X volcengine/OpenViking. REJECT. Unreviewed, affected=[]. Claude 1b175344 is an 86-file megapatch that added bot.py with optional verify_auth. Closer 27acda8d is unmarked require_auth_token. Sibling 8d977367 is Claude lint. identity FAIL, but_for FAIL. v0.2.13 vs v0.2.14 holds for the closer only.
2. GHSA-83JC-7J6X-WVJ9 rustdesk/rustdesk. REJECT. Unreviewed, affected=[]. Atomic Copilot 02da7132 is a reconnect note dialog. Other Copilot first-parent hits are keep-awake and custom scale. Closer 493b14ba is human session-scope audit. identity FAIL, ai_hunk FAIL, but_for FAIL. 1.4.8 vs 1.4.9 holds for the closer only.
3. GHSA-G57H-53RR-6677 formbricks/formbricks. REJECT. Unreviewed, affected=[]. Atomic Claude 939fedfc is a 2017-file Formbricks 5 rename of storage rate-limit namespaces. actions.ts file-add is unmarked. Closer af6023b5 is Claude Sonnet 4.6 AI-on-fix. Listed tags 5.1.0-rc.1 and 5.0.0 are absent locally. identity FAIL, ai_hunk FAIL, release UNKNOWN.

All three fail identity: unreviewed GHSA objects, github_reviewed=false, empty affected, no first-party repository advisory URL matching the identity. First-party release tags admitted them to the search universe only. Unrelated ancestor, AI-on-fix, megapatch optional-auth, new caller of an old bug, blob-generic ident overlap, and later human reintroduction do not pass. Prefer zero PASS.

## Claim boundary

No worker proposal changes the count. Current leader HOLD snapshot is canonical strict **88**. This packet does not edit canonical or site files and does not support a greater-than-200 claim.
