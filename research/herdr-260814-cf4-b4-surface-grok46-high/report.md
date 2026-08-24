# CF4 bucket-4 new-surface freeze

Verdict first: **0 PASS_PROPOSAL**. Frozen inspected count is **12**. All 12 are **REJECT**. Did not pad. packet_delta=0. Canonical strict count remains **88**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none.

## Universe and conservation

Advisory split: github-reviewed from `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`; unreviewed subtree only from `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`. Union by uppercase GHSA ID; f2c6 wins on 135 collisions. The older 39d888 reviewed tree did not constrain selection.

Active union 350659. First-party (repository advisory URL matching the GHSA, or exact github.com owner/repo releases/tag matching the same repo) 16761. Bucket sha256(uppercase GHSA) mod 6 == 4: **2701**. Prior structured `case_id` / `ghsa_id` / `reviewed_case_ids` / `assigned_ids` / `strict_released_case_ids` exclusions 24316 IDs; overlap in this bucket 2294; eligible **407**. Unreviewed rows with first-party release evidence were kept.

Focus: AI-added endpoints, plugins, adapters, transports, parsers, or auth paths. After that search, no stronger causal mechanism in the owned bucket beat these 12. Freeze 12 identities that have real Git objects and first-party release tags. Equation: 12 frozen = 12 reviewed + 0 unreviewed. Did not pad.

## Per identity (all REJECT)

1. GHSA-P2QQ-M885-CM42 nextlevelbuilder/goclaw. REJECT. Unreviewed, affected=[]. Claude Opus 4.6 co-authored the whole-repo initial commit that added router.go/policy.go. Later unmarked humans rewrote policy.go. Closer 406022e7 is unmarked. Default-permit preservation is routing. identity FAIL, but_for FAIL. v3.8.5 vs v3.9.0 holds for release only.
2. GHSA-XQ6P-PM3C-F228 TencentCloudBase/CloudBase-MCP. REJECT. Unreviewed. openUrl file-add 75e62d91 is unmarked. Closer merge of github-actions issue-auto member. AI-on-fix routing. v2.17.0 vs v2.17.1.
3. GHSA-9CQV-QVMJ-XRC4 tugcantopaloglu/godot-mcp. REJECT. Unreviewed. MCP tools added in unmarked initial release 181360fa. Closer eb63add5 unmarked. v3.0.0 contains closer.
4. GHSA-MJRQ-XG2M-QG94 HKUDS/Vibe-Trading. REJECT. Unreviewed. store.py from unmarked initial commit. Closer Hinotobi paperlantern.agent is not a recognized signature. Listed tag v0.1.10 does not contain the closer SHA. release UNKNOWN.
5. GHSA-GV7X-PQ3J-C5MJ HKUDS/nanobot. REJECT. Unreviewed. Teams handler added by unmarked T3chC0wb0y. Closer 232df451 unmarked. v0.2.0 vs v0.2.1.
6. GHSA-9CF6-6J4G-MW9R parseablehq/parseable. REJECT. Unreviewed. /targets added unmarked. Closer restores masking. v2.9.1 vs v2.9.2.
7. GHSA-PXHC-H7Q5-6QRG heymrun/heym. REJECT. Unreviewed. Upload endpoint from unmarked initial commit. Closer merge of hinotoi-agent member; no authorship transfer. v0.0.20 vs v0.0.21.
8. GHSA-4HGQ-JJGJ-6JWM new-usemame/Calibre-Web-NextGen. REJECT. Unreviewed. kobo_auth.py from unmarked MAJOR REFACTOR. Closer 9f50bb2c unmarked. v4.0.7 contains closer.
9. GHSA-5J37-RF54-82Q2 nesquena/hermes-webui. REJECT. Unreviewed. Passkey file-add AJV20 unmarked. Closer rebases Hinotoi-agent #4171: AI-on-fix. v0.51.441 vs v0.51.442.
10. GHSA-WWX5-JQ7H-RP7V nesquena/hermes-webui. REJECT. Unreviewed. Same unmarked passkey add. Bundled closer 58528a4d. Shared SHA with 5J37 is routing. v0.51.269 vs v0.51.270.
11. GHSA-HQ7F-WV7C-W9MP nesquena/hermes-webui. REJECT. Unreviewed. api/oauth.py added by unmarked bergeouss. Product word Codex is not authorship. Two-parent release closer. v0.51.468.
12. GHSA-4HHQ-38M9-MGG7 jxxghp/MoviePilot. REJECT. Unreviewed. system.py added unmarked. Closer 0b7854a0 unmarked and already in v2.13.1.

All twelve fail identity: unreviewed GHSA objects, github_reviewed=false, empty affected, no first-party repository advisory URL. First-party release tags admitted them to the search universe only. Prefer zero PASS over one false positive.

## Claim boundary

No worker proposal changes the count. Current leader HOLD snapshot is canonical strict **88**. This packet does not edit canonical or site files and does not support a greater-than-200 claim.
