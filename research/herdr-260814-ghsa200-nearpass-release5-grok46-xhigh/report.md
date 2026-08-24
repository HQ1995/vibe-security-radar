# Near-PASS release-containment close (five first-party GHSA hypotheses)

**Status: TERMINAL. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This shard proposes no admissions and does not claim more than 200. Canonical81 was not rebuilt.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical81 summary SHA-256 `dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c`. Ledger SHA-256 `3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9`. Frozen advisory-database revision `a42c436870111aa3f221257c9d56126a93173ccc`. Shared tracked files, canonical81, and prior packets were not edited. No commit, push, or credential output.

## Assignment

Exactly five identities, selected mechanically from `autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl` because the preserved overlay is NARROW and the recorded gate vector is `release_gate=NARROW` with the other six gates PASS. That vector is routing only, not truth. All seven contract gates were re-audited against first-party Git objects, repository advisories, tags/releases, and package metadata.

1. GHSA-2X93-H3HG-2XFP, openclaw/openclaw, openclaw-browser-snapshot-current-tab-preflight-residual
2. GHSA-9C3V-684M-579C, openclaw/openclaw, openclaw-mcp-sse-redirect-header-residual
3. GHSA-F2FQ-4RMP-9X8C, ChurchCRM/CRM, churchcrm-2fa-failure-counter-residual
4. GHSA-V396-V7Q4-X2QJ, gitpython-developers/GitPython, gitpython-joined-short-option
5. GHSA-WP73-F3GG-W4VR, openclaw/openclaw, openclaw-clickclack-toolsallow-propagation-residual

Conservation: assigned = 5, reviewed = 5, unreviewed = 0.

Clones used read-only: `/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/{openclaw,gitpython,churchcrm}`. Local tags were present (350 / 117 / 220). No clone writes. Public GHSA, GitHub Release, npm, and PyPI objects were fetched without credentials into `work/pages/`.

## Pattern

These five were routed as near-PASS incomplete-remediation upgrades whose only recorded miss was release containment. Independent replay does not promote any row. Incomplete-remediation PASS still requires an explicit AI security attempt at the same boundary, a public artifact that contains that attempt without closure, a first-party GHSA that names that residual, and a later fix that amends the AI-added boundary. Sibling paths, unmarked squashes, and later human matcher rewrites fail. Release PASS on an AI commit is not overall PASS.

## Verdict

Zero PASS proposals. All five stay **NARROW**. No second-independent-red-team PASS queue.

| Identity | Repository | Worker verdict | Release gate | Binding miss |
|---|---|---|---|---|
| GHSA-2X93-H3HG-2XFP | openclaw/openclaw | NARROW | PASS | patch-delta / but_for (sibling snapshot path) |
| GHSA-9C3V-684M-579C | openclaw/openclaw | NARROW | PASS | patch-delta / but_for (sibling SSE transport) |
| GHSA-F2FQ-4RMP-9X8C | ChurchCRM/CRM | NARROW | NARROW | topology (AI member never tagged) |
| GHSA-V396-V7Q4-X2QJ | gitpython-developers/GitPython | NARROW | PASS | but_for (human exact matcher, not GPT shlex) |
| GHSA-WP73-F3GG-W4VR | openclaw/openclaw | NARROW | NARROW | patch-delta (ClickClack not in candidate) |

### GHSA-2X93-H3HG-2XFP

Published repository advisory (global `/advisories` 404). npm package `openclaw`, range `>= 2026.4.14, < 2026.5.26`, patched `2026.5.26`. Atomic `[AI]` commit `b75ad800` adds `assertBrowserNavigationResultAllowed` on two `usesChromeMcp` snapshot/screenshot branches. Parent already had `agent.snapshot.ts` and already called that helper on a Chrome-MCP path. Tag `v2026.5.22` peels to `a374c3a5`, contains the candidate, lacks `06047005`. npm `2026.5.22` tarball shasum `ff2d530ad49b4874acf0fb6f37ef363f2e122ef3`. GitHub release is not draft. Tag `v2026.5.26` peels to `10ad3aa1` and contains Agustin Rivera closer `06047005`, which moves SSRF validation earlier on a broader snapshot path. Reverting the AI hunk leaves snapshots less checked than the named current-tab miss. Release of the AI commit PASSes. Patch-delta stays NARROW.

### GHSA-9C3V-684M-579C

Reviewed global GHSA plus repository advisory. npm `openclaw` `< 2026.6.5` patched `2026.6.5`. Atomic `[AI]` commit `47eb2d48` adds STREAMABLE_HTTP redirect scrubbing. Parent and candidate `SSEClientTransport` constructors both use `fetchWithUndici` with no Authorization scrub. Tag `v2026.6.1` peels to `2e08f0f4`, contains the candidate, lacks `3c6259eb`. npm `2026.6.1` tarball exists. Tag `v2026.6.5` peels to `5181e4f7` and contains closer `3c6259eb` (`fix: guard mcp http redirects`). Sibling-transport completion is not but-for of the named SSE residual. Release of the AI commit PASSes. Patch-delta stays NARROW.

### GHSA-F2FQ-4RMP-9X8C

Published repository advisory (global 404). Composer name `churchcrm/crm` is not on Packagist (404). Public artifacts are GitHub zips `ChurchCRM-7.5.1.zip` and `ChurchCRM-7.6.0.zip`. Claude Haiku member `cbea916e` restores API 2FA/lockout for GHSA-cwp8 and omits `usr_FailedLogins` on OTP reject. That member is in **zero** tags. Carrier `1bfc187a` is an unmarked sibling squash (same parent `1b29acf2`, not a descendant). `public-user.php` blobs are three-way unequal (member `74e9d890`, carrier `abf31119`, `7.5.1` `25e8219b`). Do not transfer authorship. Tag `7.5.1` peels to `9ee9c00c` and contains the carrier, not the member. Released closer `07be35d7` is first in `7.6.0` peel `9b5993c0`. Unreleased closer `32599b3d` is in no tag. Advisory array names `7.5.1` / `7.6.0`; carrier first appears in `7.3.1`. Distinct from counted GHSA-CWP8-RM8G-Q5C9. Topology and release stay NARROW.

### GHSA-V396-V7Q4-X2QJ

Reviewed global GHSA plus repository advisory. PyPI GitPython `= 3.1.50` patched `3.1.51`. GPT 5.4 `c9a26789` switches clone checking onto shlex tokens in `git/repo/base.py`. `git/cmd.py` is unchanged; `check_unsafe_options` still uses `startswith`, so `-uVALUE` is already blocked. Human `14219588` (`w`, no AI marker) rewrites the checker to exact `_canonicalize_option_name`. Human `43d92dec` hardens that canonicalization. Both are ancestors of `3.1.47` and `3.1.50`. Tag `3.1.50` peels to `5a294a6f`; cmd blob `09690081` equals `3.1.49` and is the exact matcher. PyPI `3.1.50` sdist sha256 `80da2d12504d52e1f998772dc5baf6e553f8d2fcfe1fcc226c9d9a2ee3372dcc`, not yanked. Closer GPT 5.6 `56806080` is first in `3.1.51` peel `7b0764d3`. Git first-containing tag of the AI commit is `3.1.47`; PyPI `3.1.47`-`3.1.49` are public and not yanked, so the GHSA equals-3.1.50 window is a subset. The AI shlex switch is not but-for of the named residual. Residual containment in 3.1.50 versus 3.1.51 PASSes. Overall NARROW.

### GHSA-WP73-F3GG-W4VR

Published repository advisory (global 404). npm `openclaw` `>= 2026.5.10-beta.1, < 2026.6.5` patched `2026.6.5`. Atomic `[AI]` commit `6c918ca8` inherits tool restrictions for delegated sessions. Candidate files include no ClickClack paths. `extensions/clickclack/src/inbound.ts` exists at the candidate and at `v2026.6.1` but has no `toolsAllow`. Advisory introduced npm `2026.5.10-beta.1` tarball exists; git tag `v2026.5.10-beta.1` does **not** contain `6c918ca8`. Closer `797bcd5b` (Peter Steinberger) is the first to write `toolsAllow: params.account.toolsAllow` in ClickClack inbound. Tag `v2026.6.1` contains the candidate; `v2026.6.5` contains the closer. That is containment of a sibling runner-policy commit, not of an AI ClickClack attempt. Release of the named residual as AI-caused stays NARROW.

## Uniqueness

None of the five IDs is in canonical81 `strict_released_case_ids` (81). Shared openclaw repository does not merge 2X93, 9C3V, and WP73 (different files, different SHAs, different invariants). GHSA-F2FQ is not merged with counted GHSA-CWP8-RM8G-Q5C9. CVE aliases are not counting units. Prior packets that mention these IDs are uncounted NARROW overlays and are not admissions.

## Counts

| Worker verdict | Rows |
|---|---:|
| PASS (proposal) | 0 |
| NARROW | 5 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| REJECT | 0 |

PASS proposals for a second independent red-team: **none**.

## Claim boundary

Countable PASS requires all seven gates PASS plus leader admission. Proposed PASS: 0. Publication remains HOLD. Greater-than-200 remains HOLD. This packet does not support a greater-than-200 claim. Canonical81 was not rebuilt.
