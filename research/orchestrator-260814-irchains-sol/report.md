# Original-vulnerability chain report

## Result

All 51 enriched residual-remediation rows were processed in input order. The bounded history pass resolved 47 rows to 41 unique introducing commits: 30 rows are HUMAN and 17 rows are AI. Four rows remain UNKNOWN because the relevant vulnerable surface is already present at an unavailable shallow parent after the permitted history expansion. No boundary commit was treated as an introduction merely because its parent was missing.

| Measure | Count |
| --- | ---: |
| Input rows | 51 |
| Resolved BIC rows | 47 |
| Unique resolved BICs | 41 |
| HUMAN rows | 30 |
| AI rows | 17 |
| UNKNOWN rows | 4 |

The source row for `GHSA-56C3-VFP2-5QQJ` has `original_advisory_ids: null`; the output preserves that value exactly rather than inventing an advisory identity.

## Method

For each row, the attempted repair and final closure were read first to identify the original security invariant and sink. The pre-repair code was then followed backward with bounded `git log -S` searches and commit-diff reads. Every Git invocation used a 30-second timeout. Each history expansion was limited to 500 commits, and missing parents remained unresolved. Author kind was assigned only when the introducing commit itself carried an explicit Claude, Copilot, Cursor, or equivalent AI identity; commit style and nearby AI-authored repairs were not used as attribution. The work used local repository objects and Git smart HTTP only, with no GitHub API and no line-attribution algorithm.

The available advisory-database clone supplied matching JSON for 40 rows; those exact paths are recorded in `ir-chains.jsonl`. For the other 11 rows, advisory identity and mechanism come from the enriched local record and its cited foundation, canonical-ledger, audit, and research-note paths. Introducing-commit decisions come from the repository diffs in every case.

## Notable AI-origin chains

There are 17 AI rows but 14 unique AI introducing commits because the same original security feature underlies multiple residual advisories.

| Introducing commit | Rows | Explicit identity and original vulnerable surface |
| --- | --- | --- |
| `30f9b76f848b681e2806ac6ebcebebb055af3999` | `GHSA-2944-57XV-2682`, `GHSA-8882-FRVV-92W4`, `GHSA-J5QP-P44G-2M49` | Claude co-author; introduced SpecifyJS secure fetch with an unbounded data-URI exception, a fail-open URL parse path, and default redirect following. |
| `3cd664bf7b7db5f774c1e7e3123a1a24c68ba700` | `GHSA-4MR5-G6F9-CFRH`, `GHSA-PV2J-RGHR-V5R9` | `claude[bot]` author; introduced the restricted-builtins sandbox whose object graph and later call policy remained escapable. |
| `a3d7f417be601a15865e8817086644d9451cdb73` | `GHSA-425G-FJHQ-5H92` | Claude trailer; introduced schema validation that returned without rejection when the validator dependency was absent. |
| `d9d847f230923d96e0857ccecf3a4dedcc9b0096` | `GHSA-56C3-VFP2-5QQJ` | Claude trailer; introduced the incomplete synchronous SSRF validator used by the embedder fetch path. |
| `5abd65759440ec2f243e78320befd7d77c3b0e78` | `GHSA-5C7W-4WM3-85VW` | Claude trailer; introduced the GraphQL template construction sink. |
| `3c4368da0ab48c1091858d3f9503c378a209997f` | `GHSA-5WP8-Q9MX-8JX8` | Claude trailer; introduced the incomplete shell allowlist/blocklist evaluation. |
| `5e6014c421f7e3ab1d541983372377331aa4bf7a` | `GHSA-6P9M-Q3JP-47H4` | Claude trailer; introduced the LFS deduplication shortcut that failed to consume the request body. |
| `5991e4a3518065b0d27cc9c993b39fb31a4e98ea` | `GHSA-93Q6-WWJH-JC6H` | Claude trailer; introduced the server-rendered CSS sink. |
| `f9afc3c5a961efbf600ac8f71ecc3da54ddef1b1` | `GHSA-F2FQ-4RMP-9X8C` | Claude author; removed login-path lockout and second-factor gates while applying a broad security patch. |
| `d83871ed0314f604e417f40733f762acfdcbc35c` | `GHSA-HC8V-WWC9-VGXM` | Claude `Assisted-by` trailer; introduced the path-string-only worktree filesystem guard. |
| `9a185994a4e549b7bba3cc2beffb9736aa902e79` | `GHSA-P5RM-JG5C-8C77` | Copilot trailer; introduced Kiota's first unsafe static-template file-reference validator. |
| `20523b918adff4feae378ac9965e204c56b6e3d8` | `GHSA-QJPC-QF9M-XWMR` | Cursor trailer; introduced trusted-proxy Control UI authentication that skipped device pairing. |
| `1201cbd82b2cf6d4b56edfc05c763059a12f9fdb` | `GHSA-R48C-V28R-PF6V` | Claude generation and co-author markers; introduced the first `safeDialContext` filter with an incomplete address set. |
| `b7b362ae427ccf4b33b8e8cd147f16410f3ce800` | `GHSA-X2W7-XR2G-QHJR` | Claude trailer; introduced the automation engine's caller-supplied, cross-tenant `contact_id` dispatch. |

## Notable human-origin chains

- GitPython accounts for nine resolved HUMAN rows. Its config serializer originates in `3fd37230e76a014cf5c45d55daf0be2caa6948b7` (2009), tag option forwarding in `1047b41e2e925617474e2e7c9927314f71ce7365` (2009), archive and blame forwarding in the true repository root `33ebe7acec14b25c5f84f35a664803fcab2f7781` (2008), and later URL, revision, and clone-option surfaces in their own human-authored feature commits.
- Faraday's exact protocol-relative host-override condition begins at `d8bfca25fa57c4a807f4a488f087387583c861fe`, which broadened the relative-input shortcut to all leading slashes. The older `base + url` sink was not mislabeled as the introduction of this narrower vulnerability.
- Filebrowser traces through the AI-authored partial scope repair to human commit `8650d2ffe7a29cbafa800efcecbf6a61598a9f0c`, which added the symlink-following `Fs.Stat` path.
- Langroid's SQL chain terminates at human feature commit `434db35a3005a67f241331aa438aff001c8da067`, which passed the model-provided query directly to `session.execute(text(query))` and committed it.
- Fast-uri initially appeared to stop at shallow commit `e6002d944af9dae25f14efb1df56a46401177670`. The permitted 500-commit expansion completed the small repository history and moved the origin to human commit `30aba8ca895f73c2fb41bc5028d5142e164ce5ae`, where both the disagreeing URI parser and `resolve()` were introduced.
- OpenClaw commit `a3d9c53db2999083d1387c1843185c2c9fcecb13` mentions “Codex trajectory writes” in its message but contains no explicit AI author or co-author identity. It is therefore HUMAN under the specification.
- Vitest's browser RPC chain starts at human commit `7b2f64cfa34d087d383d915c08268c0da3f54754`, which created the browser WebSocket RPC with unrestricted snapshot-file writes and configurable command dispatch. Later commits moved the file and added raw CDP handlers, but did not originate the exposed RPC trust boundary.
- Fission's standalone Container chain starts at human commit `70a93a7302d91f21fdb0532513b2b75c983d725f`, which explicitly added Runtime and Builder `Container` objects, including `SecurityContext`, and merged them into scheduled pods. The dangerous-capability PodSpec chain separately starts at human commit `d5785393910b665bc72f2007b816467676c13218`, which added the unrestricted Kubernetes PodSpec field and merge path.

## Unresolved boundaries

| Case | Boundary and reason |
| --- | --- |
| `GHSA-4FXP-2M36-QV64` | The 500-commit Prospero clone stops at `65db768ec3145c01c182b6494f3f15195d2b2125`; the permission mutation surface is already present and its parent is unavailable. |
| `GHSA-6Q7J-XR26-3H2C` | Scriban remains shallow at `9bd2cae4787ac30bb92936d1cdf8eed616cdfb90`; the recursive array-parser surface is already present. |
| `GHSA-Q9PG-JJ6X-J9P6` | Gitea exposes 829 commits from the repair ancestry after deepening, but the oldest reachable boundary `1fe652cd2697b5bb459741f988782163a091c6c8` already has the release-route surface. |
| `GHSA-WPXJ-VHFP-HHVM` | The 500-commit ClearanceKit clone stops at `420eb80f7021e97d754e58970692547b397a5bf8`; the AUTH event policy surface is already present and its parent is unavailable. |

These four records intentionally use `original_introducing_commit: null` and `original_author_kind: "UNKNOWN"`; none transfers an apparent boundary author's identity onto older code.
