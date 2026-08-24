# Batch 2: closure of eight preserved OpenClaw UNKNOWN routes

Research window: 2026-08-12 12:47–13:00 EDT

Repository: `openclaw/openclaw`

Output directory: `autoresearch/herdr-260812-b2-openclaw-unknowns/`

## Result

All eight frozen routes were attempted and closed: **0 PASS, 8 REJECT, 0 STILL_BLOCKED, 0 STILL_UNKNOWN**.

Every candidate is a direct, one-parent, AI-attributed mainline commit; none is a recovered PR member or squash carrier, so member-to-carrier survival is `NOT_APPLICABLE` for all eight. Parent-baseline inspection shows the advisory predicate already present before every candidate. Each routed fix is advisory-specific and released, but no candidate introduces or materially extends that predicate. The closure therefore rejects eight candidate-to-advisory causal edges; it does not reject the advisories.

No Batch 1 negative was reopened. No row increases the publication-grade positive count.

## Frozen manifest and snapshot boundary

The exact eight rows were copied from Batch 1's `Preserved UNKNOWN routes` section before adjudication and frozen in `manifest.json`:

- manifest SHA-256: `d48aeadbbf4c24ef1f6408abf7d4cf21e8a26424d0155df43b4c858636692324`
- source Batch 1 report SHA-256: `31b8dad43be966e78a0175bbb9775083e50a02f80dccc122b9d74aaf0947e16b`
- source Batch 1 result SHA-256: `51255be05c41b417f17bc426d6d048bfb316f0a6728511a418b9660d2be9db90`
- frozen repository-advisory snapshot SHA-256: `7512d9eb04a6533188fc23a33f39651b97885225902aac26348ab65589a3a35b`
- background primary-source notes SHA-256: `6bdae07478cdf4005462bb744f60a17fdf9be8df4216357b941228c50ce0598e`

Shared checkout read-only snapshot:

- branch `dev`
- HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`
- 405 status entries at start

Read-only OpenClaw object database:

- `/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`
- worktree HEAD `86075ed73811b8f4fcd6acd7869b191e17188873`
- `origin/main=fb9a62e9956883c1b0aed5fa742d6e527cb9e86d`

No fetch, checkout, build, test, stage, commit, reset, clean, or cache mutation was performed. All Git reads used `-c gc.auto=0 -c maintenance.auto=false`. The existing shared first-party clone and advisory snapshot were read-only; precise first-party global GHSA calls were used only to close missing CVE aliases.

## Conservation and labels

The machine ledger is `closure-ledger.jsonl`, one record per frozen manifest row. Its closure vocabulary is exactly `PASS`, `REJECT`, `STILL_BLOCKED`, or `STILL_UNKNOWN`.

| Closure | Count |
|---|---:|
| PASS | 0 |
| REJECT | 8 |
| STILL_BLOCKED | 0 |
| STILL_UNKNOWN | 0 |
| Total | 8 |

No `NARROW` condition remained after first-party identity and mechanism review. `NARROW` was used as an internal evidence posture only: a row could be rejected only as a candidate causal edge, never as an advisory. There are no unrepresented, dropped, or duplicate manifest rows.

## Row-level closure

### b2-oc-01 — REJECT — inbound caller allowlist bypass

- Identity: [GHSA-4rj2-gpmh-qq5x](https://github.com/openclaw/openclaw/security/advisories/GHSA-4rj2-gpmh-qq5x); first-party global GHSA confirms routed `CVE-2026-28446`.
- Candidate: [`8b4696c087aed2256c74d106b58367406fb96a53`](https://github.com/openclaw/openclaw/commit/8b4696c087aed2256c74d106b58367406fb96a53), direct mainline, Claude trailer, first tag `v2026.1.29`. It only lets provider credential validation accept environment variables.
- Parent baseline: `c6cdbb630c926b0be95921ba55cd6127f9fd1f56` already accepts empty normalized caller IDs and symmetric suffix matches.
- Exact mechanism/fix: [`f8dfd034f5d9235c5485f492a9e4ccc114e97fdb`](https://github.com/openclaw/openclaw/commit/f8dfd034f5d9235c5485f492a9e4ccc114e97fdb) rejects empty callers and requires strict equality.
- Release containment: first locally provable OpenClaw vulnerable tag `v2026.1.12`; fixed `v2026.2.2`.
- Decision: `PARENT_ALREADY_VULNERABLE` + `NO_CANDIDATE_MECHANISM_DELTA`.

### b2-oc-02 — REJECT — Slack non-message sender policy

- Identity: [GHSA-rm2p-j3r7-4x4j](https://github.com/openclaw/openclaw/security/advisories/GHSA-rm2p-j3r7-4x4j); repository and global GHSA confirm `CVE-2026-32899`.
- Candidate: [`5aed38eebc09cd370d1529554a2eaf0e2d53111d`](https://github.com/openclaw/openclaw/commit/5aed38eebc09cd370d1529554a2eaf0e2d53111d), direct mainline, Codex trailer, first tag `v2026.1.20`.
- Parent baseline: Slack `reaction_*` and `pin_*` handlers already enqueue system events without sender-policy checks; those handlers first appear in local tag `v2026.1.5`.
- Candidate delta: Discord guild/thread reaction channel fallback and allowlist handling. Its incidental Slack change records channel match provenance; it does not authorize Slack event senders.
- Exact mechanism/fix: [`aedf62ac7e669a89c7b299201bf6537dc6b12e0e`](https://github.com/openclaw/openclaw/commit/aedf62ac7e669a89c7b299201bf6537dc6b12e0e) and `75dfb71e4e8b7c2feba5a8ca662f92ea840e0147` apply DM/channel-user sender policy to Slack reactions/pins.
- Release containment: vulnerable `v2026.1.5`; fixed `v2026.2.25`.
- Decision: `PARENT_ALREADY_VULNERABLE` + `DIFFERENT_PROVIDER` + `DIFFERENT_PREDICATE`.

### b2-oc-03 — REJECT — pre-start voice media sockets

- Identity: [GHSA-mfg5-7q5g-f37j](https://github.com/openclaw/openclaw/security/advisories/GHSA-mfg5-7q5g-f37j); global GHSA confirms `CVE-2026-32062`.
- Candidate: `8b4696c0...`, as above.
- Parent baseline: the media handler already upgrades WebSockets before the later `start` message and lacks pending timeout/per-IP/global caps.
- Exact mechanism/fix: [`1d8968c8a821ff1a05c294a1846b3bcb6f343794`](https://github.com/openclaw/openclaw/commit/1d8968c8a821ff1a05c294a1846b3bcb6f343794) adds pre-start timeout, pending/total caps, accounting, and safer upgrade parsing.
- Release containment: first locally provable vulnerable OpenClaw tag `v2026.1.12`; fixed `v2026.2.22`.
- Decision: `PARENT_ALREADY_VULNERABLE` + `DIFFERENT_PREDICATE`.

### b2-oc-04 — REJECT — forwarded-header webhook verification

- Identity: [GHSA-3m3q-x3gj-f79x](https://github.com/openclaw/openclaw/security/advisories/GHSA-3m3q-x3gj-f79x); repository/global GHSA confirm `CVE-2026-28465`.
- Candidate: `8b4696c0...`, as above.
- Parent baseline: webhook URL reconstruction already trusts forwarding host/protocol headers without an explicit proxy-trust or hostname-allowlist gate.
- Exact mechanism/fix: [`a749db9820eb6d6224032a5a34223d286d2dcc2f`](https://github.com/openclaw/openclaw/commit/a749db9820eb6d6224032a5a34223d286d2dcc2f) ignores them by default and adds allowed-host, trusted-proxy-IP, and explicit trust controls.
- Release containment: first locally provable vulnerable OpenClaw tag `v2026.1.12`; fixed `v2026.2.3`. The legacy `@clawdbot/voice-call` lower bound remains outside this claim.
- Decision: `PARENT_ALREADY_VULNERABLE` + `NO_PROXY_TRUST_DELTA`.

### b2-oc-05 — REJECT — same advisory, private Fly documentation candidate

- Identity/mechanism/fix/release: same GHSA-3M3Q edge and containment as b2-oc-04.
- Candidate: [`b9643ad60ec5ee96ed87ab7802f8c065763ed2b9`](https://github.com/openclaw/openclaw/commit/b9643ad60ec5ee96ed87ab7802f8c065763ed2b9), direct mainline, Claude Opus 4.5 trailer, first tag `v2026.1.29`.
- Parent baseline: vulnerable webhook reconstructor already present.
- Candidate delta: only `docs/platforms/fly.md` and new `fly.private.toml`; no webhook, signature, header, provider, or proxy-trust runtime code.
- Decision: `DOCS_CONFIG_ONLY` + `PARENT_ALREADY_VULNERABLE` + `NO_WEBHOOK_RUNTIME_DELTA`. Private deployment guidance may narrow exposure, but mitigation/config adjacency is not causal introduction.

### b2-oc-06 — REJECT — Telnyx missing webhook authentication

- Identity: [GHSA-4hg8-92x6-h2f3](https://github.com/openclaw/openclaw/security/advisories/GHSA-4hg8-92x6-h2f3); repository/global GHSA confirm `CVE-2026-26319`.
- Candidate: `8b4696c0...`; it recognizes `TELNYX_API_KEY` and `TELNYX_CONNECTION_ID` during validation but does not touch `TELNYX_PUBLIC_KEY` or webhook verification.
- Parent baseline: missing Telnyx public key already returns successful verification.
- Exact mechanism/fix: [`29b587e73cbdc941caec573facd16e87d52f007b`](https://github.com/openclaw/openclaw/commit/29b587e73cbdc941caec573facd16e87d52f007b) fails closed absent a public key except explicit development bypass; `f47584fec86d6d73f2d483043a2ad0e7e3c50411` centralizes and strengthens verification.
- Release containment: first locally provable vulnerable OpenClaw tag `v2026.1.12`; both fixes in `v2026.2.14`.
- Decision: `PARENT_ALREADY_VULNERABLE` + `NO_AUTH_PREDICATE_DELTA`.

### b2-oc-07 — REJECT — ZIP extraction parent-symlink race

- Identity: global [GHSA-2g8c-6qfq-528m](https://github.com/advisories/GHSA-2g8c-6qfq-528m) confirms `CVE-2026-27670` and directly aliases repository [GHSA-r54r-wmmq-mh84](https://github.com/openclaw/openclaw/security/advisories/GHSA-r54r-wmmq-mh84), the same fix and mechanism.
- Candidate: [`f5c2be19105d2dd2429ce073dfb07c1a8806e03c`](https://github.com/openclaw/openclaw/commit/f5c2be19105d2dd2429ce073dfb07c1a8806e03c), direct mainline, Claude Opus 4.6 trailer, first tag `v2026.3.1`.
- Parent baseline: the incomplete ZIP hardening from `4b226b74...` is already present: path validation occurs before `fs.open(... O_TRUNC ...)`, leaving a parent-rebind race.
- Candidate delta: only introduces an `outside-workspace` error code and caller-facing mappings; it adds no archive or file-open behavior.
- Exact mechanism/fix: [`7dac9b05dd9d38dd3929637f26fa356fd8bdd107`](https://github.com/openclaw/openclaw/commit/7dac9b05dd9d38dd3929637f26fa356fd8bdd107) binds validation to the opened file identity, defers truncate until containment checks, and handles created-file cleanup.
- Release containment: first vulnerable implementation tag `v2026.2.22`; fixed `v2026.3.2`.
- Decision: `PARENT_ALREADY_VULNERABLE` + `ERROR_TAXONOMY_ONLY` + `NO_ARCHIVE_DELTA`.

### b2-oc-08 — REJECT — `skills.status` config secret leak

- Identity: [GHSA-8mh7-phf8-xgfm](https://github.com/openclaw/openclaw/security/advisories/GHSA-8mh7-phf8-xgfm); repository/global GHSA confirm `CVE-2026-26326`.
- Candidate: [`5af322f710be2af011d4fc53de1b39fc77e73ccb`](https://github.com/openclaw/openclaw/commit/5af322f710be2af011d4fc53de1b39fc77e73ccb), direct mainline, Claude Opus 4.5 trailer, first tag `v2026.2.3`.
- Parent baseline: `skills.status` already returns `configChecks[].value`; first local tag with that serialization is `v2026.1.5`. The candidate's parent already has broad Discord metadata `requires.config=["channels.discord"]`.
- Candidate delta: adds Discord set-presence functionality and edits prose in `skills/discord/SKILL.md`, but leaves that metadata exact string unchanged and never touches status serialization.
- Exact mechanism/fix: [`d3428053d95eefbe10ecf04f92218ffcba55ae5a`](https://github.com/openclaw/openclaw/commit/d3428053d95eefbe10ecf04f92218ffcba55ae5a) removes raw values and narrows the Discord requirement to `channels.discord.token`; `ebc68861a61067fc37f9298bded3eec9de0ba783` completes release containment.
- Release containment: vulnerable `v2026.1.5`; fixed `v2026.2.14`.
- Decision: `PARENT_ALREADY_VULNERABLE` + `METADATA_UNCHANGED` + `NO_STATUS_SERIALIZATION_DELTA`.

## Exact commands and first-party sources

Representative commands, repeated with exact SHAs and relevant paths:

```zsh
# Freeze and validate the eight-row manifest
sha256sum \
  autoresearch/herdr-260812-openclaw-tail/report.md \
  autoresearch/herdr-260812-openclaw-tail/result.json \
  autoresearch/herdr-260812-openclaw-tail/current-advisories.json \
  autoresearch/herdr-260812-b2-openclaw-unknowns/manifest.json
jq -e '.rows | length == 8' \
  autoresearch/herdr-260812-b2-openclaw-unknowns/manifest.json

# Candidate and exact parent baseline
git -c gc.auto=0 -c maintenance.auto=false \
  -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  show --format=fuller --unified=35 <candidate>
git -c gc.auto=0 -c maintenance.auto=false \
  -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  show <candidate-parent>:<affected-path>

# Predicate introduction and released topology
git -c gc.auto=0 -c maintenance.auto=false \
  -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  log --reverse -S'<advisory-specific predicate>' --format='%H|%cI|%s' -- <path>
git -c gc.auto=0 -c maintenance.auto=false \
  -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  tag --contains <sha> | rg '^v[0-9]{4}\.' | sort -V | head -n 1
git -c gc.auto=0 -c maintenance.auto=false \
  -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  merge-base --is-ancestor <sha> origin/main

# Precise first-party identity closure where repository snapshot has null cve_id
gh api 'advisories/<GHSA>' --jq \
  '{ghsa_id,cve_id,published_at,withdrawn_at,description,vulnerabilities,references}'
```

Sources were the first-party OpenClaw repository advisory records, GitHub's first-party global advisory aliases, the first-party Git history, and local release tags. Routing artifacts and model results selected rows only.

## Claim boundary

- `REJECT` means the candidate-to-advisory causal edge fails. It does not dispute that the vulnerability or fix is real.
- All eight candidates have commit-level AI attribution. That does not establish line-level model generation.
- Direct landing, ancestry, release tags, shared files, tests included in commits, and source recovery are diagnostic until exact same-mechanism and but-for gates close.
- Parent baselines establish that each vulnerability predates its routed candidate. A candidate that improves reachability, documentation, error wording, or adjacent channel behavior does not become the vulnerability's introduction.
- “First released vulnerable” means the earliest locally provable OpenClaw tag containing the exact affected predicate. It is not a universal lower bound for earlier legacy packages. The legacy `@clawdbot/voice-call` lower bound remains unknown.
- No runtime exploit, build, package install, or test suite was run. Released containment is supported by first-party advisory identity, exact fix reversal, and local tag ancestry.
- Batch 1's ten negative rows remain frozen and unopened.

## Artifact hashes

- `manifest.json`: `d48aeadbbf4c24ef1f6408abf7d4cf21e8a26424d0155df43b4c858636692324`
- `closure-ledger.jsonl`: `bf57b939f19434816c82b54edcc832b41cba96053738556a80d37a7e8cf7000d`
- `agent-primary-notes.md`: `6bdae07478cdf4005462bb744f60a17fdf9be8df4216357b941228c50ce0598e`
