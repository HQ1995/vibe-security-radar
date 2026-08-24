# Batch 2 OpenClaw primary-source notes: routes 01, 03, 04, and 06

## Result

All four assigned routes close as **REJECT**. The shared candidate
[`8b4696c087aed2256c74d106b58367406fb96a53`](https://github.com/openclaw/openclaw/commit/8b4696c087aed2256c74d106b58367406fb96a53)
is a direct, one-parent mainline commit with a `Co-Authored-By: Claude
<noreply@anthropic.com>` trailer. It only makes provider credential validation
honor environment variables. Its parent already contains every affected
security predicate below, and the candidate changes none of them. Configuration
reachability is not the advisory mechanism and cannot inherit four unrelated
GHSA identities.

Assigned-count closure: `REJECT=4`, `PASS=0`, `STILL_BLOCKED=0`,
`STILL_UNKNOWN=0`.

## Snapshot boundary

- Frozen eight-row manifest:
  `autoresearch/herdr-260812-b2-openclaw-unknowns/manifest.json`, SHA-256
  `d48aeadbbf4c24ef1f6408abf7d4cf21e8a26424d0155df43b4c858636692324`.
- Batch 1 report (used only to preserve the exact UNKNOWN scope):
  `autoresearch/herdr-260812-openclaw-tail/report.md`, SHA-256
  `31b8dad43be966e78a0175bbb9775083e50a02f80dccc122b9d74aaf0947e16b`.
- Frozen first-party repository-advisory snapshot:
  `autoresearch/herdr-260812-openclaw-tail/current-advisories.json`, SHA-256
  `7512d9eb04a6533188fc23a33f39651b97885225902aac26348ab65589a3a35b`.
- Read-only first-party Git object database:
  `/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`, with
  `origin/main=fb9a62e9956883c1b0aed5fa742d6e527cb9e86d` at inspection time
  (`2026-08-12T12:53:20-04:00`). No fetch, checkout, build, test, or cache
  mutation was performed.
- Candidate topology: parent
  `c6cdbb630c926b0be95921ba55cd6127f9fd1f56`; candidate and all routed fixes
  are ancestors of the frozen `origin/main`; candidate is an ancestor of each
  routed fix. There is no member/carrier pair in these frozen rows: the
  candidate itself is the directly landed commit. Its first containing
  OpenClaw release tag is `v2026.1.29`.

The repository-advisory snapshot has `cve_id=null` for the first three GHSAs.
Precise reads of GitHub's first-party global advisory API independently confirm
all four routed CVE aliases. No routing CVE was accepted without that identity
check.

## Row-level closure

### b2-oc-01 — REJECT

- **Identity:** [GHSA-4RJ2-GPMH-QQ5X](https://github.com/openclaw/openclaw/security/advisories/GHSA-4rj2-gpmh-qq5x) is published and not withdrawn; GitHub's global advisory identifies it as
  `CVE-2026-28446`. Affected `openclaw <2026.2.2`; first patched version
  `2026.2.2`.
- **Candidate/parent:** candidate `8b4696c0` changes only
  `validateProviderConfig()` checks for Telnyx/Twilio/Plivo credential
  environment variables. Parent `c6cdbb63` already has the vulnerable inbound
  allowlist predicate: empty normalization plus symmetric suffix matching
  (`normalized.endsWith(normalizedAllow)` and the reverse).
- **Actual mechanism/fix:** the advisory is empty caller-ID and suffix-collision
  allowlist bypass. The advisory-specific fix
  [`f8dfd034`](https://github.com/openclaw/openclaw/commit/f8dfd034f5d9235c5485f492a9e4ccc114e97fdb)
  rejects empty normalized callers and replaces suffix matching with strict
  equality in a dedicated `isAllowlistedCaller()` helper.
- **Released containment:** history search finds the affected predicate entering
  at [`42c17adb`](https://github.com/openclaw/openclaw/commit/42c17adb5e4d3ea1f9b1d2fd921b9abc183b79df);
  the first local OpenClaw release tag containing it is `v2026.1.12`. The fix's
  first containing release tag is `v2026.2.2`, matching the advisory.
- **Why rejected:** `PARENT_ALREADY_VULNERABLE` +
  `NO_CANDIDATE_MECHANISM_DELTA`. Direct-mainline survival and ancestry are
  diagnostic only.

### b2-oc-03 — REJECT

- **Identity:** [GHSA-MFG5-7Q5G-F37J](https://github.com/openclaw/openclaw/security/advisories/GHSA-mfg5-7q5g-f37j) is published and not withdrawn; the global advisory identifies it as
  `CVE-2026-32062`. Both `openclaw` and `@openclaw/voice-call` are affected
  `<2026.2.22`; first patched version is `2026.2.22`.
- **Candidate/parent:** candidate `8b4696c0` has no media-stream or webhook-server
  delta. Its parent already calls `WebSocketServer.handleUpgrade()` immediately
  and waits for a later `start` message; no pre-start timeout or connection cap
  exists in that baseline.
- **Actual mechanism/fix:** the advisory is unauthenticated pre-start upgraded
  sockets consuming connection resources. The exact fix
  [`1d8968c8`](https://github.com/openclaw/openclaw/commit/1d8968c8a821ff1a05c294a1846b3bcb6f343794)
  adds a pre-start timeout, global/per-IP pending caps, total connection cap,
  pending-socket accounting, and safer upgrade-path parsing.
- **Released containment:** the affected media-stream handler entered in
  `42c17adb`; its first containing OpenClaw tag is `v2026.1.12`. The fix's first
  containing tag is `v2026.2.22`, matching the advisory.
- **Why rejected:** `PARENT_ALREADY_VULNERABLE` +
  `DIFFERENT_PREDICATE`. Credential-validation reachability is not the
  pre-auth WebSocket resource-control mechanism.

### b2-oc-04 — REJECT

- **Identity:** [GHSA-3M3Q-X3GJ-F79X](https://github.com/openclaw/openclaw/security/advisories/GHSA-3m3q-x3gj-f79x) is published and not withdrawn; the global advisory identifies it as
  `CVE-2026-28465`. `@openclaw/voice-call <2026.2.3` is affected and
  `2026.2.3` is first patched. The legacy `@clawdbot/voice-call <=2026.1.24`
  row has no patched legacy release.
- **Candidate/parent:** candidate `8b4696c0` does not change
  `webhook-security.ts`, request headers, URL reconstruction, or proxy trust.
  Its parent already trusts `X-Forwarded-Proto`, `X-Forwarded-Host`,
  `X-Original-Host`, and `Ngrok-Forwarded-Host` without an explicit trust or
  host-allowlist gate.
- **Actual mechanism/fix:** the advisory is signature-verification URL influence
  through untrusted forwarding headers. The exact fix
  [`a749db98`](https://github.com/openclaw/openclaw/commit/a749db9820eb6d6224032a5a34223d286d2dcc2f)
  ignores forwarding headers by default and adds explicit allowed-host,
  trusted-proxy-IP, and forwarding-trust controls.
- **Released containment:** the vulnerable reconstructor entered in
  `42c17adb`; its first containing OpenClaw tag is `v2026.1.12`. The fix's first
  containing tag is `v2026.2.3`, matching the advisory. This establishes the
  OpenClaw package lower bound only; the legacy predecessor's first vulnerable
  release remains `UNKNOWN`.
- **Why rejected:** `PARENT_ALREADY_VULNERABLE` +
  `NO_PROXY_TRUST_DELTA`. Shared component/config adjacency is insufficient.

### b2-oc-06 — REJECT

- **Identity:** [GHSA-4HG8-92X6-H2F3](https://github.com/openclaw/openclaw/security/advisories/GHSA-4hg8-92x6-h2f3) is published and not withdrawn. Both repository and global advisories identify it as
  `CVE-2026-26319`; affected `openclaw <2026.2.14`, first patched
  `2026.2.14`.
- **Candidate/parent:** candidate `8b4696c0` only permits `TELNYX_API_KEY` and
  `TELNYX_CONNECTION_ID` to satisfy provider credential validation. It does not
  touch `TELNYX_PUBLIC_KEY`, `telnyx.publicKey`, or `verifyWebhook()`. Its
  parent explicitly returns `{ok: true}` when the public key is missing.
- **Actual mechanism/fix:** the advisory is fail-open Telnyx webhook
  authentication. The primary containment
  [`29b587e7`](https://github.com/openclaw/openclaw/commit/29b587e73cbdc941caec573facd16e87d52f007b)
  requires the public key unless an explicit development-only bypass is set and
  returns failure when the key is absent. The advisory also names
  [`f47584fe`](https://github.com/openclaw/openclaw/commit/f47584fec86d6d73f2d483043a2ad0e7e3c50411),
  which centralizes verification and strengthens key/timestamp handling.
- **Released containment:** the fail-open verifier entered in `42c17adb`; its
  first containing OpenClaw tag is `v2026.1.12`. Both named containment commits
  first appear in `v2026.2.14`, matching the advisory.
- **Why rejected:** `PARENT_ALREADY_VULNERABLE` +
  `NO_AUTH_PREDICATE_DELTA`. Making an already-supported environment credential
  pass validation is not a but-for cause of missing webhook authentication.

## Exact read commands

All local Git reads used the required maintenance-disable flags. Representative
commands (repeated for each SHA/path) were:

```zsh
sha256sum \
  autoresearch/herdr-260812-b2-openclaw-unknowns/manifest.json \
  autoresearch/herdr-260812-openclaw-tail/report.md \
  autoresearch/herdr-260812-openclaw-tail/current-advisories.json

jq '[.[] | select(.ghsa_id == "GHSA-4rj2-gpmh-qq5x")]' \
  autoresearch/herdr-260812-openclaw-tail/current-advisories.json

git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  -c gc.auto=0 -c maintenance.auto=false \
  show --format=fuller --stat <candidate-or-fix>

git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  -c gc.auto=0 -c maintenance.auto=false \
  show <candidate-parent>:<path>

git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  -c gc.auto=0 -c maintenance.auto=false \
  log --reverse -S '<advisory-specific predicate>' origin/main -- <path>

git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  -c gc.auto=0 -c maintenance.auto=false \
  tag --contains <sha>

git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  -c gc.auto=0 -c maintenance.auto=false \
  merge-base --is-ancestor <sha> <descendant>

gh api 'advisories/<GHSA>' --jq \
  '{ghsa_id,cve_id,identifiers,published_at,updated_at,withdrawn_at,vulnerabilities}'
```

## Claim boundary

These four labels reject candidate-to-advisory causal edges; they do not reject
the advisories. First-party advisory identity, exact source deltas, and released
tag containment support the mechanism histories. Direct reachability, ancestry,
tag containment, AI trailers, and path overlap alone remain diagnostic. The
`v2026.1.12` lower bounds are the first locally provable **OpenClaw-tagged**
containment of the affected predicates; they do not establish earlier legacy
package history. No Batch 1 negative was reopened, no new positive may be added,
and no test result is claimed.
