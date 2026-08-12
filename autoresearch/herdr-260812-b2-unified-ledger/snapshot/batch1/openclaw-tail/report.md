# OpenClaw-only post-frontier tail

Research window: 2026-08-12 12:17–12:42 EDT

Repository: `openclaw/openclaw`

Owned output: `autoresearch/herdr-260812-openclaw-tail/`

## Result

**No new publication-grade positive was found.** Ten novel routed edges were adjudicated after freezing the current OpenClaw ledger/closure identities: **0 PASS, 10 FAIL**. One edge contains a recovered AI-attributed PR member and its landed squash carrier; the member's feature survives the carrier, but it is not the advisory mechanism. A separate advisory-linked member belongs to a closed, unmerged PR and is retained as negative topology evidence. Eight further routes remain `UNKNOWN` rather than being silently treated as negatives.

This result does not increase the strict component count. It is source-review evidence, not a benchmark, test, or runtime result.

## Scope and snapshot boundary

The shared checkout was intentionally dirty and volatile. At the final read-only status snapshot it was branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`, with 405 status entries. No shared path was edited, staged, formatted, committed, reset, cleaned, fetched, or pushed.

Validation briefly created two zero-byte `/tmp/openclaw-tail-*-check` files; both were deleted immediately and no external artifact remains.

The existing OpenClaw clone was read-only:

- path: `/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`
- worktree HEAD: `86075ed73811b8f4fcd6acd7869b191e17188873`
- frozen remote-tracking ref: `origin/main=fb9a62e9956883c1b0aed5fa742d6e527cb9e86d`
- no fetch or checkout was performed; Git claims below are bound to the existing object/tag database and this ref.

The first-party repository advisory API was snapshotted once. It contains 647 records, all `published`, none withdrawn, spanning publication dates 2026-01-31 through 2026-06-30.

### Frozen inputs

| Input | SHA-256 |
|---|---|
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md` | `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd` |
| `strict-ledger-union-v2/ledger.jsonl` | `282d2975d0ee24e9949cc4d108ad5a1ffd9b045ad8548cc6b1661aaf2c18392e` |
| `strict-200-v3/ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `strict-audit-20260811/class_adjudications_v4.json` | `af8ac38d9f879130b5067afa63a4ee208c9571fbe9c8ddb937699e51c77a5abe` |
| `openclaw-review-packets-v2/packets.jsonl` | `3f6377289094ef4995ca7f4c9f3f510fe0df90a270b98ed59bbc43be6199d710` |
| `openclaw-review-packets-v2/summary.json` | `9fdb47250e431230393ac3e87c89bb1b346dee89e252e05da2aaf0d7a521a74d` |
| `openclaw-blame-screen-v3/exact-direct-candidates.jsonl` | `a65921693400bb29fef202cfeb34944dbb85981bb11aca1d29f23c43c2fd2576` |
| `openclaw-exact-review-deepseek-v2/results.jsonl` | `553c2c3edf383041508878b8edb306e561dd67d12bc03df643358e65379b003b` |
| canonical first-party advisory snapshot `current-advisories.json` | `7512d9eb04a6533188fc23a33f39651b97885225902aac26348ab65589a3a35b` |
| raw paginated API snapshot `current-advisories-pages.json` | `8435983cb7b4954dd5bb0427bc553feb9691de6813c1622cf8340815088fc8e0` |
| independent primary-source notes `agent-source-notes.md` | `c687474383c39cde6ffc162daf755ae675f98216293912c6c73bae8a4e0fdd76` |

## Freeze and exclusion

Before discovery, the following were excluded:

- all 12 closure rows, including its 9 accepted and 3 rejected edges;
- all public IDs, candidate/member/carrier/fix SHAs, and mechanism fingerprints printed in the closure;
- the first-party advisory intersection of the current strict ledger: 37 OpenClaw rows, 74 public IDs, 25 candidate SHAs, 10 carrier SHAs, and 36 fix SHAs;
- every one of the 156 existing audit `class_id` values, regardless of PASS/FAIL/NEEDS_REVIEW, so negative rows could not be recycled;
- already adjudicated mechanism families even when a new diagnostic route pointed at a different SHA.

Each of the ten candidate SHAs and ten GHSA identities below was then checked by exact, case-insensitive search across the closure, union ledger, strict ledger, and audit file; all returned `NONE`. Two tempting routes were explicitly dropped before adjudication: candidate `a39951d4...` was already present in frozen sources, and GHSA-F7FH was already represented by a frozen row.

Blame, same-file overlap, model votes, ancestry, and route packets were used only to select work. They were not accepted as causality.

## Adjudication gates

An edge could be positive only if all of the following closed:

1. exact first-party advisory identity;
2. first-party AI attribution on the candidate unit;
3. if a PR member, member-to-carrier landing and semantic survival;
4. the candidate introduced or materially extended the same security predicate reversed by the fix;
5. a but-for chain, not mere ancestry, shared file, or adjacent hardening;
6. a first released vulnerable version supported by first-party history, or explicit `UNKNOWN` if the lower bound is absent;
7. a released containment commit/tag matching the advisory mechanism.

An AI trailer establishes commit-level co-authorship only, not line-level model generation.

## Row-level evidence

### 1. MiniMax web-search provider -> workspace auth-choice shadowing

- Identity: [GHSA-939r-rj45-g2rj](https://github.com/openclaw/openclaw/security/advisories/GHSA-939r-rj45-g2rj).
- Candidate: [`d204be80af6000f606aef133852359e59c4d7fe5`](https://github.com/openclaw/openclaw/commit/d204be80af6000f606aef133852359e59c4d7fe5), direct commit, `Co-Authored-By: Claude Opus 4.6`, first tag `v2026.4.5`.
- Candidate delta: adds MiniMax as a bundled `web_search` provider, credential/region resolution, registry wiring, and tests.
- Advisory containment: [`2d97eae53e212ae26f3aebcd6a50ffc6877f770d`](https://github.com/openclaw/openclaw/commit/2d97eae53e212ae26f3aebcd6a50ffc6877f770d), first released in `v2026.4.9`; it filters untrusted workspace provider auth choices during setup.
- First released vulnerable version: `UNKNOWN`; the first-party range is `<2026.4.9` and supplies no lower bound.
- But-for: **no**. The candidate adds a web-search capability to an already bundled provider and does not introduce the generic auth-choice trust-resolution defect. The containment is provider-agnostic and reverses workspace-origin selection, not MiniMax search registration.
- Verdict: **FAIL — `NO_BUT_FOR`**.

### 2. Explicit non-loopback extension relay -> default private-network SSRF policy

- Identity: [GHSA-53vx-pmqw-863c](https://github.com/openclaw/openclaw/security/advisories/GHSA-53vx-pmqw-863c).
- Candidate: [`e883d0b556b069d216e76fedbb17d4b59babd35d`](https://github.com/openclaw/openclaw/commit/e883d0b556b069d216e76fedbb17d4b59babd35d), direct, Claude Opus 4.6 trailer, first tag `v2026.3.8`.
- Candidate delta: validates `relayBindHost` as IP and permits non-loopback relay clients only when an operator explicitly selects a non-loopback bind. Token/origin checks remain.
- Advisory containment set: `024f4614a1a1831406e763adc40ef226e3d5e9ed`, [`1dabfef28db523e7de81edeb3dd689e9171236a2`](https://github.com/openclaw/openclaw/commit/1dabfef28db523e7de81edeb3dd689e9171236a2), `213c36cf51121ef6c05cfccd78037371f968f31a`, and `7eecfa411df3d12e6b810e6ca5df47254fc3db3f`; released in `v2026.4.14`.
- First released vulnerable version: `UNKNOWN`; advisory range `<2026.4.14`.
- But-for: **no**. Explicit relay exposure is a distinct operator-selected surface. The advisory reverses browser navigation/CDP private-network policy defaults. Neither the policy object nor `dangerouslyAllowPrivateNetwork` is changed by the candidate.
- Verdict: **FAIL — `DIFFERENT_PREDICATE`**.

### 3. Control UI WebSocket scopes -> assistant-media HTTP scope enforcement

- Identity: [GHSA-v8qf-fr4g-28p2](https://github.com/openclaw/openclaw/security/advisories/GHSA-v8qf-fr4g-28p2).
- Candidate: [`fa0a9ce2af9d8ec656aae323ffb28ef27b8d055d`](https://github.com/openclaw/openclaw/commit/fa0a9ce2af9d8ec656aae323ffb28ef27b8d055d), direct, Claude Opus 4.6 trailer, first tag `v2026.3.22`.
- Candidate delta: adds `operator.read` and `operator.write` to the browser UI's WebSocket connect request so dashboard RPCs work.
- Advisory containment: [`99ef3a63c58440d53f8e45ad861b846032fcb036`](https://github.com/openclaw/openclaw/commit/99ef3a63c58440d53f8e45ad861b846032fcb036), present in beta `v2026.4.19-beta.1`; first-party advisory declares stable containment `2026.4.20`.
- First released vulnerable version: `UNKNOWN`; range `<2026.4.20`.
- But-for: **no**. The affected path is identity-bearing trusted-proxy HTTP `/__openclaw__/assistant-media`, which failed to enforce declared scopes server-side. A UI WebSocket client's requested scope list neither creates nor fixes that HTTP authorization omission.
- Verdict: **FAIL — `DIFFERENT_SURFACE`**.

### 4. Remote-node cwd behavior -> sandboxed `host=node` escape

- Identity: [GHSA-736r-jwj6-4w23](https://github.com/openclaw/openclaw/security/advisories/GHSA-736r-jwj6-4w23).
- Candidate: [`3b3191ab3a5acac6414e2897d8117640f6a3b592`](https://github.com/openclaw/openclaw/commit/3b3191ab3a5acac6414e2897d8117640f6a3b592), direct, Claude Opus 4.6 trailer, first tag `v2026.4.2`.
- Candidate delta: stops injecting the gateway cwd into legitimate remote-node execution when no cwd was explicitly requested.
- First released vulnerable version: `v2026.4.5`, exactly matching the advisory lower bound `>=2026.4.5 <2026.4.10`.
- Advisory containment: [`dffad08529202edbf34e4808788e1182fe10f6a9`](https://github.com/openclaw/openclaw/commit/dffad08529202edbf34e4808788e1182fe10f6a9), released in `v2026.4.10`; it blocks sandboxed `auto` sessions from per-call `node`/`gateway` overrides.
- But-for: **no**. Candidate `v2026.4.2` predates the first affected release and modifies cwd serialization after a legitimate node target is selected. The vulnerability is target-authorization logic before execution.
- Verdict: **FAIL — `PREDATES_AFFECTED_RANGE` and `DIFFERENT_PREDICATE`**.

### 5. ACP gateway readiness -> rawInput tool-identity spoof

- Identity: [GHSA-74wf-h43j-vvmj](https://github.com/openclaw/openclaw/security/advisories/GHSA-74wf-h43j-vvmj).
- Candidate: [`7499e0f6195200de5b401c33d3407d2f457e606c`](https://github.com/openclaw/openclaw/commit/7499e0f6195200de5b401c33d3407d2f457e606c), direct, Claude Opus 4.6 trailer, first tag `v2026.2.22`.
- Candidate delta: starts the gateway and waits for `hello` before constructing/servicing the ACP server connection; only `src/acp/server.ts` changes.
- Advisory containment: [`e4c61723cd2d530680cc61789311d464ab8cdf60`](https://github.com/openclaw/openclaw/commit/e4c61723cd2d530680cc61789311d464ab8cdf60), released in `v2026.3.22`; it fails closed on conflicting `meta`, `rawInput`, and title identity hints in `src/acp/client.ts`.
- First released vulnerable version: `UNKNOWN`; range `<2026.3.22`.
- But-for: **no**. Readiness ordering does not create identity precedence or suppress dangerous-tool prompts.
- Verdict: **FAIL — `DIFFERENT_SURFACE`**.

### 6. Plugin-command hardening -> wildcard sender treated as command owner

- Identity: [GHSA-c28g-vh7m-fm7v](https://github.com/openclaw/openclaw/security/advisories/GHSA-c28g-vh7m-fm7v).
- Candidate: [`6bd6ae41b19371fcfdad43e158dc51d5656e3e5a`](https://github.com/openclaw/openclaw/commit/6bd6ae41b19371fcfdad43e158dc51d5656e3e5a), direct, Claude Opus 4.5 trailer, first containing tag `v2026.1.23`.
- Candidate delta: registry lock, argument sanitization/length cap, handler validation, and safe error handling inside the plugin-command registry. It consumes the precomputed `isAuthorizedSender` value.
- Advisory containment: mainline [`2aa93d44a1b2c7058c371f261fda2b5d4de4a882`](https://github.com/openclaw/openclaw/commit/2aa93d44a1b2c7058c371f261fda2b5d4de4a882) plus release-line `995febb7b1e811ff6a1df5b18c22de94103f4c9f`; the release-line fix is in `v2026.4.21`.
- First released vulnerable version: `UNKNOWN`; range `<=2026.4.20` has no lower bound.
- But-for: **no**. The defect is in `resolveCommandAuthorization`: wildcard channel `allowFrom` leaked into the owner decision when a plugin enforced owner-only commands. The candidate never changes owner identity resolution.
- Verdict: **FAIL — `INCOMPLETE_HARDENING_NOT_CAUSAL`**. This is retained as qualified incomplete hardening, not promoted merely because the candidate is security-themed and touches plugin commands.

### 7. External Twilio outbound calls -> Plivo V2 replay identity

- Identity: [GHSA-cg6c-q2hx-69h7](https://github.com/openclaw/openclaw/security/advisories/GHSA-cg6c-q2hx-69h7).
- Candidate: [`a1b4a0066ba3db1daf526301188b09e28786c456`](https://github.com/openclaw/openclaw/commit/a1b4a0066ba3db1daf526301188b09e28786c456), direct, Claude Opus 4.6 trailer, first tag `v2026.3.2`.
- Candidate delta: auto-registers externally initiated Twilio `outbound-api` calls in the call manager; it does not modify webhook signature or replay-key construction.
- Advisory containment: [`b0ce53a79cf63834660270513e26d921899b4e5b`](https://github.com/openclaw/openclaw/commit/b0ce53a79cf63834660270513e26d921899b4e5b), released in `v2026.3.23`; it derives Plivo V2 replay identity from the signed base URL plus nonce rather than the unsigned query-bearing URL.
- First released vulnerable version: `UNKNOWN`; range `<2026.3.23`.
- But-for: **no**. Different provider, stage, data, and predicate.
- Verdict: **FAIL — `DIFFERENT_PROVIDER_AND_PREDICATE`**.

### 8. Recovered PR member -> squash carrier -> Chromium `--no-sandbox`

- Identity: [GHSA-43x4-g22p-3hrq](https://github.com/openclaw/openclaw/security/advisories/GHSA-43x4-g22p-3hrq).
- Recovered member: [`bd96167364052b3b4b7dbfa5c6aec0a521b5bb08`](https://github.com/openclaw/openclaw/commit/bd96167364052b3b4b7dbfa5c6aec0a521b5bb08), PR #16230 member, Claude Opus 4.6 trailer, no release tag.
- Landed carrier: [`cb9a5e1cb9701546a98b8e0e5ce8427632ada9a0`](https://github.com/openclaw/openclaw/commit/cb9a5e1cb9701546a98b8e0e5ce8427632ada9a0), squash commit, first tag `v2026.2.14`.
- Member-to-carrier survival: **yes, with refinement**. The member's `sandbox.browser.binds` schema/type, merge behavior, and `browserDockerCfg` use all survive in the carrier. The carrier improves the truthiness test to preserve explicit `binds: []`. This is a genuine compositional carrier, not an erased member.
- Candidate mechanism: separate browser-container bind mounts. It does not touch the entrypoint's default Chromium `--no-sandbox` flag.
- First released vulnerable version: `UNKNOWN`; advisory range `<=2026.2.19-2`. Carrier `v2026.2.14` is only a survival witness and is not substituted for the missing lower bound.
- Advisory containment: [`e7eba01efc4c3c400e9cfd3ce3d661cbc788a631`](https://github.com/openclaw/openclaw/commit/e7eba01efc4c3c400e9cfd3ce3d661cbc788a631) removes the default flag; [`1835dec2004fe7a62c6a7ba46b8485f124ec6199`](https://github.com/openclaw/openclaw/commit/1835dec2004fe7a62c6a7ba46b8485f124ec6199) forces stale-container migration/auditing. Both are released in `v2026.2.21`.
- But-for: **no**. The member survives, but its bind-mount feature is orthogonal to the browser OS-sandbox flag. Same-file overlap with the migration fix is not causality.
- Verdict: **FAIL — `MEMBER_SURVIVES_BUT_DIFFERENT_MECHANISM`**.

### 9. Typing indicator -> directionally wrong `/send` “fix” route

- Identity: [GHSA-39mp-545q-w789](https://github.com/openclaw/openclaw/security/advisories/GHSA-39mp-545q-w789).
- Candidate: [`29c5ed54b276e8e65e2e894d0d29cc5ccbbadddd`](https://github.com/openclaw/openclaw/commit/29c5ed54b276e8e65e2e894d0d29cc5ccbbadddd), direct, explicit “Generated with Claude Code” plus Claude trailer, first tag `v2026.1.8`.
- Candidate delta: keeps a typing indicator alive when tool-start events occur. It does not touch `/send`, `senderIsOwner`, command authorization, or session `sendPolicy`.
- Routed purported fix: [`ea018a68ccb92dbc735bc1df9880d5c95c63ca35`](https://github.com/openclaw/openclaw/commit/ea018a68ccb92dbc735bc1df9880d5c95c63ca35). The first-party advisory instead identifies it as the earliest vulnerable handler/history point, first released in `v2026.1.14-1`.
- First released vulnerable version: `v2026.1.14-1`, explicitly stated by the advisory.
- Actual containment: [`47dc7fe816006dfc49bdcfca74e66c5ba46d4de8`](https://github.com/openclaw/openclaw/commit/47dc7fe816006dfc49bdcfca74e66c5ba46d4de8), released in `v2026.3.24`, requiring owner status for `/send` policy changes.
- But-for: **no**; the candidate predates and is unrelated to the affected handler. The route also reverses fix direction.
- Verdict: **FAIL — `WRONG_FIX_IDENTITY` and `UNRELATED_CANDIDATE`**.

### 10. Image-generator filename extension -> exporter MIME XSS identity mismatch

- Identity: [GHSA-2ww6-868g-2c56](https://github.com/openclaw/openclaw/security/advisories/GHSA-2ww6-868g-2c56).
- Candidate: [`6ac1c1d6ea0359069cf8d4c6e73ea20c0dad54e2`](https://github.com/openclaw/openclaw/commit/6ac1c1d6ea0359069cf8d4c6e73ea20c0dad54e2), direct, explicit “Generated with Claude Code” plus Claude Opus 4.5 trailer, first tag `v2026.1.15`.
- Candidate delta: makes `skills/openai-image-gen/scripts/gen.py` use the requested output filename extension.
- Diagnostic routed fix: [`f3adf142c195000cbde31200626a1d8c8b716df9`](https://github.com/openclaw/openclaw/commit/f3adf142c195000cbde31200626a1d8c8b716df9), gallery HTML escaping in the same image-generator script, first tag `v2026.2.23`.
- Advisory-linked PR #24140: `state=closed`, `merged_at=null`, no merge SHA. Its only member, `d93d22fc48443b8dcc9544ff93fdcba42b0eff49`, never landed and is therefore negative topology evidence, not released containment.
- Advisory mechanism: unvalidated `img.mimeType` interpolated into data URLs in `src/auto-reply/reply/export-html/template.js`.
- First released vulnerable version: `UNKNOWN`; first-party range is `<=2026.2.22` without a lower bound.
- Actual mainline containment: [`f8524ec77a3999d573e6c6b8a5055bf35c49a2e6`](https://github.com/openclaw/openclaw/commit/f8524ec77a3999d573e6c6b8a5055bf35c49a2e6) plus [`e578521ef4930d02c573fa2d9ef72c4317a34dd6`](https://github.com/openclaw/openclaw/commit/e578521ef4930d02c573fa2d9ef72c4317a34dd6), both released in `v2026.2.23`.
- But-for: **no**. The candidate and routed fix concern an image-generator gallery; the advisory concerns session-export MIME data. A possibly useful hardening cannot borrow an unrelated GHSA identity. The unmerged member cannot be counted.
- Verdict: **FAIL — `PUBLIC_ID_FIX_MECHANISM_MISMATCH` and `UNMERGED_MEMBER`**.

## Preserved UNKNOWN routes

The following exact-blame routes survived the freeze but were not independently replayed within this bounded shard. They remain diagnostic `UNKNOWN`; shared candidates/fixes are not assumed to make public IDs aliases.

```text
CVE-2026-28446 / GHSA-4RJ2-GPMH-QQ5X  8b4696c0 -> f8dfd034
CVE-2026-32899 / GHSA-RM2P-J3R7-4X4J  5aed38ee -> aedf62ac
CVE-2026-32062 / GHSA-MFG5-7Q5G-F37J  8b4696c0 -> 1d8968c8
CVE-2026-28465 / GHSA-3M3Q-X3GJ-F79X  8b4696c0 -> a749db98
CVE-2026-28465 / GHSA-3M3Q-X3GJ-F79X  b9643ad6 -> a749db98
CVE-2026-26319 / GHSA-4HG8-92X6-H2F3  8b4696c0 -> 29b587e7
CVE-2026-27670 / GHSA-2G8C-6QFQ-528M  f5c2be19 -> 7dac9b05
CVE-2026-26326 / GHSA-8MH7-PHF8-XGFM  5af322f7 -> d3428053
```

The repository advisory API currently has `cve_id=null` for many rows even when routing artifacts carry a CVE string. The GHSA is therefore the first-party identity anchor; routing CVE aliases are not promoted without first-party linkage.

## Exact primary sources and commands

Primary sources were the first-party repository advisory API, first-party pull API, and the frozen first-party Git object/tag database. No broad build, full-corpus rerun, test suite, or mutable cache was used.

```zsh
# One bounded first-party advisory snapshot
gh api --paginate --slurp \
  'repos/openclaw/openclaw/security-advisories?per_page=100' \
  > autoresearch/herdr-260812-openclaw-tail/current-advisories-pages.json

# Hash-bound input freeze
sha256sum \
  docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md \
  docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md \
  docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-audit-20260811/class_adjudications_v4.json

# Exact exclusion check, repeated for each selected candidate and GHSA
rg -i -l "$needle" \
  docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md \
  autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl \
  autoresearch/orchestrator-260811-atomic150/strict-audit-20260811/class_adjudications_v4.json

# Candidate attribution/delta and containment reversal
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  show --format=fuller --unified=25 <candidate>
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  show --format=fuller --unified=25 <fix>

# Released topology witness; the result is not used as causality
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  tag --contains <sha> | rg '^v2026\.' | sort -V | head -n 1

# Advisory-linked PR topology negative control
gh api repos/openclaw/openclaw/pulls/24140 \
  --jq '[.state,.merged_at,.merge_commit_sha,.html_url] | @tsv'
gh api 'repos/openclaw/openclaw/pulls/24140/commits?per_page=100' \
  --jq '.[] | [.sha,.commit.author.date,.commit.message] | @tsv'

# Locate actual mainline containment rather than trusting a routed fix label
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  log origin/main -S'sanitizeImageMimeType' \
  --format='%H %ad %s' --date=iso-strict -- \
  src/auto-reply/reply/export-html/template.js
```

## Claim boundary

- **New strict positives: 0.** None of these rows may increase the 125-component lower bound or any OpenClaw subtotal.
- All ten candidates have first-party commit-level AI markers, but those markers do not prove that every changed line was model-generated.
- A tag is only a release-entry witness. When the advisory omits a lower bound, the first vulnerable release remains `UNKNOWN`; the candidate's first tag is not substituted.
- The recovered PR #16230 member survives its squash carrier, yet fails the exact-mechanism/but-for gate. Carrier survival alone is not a positive.
- No new erased squash member was promoted. The erased member already rejected by the frontier closure stayed frozen as a known negative and was not recycled into this tail.
- PR #24140 is closed and unmerged. Its member is not released code and remains negative, even though equivalent containment later landed through different commits.
- Incomplete security-themed work remains qualified negative: command sanitization does not become owner-authorization causality.
- Routing artifacts, source recovery, ancestry, tests in commits, same-file overlap, and model votes are diagnostic only.
- No runtime exploit, package publication query, or independent reproduction was run. Released containment is supported by first-party advisory text plus local tag ancestry, not live package execution.

## Counts

```json
{
  "first_party_advisories_snapshotted": 647,
  "frozen_existing_openclaw_rows": 37,
  "frozen_existing_public_ids": 74,
  "frozen_existing_candidate_shas": 25,
  "frozen_existing_carrier_shas": 10,
  "frozen_existing_fix_shas": 36,
  "frozen_closure_rows": 12,
  "frozen_audit_classes": 156,
  "novel_edges_adjudicated": 10,
  "publication_grade_positives": 0,
  "negative_edges": 10,
  "member_carrier_edges": 1,
  "unmerged_member_controls": 1,
  "unknown_routes_preserved": 8
}
```
