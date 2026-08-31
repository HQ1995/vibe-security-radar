# Provisional closure audit — shard 01

Date: 2026-08-31  
Scope: eight provisional cases assigned to shard 01, plus the requested
`CVE-2026-55828` confirmed-status anomaly.  This is a read/replay report; it
does not mutate the ledger or publisher inputs.

## Method and decision rule

I read `docs/AUDIT-PROTOCOL.md` in full, then reconciled the current ledger's
`round11_research`, the Round11 primary and independent-review records, the
current published catalog, the specified full-history clones, and the linked
first-party advisories.  `PASS` below means the gate is closed by replayable
evidence. `NARROW` means the evidence supports a bounded claim but not a
broader release/remediation statement. `FAIL` means the current row must not
be published as a distinct closed case. No `UNKNOWN` was converted merely to
make the page look final.

The eight provisional rows are mostly a publisher wiring omission: seven have
enough evidence to replace every `UNKNOWN` with `PASS`/`NARROW`. One is an
actual duplicate identity and must be merged, not backfilled as a second case.

## Current public chains and recommended gate result

| Case | Current candidate / carrier / fix | Recommended gates (`identity, ai_hunk, topology, but_for, fix_reversal, release, uniqueness`) | Decision |
|---|---|---|---|
| `GHSA-Q8HH-M6V5-4F3X` | `b47fa1c75d890cd080e3f6699bbfca8cd8d4b939` / `[]` / `[]` | `PASS, PASS, PASS, NARROW, NARROW, NARROW, PASS` | `READY_TO_BACKFILL` as a verified-unpatched, scope-limited finding |
| `GHSA-HW36-J4Q7-VJXX` | `9dbcf8c3d5de23925195bac6217fc85df6e8bb71` / `[]` / `d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd` | all `PASS` | `READY_TO_BACKFILL` |
| `GHSA-H5RM-9FHH-5PHJ` | `6d88b9e1e9f24901985b1fb4e4200f18bd550e1b` / `[]` / `ca3d42d8386515cd9f044377a15a632cd09b62f0` | `PASS, PASS, PASS, PASS, PASS, NARROW, PASS` | `READY_TO_BACKFILL`; distinguish loader landing from verified MCP exposure |
| `GHSA-2664-HR5V-554W` | `562d867483e871b0f1e31776252e23bd721df75b` / `[]` / `ca3d42d8386515cd9f044377a15a632cd09b62f0` | all `PASS` after range/branch-edge correction | `READY_TO_BACKFILL` |
| `GHSA-JJ45-W38G-GFRJ` | `086c8ad58f91a8e34ea27fabd1ba9ca0b2487f42` / `[]` / `17b7f5b0e181c6ced34887acc5f836eec7f6d0f8` | all `PASS` after release-range correction | `READY_TO_BACKFILL` |
| `GHSA-GVQ9-CMXR-844M` | `fafdfeed1b279cfe61e86cd8adc132b206eef8d4` / `[]` / `1d519a1eb1a29936d087fc7d98dc84a4718098c9` | `PASS, PASS, PASS, PASS, PASS, NARROW, PASS` | `READY_TO_BACKFILL`; development/server release boundary remains bounded |
| `GHSA-C7VW-VFXJ-3MVH` | `8a5ed7e62417441ed98b39481ac1a47510c1a9ef` / `[]` / `e0c999ea44429e8de00b4acb3ba570efdc733092` | all `PASS` after stale narrative is replaced | `READY_TO_BACKFILL` |
| `GHSA-723W-CRW6-P9HX` | `fafdfeed1b279cfe61e86cd8adc132b206eef8d4` / `[]` / `f4a1ba660063cd9e17883829e5272a248525a16b` | `PASS, PASS, PASS, PASS, PASS, PASS, FAIL` | `RESEARCH_GAP`: alias/dedup reconciliation; merge into existing `GHSA-8H88-GXP3-J7PG` page |

## Case findings

### GHSA-Q8HH-M6V5-4F3X — bounded attribution, verified unpatched

Recommended structured result:

```json
{
  "candidate_set": ["b47fa1c75d890cd080e3f6699bbfca8cd8d4b939"],
  "carrier_set": ["3f8fb150158723aca31df2ae937a1aa7b31ac254"],
  "minimum_fix_set": [],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "NARROW", "fix_reversal": "NARROW",
    "release": "NARROW", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

The Cursor-marked PR member first wrote `RequireScopes` with the
`TokenTypeSession -> ctx.Next()` bypass; its parent has no `scope.go`, and
`3f8fb150...` is the main-line squash carrier. This is but-for causal for the
session-bypass constituent, not for every independently introduced dashboard
or WebSocket sink in the aggregate advisory. `1b8c64d0...` fixes only
`GetAllUsers`; v4.5.1, v5.7.0, and `origin/main` retain the session early return
and middleware-free `/ws/system/logs` route. The current explicit `unpatched`
record is therefore evidence, not uncertainty.

Primary replay: [first-party GHSA-hmmq-qh6g-6wgh](https://github.com/lin-snow/Ech0/security/advisories/GHSA-hmmq-qh6g-6wgh), plus
`git show b47fa1c7:internal/middleware/scope.go` and
`git grep 'WSRouterGroup.GET.*system/logs' v5.7.0 -- '*.go'` in
`.ai-slop/state/repos/lin-snow_ech0`.

Required fields: add carrier `3f8fb150...`; add a `scope_statement` limiting
AI attribution to the session-token bypass; keep the complete-fix set empty;
retain `1b8c64d0...` only as a partial remediation; describe affected main-line
membership from v4.2.1 and state that no fully fixed release is verified.

### GHSA-HW36-J4Q7-VJXX — complete chain, missing carrier/gates only

```json
{
  "candidate_set": ["9dbcf8c3d5de23925195bac6217fc85df6e8bb71"],
  "carrier_set": ["e23b19309b8705b21c3b3ff4129c9974ba15a419"],
  "minimum_fix_set": ["d83eb0b36bfbe26fc856ffdb60f05c8bd460f2fd"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

PR #42424 member `9dbcf8c3...`, bearing a Claude Opus 4.8 trailer, first adds
DeepStream as an inner `opencv` codec, request-controlled process-wide
`pool_size`, and a decode path that probes but does not enforce pixel limits.
Its parent has no DeepStream source. Squash `e23b193...` lands it. Fix
`d83eb0b...` registers DeepStream as GPU-only, enforces the pixel limit, and
strips runtime `pool_size`. The landing is in v0.26.0; the fix is absent from
v0.27.1 and present in v0.28.0.

Primary replay: [first-party GHSA-cqm8-jxg6-fqfq](https://github.com/vllm-project/vllm/security/advisories/GHSA-cqm8-jxg6-fqfq), plus
`git show 9dbcf8c3:vllm/multimodal/video.py` and
`git show d83eb0b3 --` in `.ai-slop/state/repos/vllm-project_vllm`.

Required field: publish `e23b193...` as the squash carrier. The already
corrected `>=0.26.0,<0.28.0` / fixed `0.28.0` release fields should remain.

### GHSA-H5RM-9FHH-5PHJ — complete causal edge, release lower bound is two-stage

```json
{
  "candidate_set": ["6d88b9e1e9f24901985b1fb4e4200f18bd550e1b"],
  "carrier_set": ["9729c2a5da7b59fdbf62b95c100e085a2c2daa4d"],
  "minimum_fix_set": ["ca3d42d8386515cd9f044377a15a632cd09b62f0"],
  "release_fix_variants": [
    "0405fc550f55051f6c459252f5860fa78d27ab80",
    "170cfc787015d352488f6b6403af07a74e95ca1d"
  ],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "NARROW", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

Claude-marked PR member `6d88b9e1...` adds a `node.type` to
`path.join(...)->require(schemaPath)` loader without component or realpath
containment; the parent lacks the file. `9729c2a5...` is the squash carrier and
first enters a tag at n8n@2.9.0. The advisory-specific MCP
`validate_node_config` exposure enters at n8n@2.25.1 (`166eb855...`). The
master fix and both release backports add component checks plus
`require.resolve`/realpath containment.

Primary replay: [first-party GHSA-6h4x-896x-fw5m](https://github.com/n8n-io/n8n/security/advisories/GHSA-6h4x-896x-fw5m), plus
`git show 6d88b9e1:packages/@n8n/workflow-sdk/src/validation/schema-validator.ts`
and `git tag --contains 166eb855...` in `.ai-slop/state/repos/n8n-io_n8n`.

Required fields: add carrier `9729c2a5...` and release-specific fix edges.
Do not flatten “unsafe loader shipped from 2.9.0” and “advisory-specific MCP
source-to-sink verified from 2.25.1” into a single overconfident lower bound.
That bounded release statement is why `release=NARROW`, not `UNKNOWN`.

### GHSA-2664-HR5V-554W — complete shared-attribution regression

```json
{
  "candidate_set": ["562d867483e871b0f1e31776252e23bd721df75b"],
  "carrier_set": [
    "9e5212ecbc5d2d4e6f340b636a5e84be6369882e",
    "1479aab2d32fe0ee087f82b9038b1035c98be2f6"
  ],
  "minimum_fix_set": ["ca3d42d8386515cd9f044377a15a632cd09b62f0"],
  "release_fix_variants": [
    "3e4fb19caf73276a68b38d45d96b3da5baf7cab7",
    "0405fc550f55051f6c459252f5860fa78d27ab80",
    "170cfc787015d352488f6b6403af07a74e95ca1d"
  ],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

The public smallest-surviving squash changes an unconditional
`Object.freeze(fn.prototype)` into an object-only guard. Because
`typeof Function.prototype === 'function'`, it creates the regression. Its
commit object has a Claude Opus 4.6 coauthor among human coauthors, which is
`ai_hunk=PASS` under the campaign's settled shared-authorship rule and supports
`AI_CODE_FLAWED`, not sole-AI authorship. `ca3d42d8...` reverses the exact
predicate and adds a regression test.

Primary replay: [first-party GHSA-c9c6-rq46-h25v](https://github.com/n8n-io/n8n/security/advisories/GHSA-c9c6-rq46-h25v), plus
`git diff 3f02194f 562d8674 -- packages/@n8n/task-runner/src/js-task-runner/js-task-runner.ts`
and `git show ca3d42d8 --` in `.ai-slop/state/repos/n8n-io_n8n`.

Required fields: add the 2.10.x and 1.x equivalent landings and branch-specific
fix edges. Replace the overbroad current release text with repository-proven
windows: the 1.x landing first appears at n8n@1.123.22 and is fixed at
1.123.69; the 2.x landing first appears at 2.10.1 and is fixed at 2.33.4,
with the 2.34.0 line fixed at 2.34.1.

### GHSA-JJ45-W38G-GFRJ — complete edge, advisory range must not overwrite Git

```json
{
  "candidate_set": ["086c8ad58f91a8e34ea27fabd1ba9ca0b2487f42"],
  "carrier_set": [],
  "minimum_fix_set": ["17b7f5b0e181c6ced34887acc5f836eec7f6d0f8"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

Copilot SWE-agent commit `086c8ad5...` switches the shared LIKE escaper from
backslash to `|` while native `Pgsql.php` retains no matching `ESCAPE` clause;
its parent uses PostgreSQL's matching default backslash escape. Fix
`17b7f5b0...` centralizes `LIKE_ESCAPE_CHARACTER='|'`. The vulnerable edge is
present in `4.1-nightly-2026-04-17`; the fix is present in
`4.1-nightly-2026-08-02`. Stable 4.1.5–4.1.7 do not contain the BIC and are not
affected by this lineage.

Primary replay: [first-party GHSA-5hx6-c293-588h](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-5hx6-c293-588h), plus
`git show 086c8ad5:phpmyfaq/src/phpMyFAQ/Search/SearchDatabase.php` and tag
ancestry in `.ai-slop/state/repos/phpmyfaq`.

Required field: replace `vulnerable_release <=4.1.7` with the verified affected
nightly lineage. The live PR `merge_commit_sha` erratum is evidence metadata,
not a causal or topology gap.

### GHSA-GVQ9-CMXR-844M — complete code edge, bounded release claim

```json
{
  "candidate_set": ["fafdfeed1b279cfe61e86cd8adc132b206eef8d4"],
  "carrier_set": [],
  "minimum_fix_set": ["1d519a1eb1a29936d087fc7d98dc84a4718098c9"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "NARROW", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

Claude-generated single-parent commit `fafdfeed...` first adds the key-server
`verify_api_token` placeholder that accepts any non-empty Bearer value. Its
parent has neither the path nor symbol. Fix `1d519a1e...` replaces it with
HMAC, expiry, issuer, and constant-time comparison. The impact is unauthenticated
upload of an otherwise-valid self-signed bundle; search was public and revoke
still required an ownership signature.

Primary replay: [first-party GHSA-4g2c-wpgj-49w8](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-4g2c-wpgj-49w8), plus
`git show fafdfeed:server/key-server/app/api/v1/keys.py` and
`git show 1d519a1e:server/key-server/app/api/v1/keys.py` in
`.ai-slop/state/repos/openssl_encrypt`.

Required field: keep the narrowed impact from the reconciled Round11 record.
The public Git development line is vulnerable and v1.4.0 contains the fix, but
the key-server path is absent from the PyPI 1.4.0b8 sdist and no vulnerable
tagged server artifact was reproduced here. Record that boundary explicitly
and use `release=NARROW`, not a blanket released-package claim.

### GHSA-C7VW-VFXJ-3MVH — gates can close only after narrative follows corrected BIC

```json
{
  "candidate_set": ["8a5ed7e62417441ed98b39481ac1a47510c1a9ef"],
  "carrier_set": [],
  "minimum_fix_set": ["e0c999ea44429e8de00b4acb3ba570efdc733092"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  },
  "decision": "READY_TO_BACKFILL"
}
```

The reconciled BIC `8a5ed7e6...` first creates normal execution of validated
plugins while interposing only selected builtin/socket/subprocess entry points;
its parent has no plugin system. Later `e588aaa...` and `50bec5d...` are
incomplete runtime/static hardenings, not the root. Fix `e0c999ea...` makes the
runtime and AST checks consume one blocked-module set. The candidate is in
v1.3.0 and PyPI 1.4.0b8 still contains the incomplete runtime-vs-AST lists;
v1.4.0 contains the fix.

Primary replay: [first-party GHSA-9pgj-v69p-q586](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-9pgj-v69p-q586), plus
`git show 8a5ed7e6:openssl_encrypt/modules/plugin_system/plugin_sandbox.py` and
`git show e0c999ea:openssl_encrypt/modules/plugin_system/plugin_security_constants.py`
in `.ai-slop/state/repos/openssl_encrypt`.

Required fields: the current scalar introducer was corrected to `8a5ed7e6...`,
but `bug_semantics`, several `evidence` entries, and `reasoning` still call
`e588aaa...` the BIC. Replace that stale narrative as a unit; set the
repository-supported vulnerable range to `>=1.3.0,<1.4.0`; add a mechanism key
that distinguishes this import-policy flaw from `GHSA-P2G6-JJWG-33V4`, which
shares the feature commit but has a different file-access mechanism and fix.

### GHSA-723W-CRW6-P9HX — do not publish a second copy

```json
{
  "candidate_set": ["fafdfeed1b279cfe61e86cd8adc132b206eef8d4"],
  "carrier_set": [],
  "minimum_fix_set": ["f4a1ba660063cd9e17883829e5272a248525a16b"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "FAIL"
  },
  "decision": "RESEARCH_GAP"
}
```

The code evidence itself is complete: `fafdfeed...` first adds unchecked
`PublicKeyBundle.from_dict()` and `to_identity()` with Claude Code/Sonnet
markers, its parent lacks the file, and `f4a1ba66...` makes signature
verification default. PyPI 1.4.0b8 contains the vulnerable code; v1.4.0
contains the fix.

The failure is identity uniqueness. The Round11 record itself says OSV aliases
first-party `GHSA-8H88-GXP3-J7PG` to `CVE-2026-74876`; the site already
publishes `GHSA-8H88-GXP3-J7PG` as a confirmed case with the exact same
candidate, fix, mechanism, and patch. `GHSA-723W-CRW6-P9HX` is the later
unreviewed mirror, not a second vulnerability.

Primary replay: [first-party GHSA-8h88-gxp3-j7pg](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-8h88-gxp3-j7pg), local reviewed advisory
`/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/04/GHSA-8h88-gxp3-j7pg/GHSA-8h88-gxp3-j7pg.json`, and exact pair comparison in
`web/src/generated/research-data.json`.

Required action: merge `GHSA-723W-CRW6-P9HX`, `CVE-2026-74876`, and
`GHSA-8H88-GXP3-J7PG` into one alias class/page, preserving every public ID.
Do not backfill seven gates on the duplicate page.

## Confirmed-status anomaly: CVE-2026-55828 / GHSA-F9M7-VC86-P6JJ

This is **stale publication wiring, not an evidence gap**. The current ledger
contains both an old `partial_wave[0]` BLOCKED note (“no auditable source
history”) and a later `blocked_deepwave_research` record with the full BIC,
parent, AI marker, direct fix, and independent acceptance. The publisher chose
the old note for `description`, `mechanism`, and `code_evidence.summary`, while
choosing the later record for candidates and all-PASS gates. That produces the
visible contradiction.

```json
{
  "candidate_set": ["6a3afbcf335ea2cb22e50fd0563ede611e3ec8c7"],
  "carrier_set": [],
  "minimum_fix_set": ["43947671ba9be8fb08b105f3539a112ee7a57ddc"],
  "gates": {
    "identity": "PASS", "ai_hunk": "PASS", "topology": "PASS",
    "but_for": "PASS", "fix_reversal": "PASS",
    "release": "PASS", "uniqueness": "PASS"
  },
  "publication_status": "confirmed",
  "decision": "READY_TO_BACKFILL"
}
```

First-party advisory `GHSA-F9M7-VC86-P6JJ` describes the same symlink-chain
escape: lexical validation accepts a symlink created earlier in the tar, then
a regular file open follows that chain one directory above the destination.
Candidate `6a3afbcf...` adds `extractTar`/`extractFile` and
`OpenFile(O_CREATE|O_WRONLY|O_TRUNC)` and has a Claude Opus 4.6 trailer; its
parent lacks file transfer. Fix `43947671...` removes a pre-existing entry,
uses `O_EXCL`, and adds the exact symlink-chain regression. v1.25.28 lacks the
candidate, v1.26.16/v1.26.18 contain the candidate without the fix, and
v1.26.25 contains the fix.

Primary replay: [first-party GHSA-f9m7-vc86-p6jj](https://github.com/qbee-io/transport/security/advisories/GHSA-f9m7-vc86-p6jj), local reviewed advisory
`/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/06/GHSA-f9m7-vc86-p6jj/GHSA-f9m7-vc86-p6jj.json`, and
`git diff f449f6f1 6a3afbcf -- file_transfer.go` /
`git diff 43947671^ 43947671 -- file_transfer.go file_transfer_test.go` in
`.ai-slop/state/repos/qbee-io_transport`.

Required publication correction: make the later terminal/deepwave evidence
win over stale `partial_wave` text (or remove the superseded partial fields),
replace the three stale summaries with the concrete symlink-chain mechanism,
and narrow the repository-proven release window to
`>=1.26.16,<1.26.25`. Keeping `publication_status=confirmed` is justified once
the contradictory stale text is no longer selected.

## Landing summary

- Backfill seven-gate values for seven rows; three remain deliberately
  `qualified` through `NARROW`, not “still under review.”
- Merge `GHSA-723W-CRW6-P9HX` into the already confirmed
  `GHSA-8H88-GXP3-J7PG` alias class instead of publishing two copies.
- Add missing squash/branch carriers for Q8HH, HW36, H5RM, and 2664, plus n8n
  release-specific fix edges.
- Correct release language for H5RM, 2664, JJ45, GVQ9, C7VW, and CVE-55828;
  preserve source-vs-advisory disagreements instead of copying advisory ranges.
- CVE-55828 remains confirmed; its “no auditable source history” language is a
  superseded BLOCKED artifact and must not survive publication.

