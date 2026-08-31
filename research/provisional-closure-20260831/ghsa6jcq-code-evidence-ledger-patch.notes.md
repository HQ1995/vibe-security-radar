# GHSA-6JCQ-6546-QRRW canonical evidence repair

- Class: `alias-9638cedab2290ab95b10127c` (`CVE-2026-57144` / `GHSA-6JCQ-6546-QRRW`).
- Repository: `mervinpraison/praisonai`.
- Fresh Neon base: revision `3`, change set `df53d33c-4109-44a2-9e6e-b607c99658b9`.
- Fresh Neon base checksum: `c8b80a1e96c2fba9daeba949de933ec58338e231c77f83712c2813775a1c4d5b`.
- Candidate: `4ee7d298c89f89cadcdde8312aab0fa3d9c0a14f`, parent `1ae86076a906f7f9cc2092c9c551e03a7466ecaa`.
- Direct fix: `55dc751cc69945d0b5dfb02d015f146ad6399aa9`, parent `ec1ee648bcf4496a17c58c7932fb411d44a9067d`.
- This artifact is staged only. It has not been applied, exported, published, copied into generated site data, or committed.

## Identity and mechanism

The first-party advisory is
<https://github.com/advisories/GHSA-6jcq-6546-qrrw>. It describes
`SandlockSandbox.execute()` and `run_command()` silently replacing the requested
Landlock-backed sandbox with `SubprocessSandbox` when Landlock was unavailable.
The fallback preserved the high-level configuration object but did not enforce
the filesystem allowlist or `network=False`, so untrusted code continued with
the host user's filesystem and network reach.

This is distinct from `GHSA-8CCJ-P46R-JWQQ`, the same repository's
`PRAISONAI_CALL_AUTH` authentication-bypass advisory. The prior published
description and evidence marker were cross-contaminated by that neighboring
case; this patch records only the Sandlock mechanism.

The candidate is the file birth of
`src/praisonai/praisonai/sandbox/sandlock.py`. Its parent has no such path, and
the commit object contains the exact trailer:

`Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>`

The fix queries the installed Landlock ABI in the constructor and raises below
the backend's minimum. It also deletes the fallback branches from both
execution entry points, requiring callers to choose `SubprocessSandbox`
explicitly if weaker isolation is acceptable.

## Displayed code evidence

The candidate commit creates a 437-line file in one raw Git hunk. Publishing
that whole file would bury the causal lines, so the canonical display stores
two count-valid, byte-exact contiguous excerpts from the new blob. Every body
line retains the `+` prefix from the file-birth diff.

| Role | Header | Exact commit-blob range | Meaning |
|---|---|---:|---|
| candidate | `@@ -0,0 +258,18 @@` | 258-275 (18) | `execute()` and its silent fallback |
| candidate | `@@ -0,0 +317,16 @@` | 317-332 (16) | `run_command()` and the same fallback |
| fix | `@@ -75,12 +75,32 @@` | parent 75-86; commit 75-106 | constructor ABI fail-closed guard |
| fix | `@@ -306,24 +365,10 @@` | parent 306-329; commit 365-374 | complete raw hunk deleting the `execute()` fallback |
| fix | `@@ -371,24 +433,10 @@` | parent 371-394; commit 433-442 | complete raw hunk deleting the `run_command()` fallback |

The three fix blocks are complete, byte-for-byte hunks from
`git show --format= --no-ext-diff --unified=3 55dc751c -- sandlock.py`.
Annotations are distinct and hunk-specific, and required anchors cover both
candidate sinks, the constructor guard, and both removed fallback calls.

Fingerprints:

- Full candidate Git diff: `dc45d9c73404c49512e4834b3e8a25c8a51e6ce83bdfcb10e9865244a33b4fb7`.
- Displayed candidate hunks: `18ec450a78d41347bdc8078fb2c9311658485cb704021a7058638fbb878f66eb`.
- Full fix Git diff: `410fad515ccc3b1f87aff19bb55939d297b4738186f334eb4347d85886d87547`.
- Displayed fix hunks: `3aa5f05d3adc91b6d79934cca5b982e41ec8b2b7f26d744b75e3ee4d7160e8b3`.

Displayed fingerprints are SHA-256 over the role's hunk strings joined by one
newline, matching the catalog convention.

## Release boundary and gates

The first-party advisory reports affected `>= 4.5.110, < 4.6.61` and patched
`4.6.61`. Tagged source does not support that closure boundary:

- the clone has no `v4.6.61` tag;
- release commit/tag `v4.6.62` still contains both fallback branches;
- `SandboxConfig.native()` at `v4.6.62` does not set the newly checked
  `require_landlock` metadata flag, so its default path still falls back;
- `v4.6.74` retains the same branches; and
- `55dc751c` is absent from `v4.6.74` and first appears in `v4.6.75`.

The canonical Git boundary is therefore `>= 4.5.110, < 4.6.75`, fixed in
`v4.6.75`. The release gate remains `NARROW` because this verified boundary
conflicts with the advisory's `4.6.61` claim; it is not promoted to `PASS`.

The other retained gate values were independently rechecked:

- `identity=PASS`: advisory, repository, file, and mechanism agree.
- `ai_hunk=PASS`: the Copilot trailer is on the file-birth commit that writes
  both fallback paths.
- `topology=PASS`: `4ee7d298` is a direct ancestor of `55dc751c`; no carrier is
  needed.
- `but_for=PASS`: the candidate parent does not contain `sandlock.py`.
- `fix_reversal=PASS`: the direct fix fails at construction and deletes both
  fallback paths.
- `release=NARROW`: advisory and tagged-source boundaries disagree as above.
- `uniqueness=PASS`: this is the Sandlock downgrade, not the adjacent call-auth
  advisory.

The old `research/gate-campaign-20260830/verdicts/wave-04.jsonl:3` source is
superseded because that historical packet was pair-swapped. The values are now
sourced to this recheck rather than rewriting the historical artifact.

## Patch preservation and validation

The full-row patch preserves every live revision-3 field and value except the
superseded `gates_source`. It adds canonical candidate/fix sets, reader-facing
description/mechanism/scope, verified release facts, and canonical
`code_evidence`.

Validation performed on the staged artifact:

- exactly one non-empty JSONL line; `json.loads` passes;
- `scripts.ledger_store.read_patches(..., require_assessments=False)` passes;
- live revision still equals `expected_revision == 3`;
- `scripts.ledger_store.validate_update(live_row, staged_row)` passes;
- every pre-existing live field other than `gates_source` is byte-equivalent as
  parsed JSON, and no live key is removed;
- all five blocks pass `scripts.site_preflight.valid_unified_hunks`;
- candidate excerpt bodies equal their exact contiguous commit-blob slices;
- every fix block equals one complete raw Git hunk, with old/new header counts
  recomputed from prefixes;
- both display fingerprints, both full-diff fingerprints, all required anchors,
  distinct annotations, parent absence, ancestry, commit trailer, and tag
  containment recompute successfully.
