# Batch 2 acceptance matrix for the 12 Batch 1 shards

## Outcome

The acceptance task is **COMPLETE**, but the combined research closure is
**not integration-ready**.

- `ACCEPT`: 4 shards.
- `ACCEPT_WITH_LIMITS`: 8 shards.
- `REJECT`: 0 shards.
- Required `report.md`/`result.json` pairs: 12/12 present.
- Structured data: 444 JSON/JSONL files parsed, 0 failures.
- Directly resolvable report path/hash declarations: 87/87 matched.
- Result-declared artifacts: 28/28 exist; all four declarations that included
  an explicit expected SHA-256 matched.
- Directory snapshots stable during capture: 12/12.
- Report/result contradictions found: 0.

This mechanical acceptance does not promote routing, ancestry, source
recovery, tests, or report prose into causal proof. The current reproducible
generator supports only the frozen 110-component/200-public-ID strict ledger.
It does not emit a corrected postbaseline ledger containing Batch 1 additions,
negative corrections, alias actions, or split decisions.

## Scope and snapshot boundary

- Task start: `2026-08-12T12:48:06-04:00`.
- Workspace: `/home/hanqing/agents/ai-slop`.
- Branch: `dev`.
- HEAD: `6c0d2084fd1240341d6d1b9f9096252490168f0b`.
- Owned output: `autoresearch/herdr-260812-b2-acceptance-matrix/`.
- Batch 1 input set: exactly the 12 directories listed below.
- Excluded: every `herdr-260812-b2-*` directory and every non-listed
  directory. No Batch 2 output was accepted as Batch 1 input.
- Network/API calls: 0.
- Research reruns: 0.
- Shared cache writes requested: 0.
- Service tier: default; `/fast` was not enabled.

The validator recursively inventoried each source directory before and after
copying its top-level terminal artifacts into the owned `snapshot/` tree. The
two inventories compare path, size, `mtime_ns`, and SHA-256 and were identical
for every shard. `input-manifest.json` retains all 1,271 file records. The
owned snapshots, rather than later live-directory state, are the acceptance
review boundary for terminal reports and machine outputs.

### Whole-directory identities

| Batch 1 shard | Files | Directory identity SHA-256 |
|---|---:|---|
| `herdr-260812-repro-qa` | 15 | `3614e8795a1c628036f365f14b083d714cae5974cafd12124efe6961760484cb` |
| `herdr-260812-negative-controls` | 3 | `4de4afdf6233f5dcd0058038e68e0c4cd258751094d2362fcbbc5fc2898655f2` |
| `herdr-260812-systems-ecosystem` | 3 | `09055a22d0d57dd05bf844551edc60cf9f78ed0dc06086624729a81fb394080b` |
| `herdr-260812-python-ecosystem` | 79 | `6d573b380f5b858f36bd837f497cf6f67bf912d3d13013d98866be458f659332` |
| `herdr-260812-fresh-advisories` | 392 | `041c839203d6fde58f43050994113e906a88839dcdbd9f3c196c66305a0fef30` |
| `herdr-260812-ledger-qa` | 27 | `af880af02b93a4b57c2fcd90aeda1e02e1c657678cdd8c65a1482a97329dfbcd` |
| `herdr-260812-coolify-tail` | 7 | `a0d675c176118ac9772301cc49a5804f7e7f5da48f6948bd2841182bb2f1ea1d` |
| `herdr-260812-alias-qa` | 385 | `e22f3d444950ca2e08905f64419510c652a5365cd9cd64bc33f46f2c6a71078b` |
| `herdr-260812-unknown-recovery` | 347 | `e5bfee719c4cb9d67bdef9480ad80a6562ec3a8792e91e1bdb09c4814878dbe0` |
| `herdr-260812-openclaw-tail` | 5 | `438a004575a4e1c56459f943d2c4de86cbea853acf36d967a71d96fda8667d2c` |
| `herdr-260812-mcp-js-ecosystem` | 3 | `118aaf19df68c97c657e68046b99f5dcac5aa0f37bcf64f621fd460e35a4643d` |
| `herdr-260812-squash-lineage` | 5 | `75a79da0422756ad22b422af68e2088fd0a2c92cab034a2f54d0283df96a31c1` |

## Acceptance matrix

| Shard | Source status | Acceptance | Independent consistency check | Claim/evidence boundary |
|---|---|---|---|---|
| repro QA | COMPLETE | **ACCEPT** | Four JUnit files total 31 tests with no failures/errors/skips; replay JSONL has 110 components and 200 unique IDs | Consumer contract only; synthetic witnesses and 110/200 replay do not prove 125/173/186 |
| negative controls | COMPLETE | **ACCEPT_WITH_LIMITS** | 20 report rows = 15 KEEP, 3 REJECT, 1 NARROW, 1 UNKNOWN | Sampled correction, not full census; 169 is only the source shard's sample-adjusted ceiling |
| systems ecosystem | COMPLETE | **ACCEPT** | 15 rows = 15 wrong-edge FAIL, 0 additions | Negative-only bounded selection; ancestry/release evidence does not cure wrong causal edge |
| Python ecosystem | PARTIAL | **ACCEPT_WITH_LIMITS** | 5 novel rows = 0 PASS, 4 FAIL, 1 UNKNOWN | GitHub 403, containment gaps, and shared-cache auto-pack incident remain explicit |
| fresh advisories | COMPLETE | **ACCEPT_WITH_LIMITS** | 12 groups/13 mechanisms/1 proposed AutoGPT addition; frozen CVE and patch hashes match | Strong downstream proposal, but not machine-admitted; unreviewed stream incomplete and local release tag absent |
| ledger QA | COMPLETE | **ACCEPT** | `reconciliation.json` has 8 discrepancies: 6 confirmed, 1 superseded, 1 UNKNOWN | Snapshot arithmetic only; corrected totals are ceilings, not causal ledger output |
| Coolify tail | COMPLETE | **ACCEPT_WITH_LIMITS** | 11 rows/12 edges = 11 FAIL, 0 additions; four artifact hashes match | Unnamed other-12 overlap BLOCKED; 22,441 nonterminal edges remain UNKNOWN |
| alias QA | PARTIAL | **ACCEPT_WITH_LIMITS** | 76 JSONL rows = 65 KEEP, 2 ADD_ALIAS, 1 SPLIT, 2 REMOVE_ID, 6 UNKNOWN; start/end inputs equal | Alias additions and duplicate-instance removals actionable; split/UNKNOWN rows gated |
| unknown recovery | COMPLETE | **ACCEPT_WITH_LIMITS** | Inventory = 393; top-12 ledger = 8 RESOLVED_REJECT, 3 STILL_BLOCKED, 1 STILL_UNKNOWN | Workflow complete, evidence not closed; 381 rows were not deeply attempted |
| OpenClaw tail | COMPLETE | **ACCEPT** | Frozen advisory JSON = 647; 10 novel edges = 10 negative, 0 positive | Accepts the scoped negative/UNKNOWN artifact, not exhaustive ecosystem closure |
| MCP/JS ecosystem | PARTIAL | **ACCEPT_WITH_LIMITS** | Report/result agree: 3 strict, 1 incomplete, 2 ID rows, 7 FAIL, 1 UNKNOWN | Proposed n8n rows lack a shard-local raw evidence bundle; source cache boundary was violated |
| squash lineage | COMPLETE | **ACCEPT_WITH_LIMITS** | Snapshot = 10 edges; 9 REJECT_NONCAUSAL, 1 UNKNOWN, 0 PASS | Missing advisory/release/blob evidence stays BLOCKED; Coder reachability stays UNKNOWN |

No shard is `REJECT` because every required terminal pair exists, every
structured artifact parses, all resolvable declarations match, and no
report/result contradiction was found. `ACCEPT_WITH_LIMITS` is material: it
prevents positive integration or completeness inference outside the accepted
scope.

## Batch 1 reconciliation

### Machine baseline

`PASS` only for the frozen strict ledger:

- 110 semantic components.
- 200 unique public IDs.
- 120 accepted edge occurrences.
- 119 unique candidate/fix pairs.
- Four alias amendments.

This is byte-reproducible consumer evidence. It does not contain the actions
below.

### Candidate additions

Five component proposals under three public-ID rows are conserved, but none is
silently added to the integrated census by this audit:

1. AutoGPT `CVE-2026-72922` / `GHSA-349P-3C3R-8MJR`: source disposition is
   publication-grade candidate; acceptance disposition is **NARROW** to a
   downstream admission proposal. The frozen GitHub CNA record is published,
   names the same provider-path-confusion mechanism, cites exact fix
   `646dd5b8...`, and says fixed in 0.6.70. The marked carrier
   `7f08a16d...` is an ancestor of the fix (`merge-base` RC 0), and the frozen
   origin/fix patches show the no-op verifier/path-selection creation and the
   stored-provider comparison closure. The shard-local clone lacks the named
   `autogpt-platform-beta-v0.6.70` tag object (`rev-parse` RC 128), so this
   audit does not independently promote it into the machine census.
2. n8n-mcp `GHSA-75HX-XJ24-MQRW`: source disposition is one
   `STRICT_CAUSAL` component; acceptance disposition is **NARROW** pending a
   frozen raw-evidence replay.
3. n8n-mcp `GHSA-8G7G-HMWM-6RV2`: source disposition is two
   `STRICT_CAUSAL` mechanisms plus one `AI_INCOMPLETE_REMEDIATION` mechanism;
   acceptance disposition is **NARROW**. The three mechanisms must remain one
   public-ID row.

### Negative corrections

- **REJECT** Gitea OAuth reactivation as an AI incomplete-remediation edge:
  the AI member had the safe predicate and a human member introduced the
  shipped degradation. Preserve the advisory IDs.
- **REJECT** GitPython positional-tag `--file` as an extra component: it is the
  same `TagReference.create`/`--file`/arbitrary-read series already counted by
  `GHSA-3F7W-8RR8-F37F`. Preserve both advisories.
- **REJECT** Scriban lazy multiplication as an extra component: it is the same
  multiplication/`LoopLimit` residual series as `GHSA-Q6RR-FM2G-G5X8`.
  Preserve both advisories.
- **NARROW** Hermes profile-session search: keep the distinct hunk/mechanism,
  but its candidate SHA is already used by frozen `CVE-2026-6830`, so the
  candidate-SHA-disjoint claim is false.
- **UNKNOWN** Coolify TrustHosts: the cold-cache contributor exists, but durable
  atomic AI attribution does not close. Exclude it from a confirmed AI census.

The other 15 sampled negative controls remain `KEEP` only in the adversarial
sample's stated sense: they resisted the seven gates; the audit did not
re-prove every source-document assertion.

### Alias and duplicate actions

Actionable identity-only additions:

- Add `GHSA-CGJ8-7M5Q-X5GV` as alias of `CVE-2026-34198`.
- Add `GHSA-48P8-G2FX-3WWM` as alias of `CVE-2026-54526`.

Required split:

- **NARROW** OpenClaw Feishu `GHSA-XH72-V6V9-MWHC`: retain webhook-scoped
  evidence and split the distinct blank card-action-token mechanism before
  claim use.

Exact duplicate row occurrences to remove while retaining canonical IDs:

- `coolify-shell-grammar@batch-e` duplicates
  `coolify-shell-grammar@main`.
- `coolify-activity-scope@batch-e` duplicates
  `coolify-activity-scope@main`.

Six alias rows remain `UNKNOWN`: MISP mass assignment, OmniFaces combined
resource, Gitea draft attachment, Gitea OAuth reactivation, PraisonAI JWT
default, and Gitea private-org members.

### Arithmetic-only reconciliation

The following combines only disjoint Batch 1 corrections. These are ceilings,
not a new ledger, not a confirmed lower bound, and not publication-grade:

| Census | Source-document value | After known Batch 1 corrections | Conditional File Browser overlap |
|---|---:|---:|---:|
| strict released | 125 | at most 124 after excluding the TrustHosts UNKNOWN | unchanged |
| incomplete released | 48 | at most 44 after one exact duplicate and three REJECT rows | at most 43 |
| broad released | 173 | at most 168 after one exact duplicate, three REJECT rows, and one UNKNOWN | at most 167 |
| commit-only | 13 | at most 12 after one exact duplicate | unchanged |
| widest including commit-only | 186 | at most 180 after two exact duplicates, three REJECT rows, and one UNKNOWN | at most 179 |

The five proposed candidate components are not added to these figures. Public
ID counts are not arithmetically reduced for semantic duplicates because the
real advisory identities must be preserved; they need a row-aware regenerated
ledger.

### Unresolved conservation

- Unknown-recovery inventory: 393 distinct current unresolved components
  (263 `UNKNOWN`, 129 `BLOCKED`, 1 `NEEDS_REVIEW`). Of the top 12, eight became
  `RESOLVED_REJECT`, three remain `STILL_BLOCKED`, and one remains
  `STILL_UNKNOWN`; 381 were not deeply attempted.
- Ledger QA: File Browser umbrella-versus-split-mechanism overlap remains
  `UNKNOWN` and may reduce broad/widest ceilings by one.
- Alias QA: six rows remain `UNKNOWN`; the Feishu split remains unapplied.
- Fresh advisories: GitHub's unreviewed stream remained paginated.
- Coolify tail: unnamed other-12 semantic overlap is `BLOCKED`; nonterminal
  edges remain `UNKNOWN`.
- OpenClaw tail: eight routes remain `UNKNOWN`.
- MCP/JS: `GHSA-WJJV-3MJ2-39HF` remains aggregate and `UNKNOWN`.
- Squash lineage: Coder KeyId reachability remains `UNKNOWN`; named source,
  release, and blob gaps remain `BLOCKED`.

These pools are not summed because their source scopes may overlap.

## Exact commands and local sources

All commands were bounded and read-only with respect to Batch 1/shared paths;
only this owned directory was written.

| Command | RC | Duration/result |
|---|---:|---|
| `/usr/bin/time -f 'validator_duration_seconds=%e' env PYTHONDONTWRITEBYTECODE=1 python3 autoresearch/herdr-260812-b2-acceptance-matrix/validate_batch1.py` | 0 | 0.69 s; wrote owned manifest/validation/snapshots |
| `jq -e '.shards|length==12' autoresearch/herdr-260812-b2-acceptance-matrix/acceptance.json` | 0 | `true` |
| `jq -s '[.[]|.action] | group_by(.)' .../snapshot/herdr-260812-alias-qa/ledger.jsonl` | 0 | 76 rows; 65/2/1/2/6 action conservation |
| `jq -s` over `recommendation-ledger.jsonl` | 0 | 12 rows; 8 reject/3 blocked/1 unknown |
| Python stdlib `ElementTree` over `herdr-260812-repro-qa/junit/*.xml` plus JSONL ID-set check | 0 | 31 tests, 0 failures/errors/skips; 110 rows/200 IDs |
| `sha256sum` over AutoGPT CVE/origin/fix artifacts | 0 | `eeb187...`, `c5362e...`, `404c9e...`; all report declarations match |
| `git -c gc.auto=0 -c maintenance.auto=false -C autoresearch/herdr-260812-fresh-advisories/autogpt merge-base --is-ancestor 7f08a16d... 646dd5b8...` | 0 | Carrier is ancestor of exact fix |
| `git -c gc.auto=0 -c maintenance.auto=false -C autoresearch/herdr-260812-fresh-advisories/autogpt rev-parse 'autogpt-platform-beta-v0.6.70^{commit}'` | 128 | Negative control: release tag object absent from frozen clone |
| `git -c gc.auto=0 -c maintenance.auto=false rev-parse HEAD` | 0 | `6c0d2084fd1240341d6d1b9f9096252490168f0b` |

Primary local sources are the owned `snapshot/` terminal copies, the complete
hash inventory in `input-manifest.json`, the structural results in
`validation.json`, and the frozen first-party artifacts already present inside
the Batch 1 fresh-advisory shard. No live source refresh or research rerun was
performed.

## Artifact map

| Artifact | SHA-256 before `report.md`/`result.json` finalization | Purpose |
|---|---|---|
| `acceptance.json` | `71204436368c379a43263861ae087425dc8c33825ee8b6fca4e974cae5f2cf8c` | One acceptance row per shard plus full reconciliation |
| `input-manifest.json` | `6c1774f61c98146b97528b228d4655295f6099d71080fe0d0cf0618b15c20488` | 1,271-file snapshot manifest and 12 directory identities |
| `validation.json` | `abc8739876f82fd61d36e191be03cbbc333d960536df88a366dc5113e82d5314` | Required artifacts, parsing, hash, stability, and result-contract checks |
| `validate_batch1.py` | `34ce9cb9b9b93ca674a132a5b7212b5fd01e68092a30ff97955ab5f2d2662c6f` | Bounded stdlib reproducer |
| `snapshot/` | identities in `input-manifest.json` | Owned terminal-artifact copies |

## Claim boundary

`COMPLETE` means all 12 Batch 1 directories received a terminal acceptance row
and their required artifacts, structured syntax, declared hashes, snapshot
stability, report/result agreement, and evidence boundaries were checked.

It does **not** mean the research corpus is complete, the postbaseline census is
correct, or the proposed additions are integrated. Only the frozen 110/200
strict ledger is presently machine-reproduced. Candidate additions remain
proposals; `REJECT`, `NARROW`, `BLOCKED`, and `UNKNOWN` controls above must be
carried into a new atomic ledger and independently verified before any broader
publication claim.
