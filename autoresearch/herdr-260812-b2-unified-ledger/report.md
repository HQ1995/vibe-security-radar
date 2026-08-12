# Batch 2 snapshot-only unified ledger

## Result

The requested ledger and verifier are complete. `integration_ready` is intentionally `false`.

The frozen source census contains 186 positive-row instances: 110 strict-baseline rows and 76 post-strict instances. Two Batch E instances are exact duplicates, leaving 184 canonical source components. Their source-tier envelope is:

| Source unit | Snapshot result |
|---|---:|
| Frozen strict baseline | 110 components / 200 public IDs |
| Post-strict strict released | 15 canonical rows |
| Strict document census | 125 rows |
| Incomplete-remediation released | 47 canonical rows |
| Broad released source maximum | <=172 rows |
| Commit-only | 12 canonical rows: 11 incomplete-remediation + 1 strict |
| Widest source maximum | <=184 rows |

Those are upper envelopes, not a final publication count. The ledger does not coerce `REJECT`, `NARROW`, `BLOCKED`, or `UNKNOWN` into `PASS`.

Batch 1's adversarial sample is represented on the exact component rows: 15 `KEEP`, 3 `REJECT`, 1 `NARROW`, and 1 `UNKNOWN`. Alias QA is represented independently: 65 `KEEP`, 2 `ADD_ALIAS`, 1 `SPLIT`, 2 duplicate-instance `REMOVE_ID`, and 6 `UNKNOWN` actions. This separation matters: identity QA and causal-control QA are different axes.

## Grain and ledger contract

`ledger.jsonl` contains three record kinds:

| Record kind | Rows | Counting behavior |
|---|---:|---|
| `COMPONENT_ROW` | 186 | 184 canonical rows form the source envelopes; two duplicate instances count nowhere |
| `BATCH1_ROUTE_CONTROL` | 22 | Non-counting: 17 scoped rejects, 3 blocked, 2 unknown |
| `BATCH1_PENDING_PROPOSAL` | 5 | Source shards reported PASS, but all five remain non-counting pending cross-shard integration |

Every record has a unique `row_key`, normalized public IDs, source tier, row state, independent state axes, counting booleans, source hash references, and available repo/mechanism/fix identity. Frozen strict rows carry their accepted candidate/fix edges. Post-strict rows carry the Batch 1 exact fix objects and point to their hashed source rows; candidate edges were not guessed when the machine ledger did not contain them.

Allowed row states are `PASS`, `REJECT`, `NARROW`, `BLOCKED`, `UNKNOWN`, and `DUPLICATE`. `source_verdict`, `alias_qa_action`, `negative_control_outcome`, and `integration_state` remain separate fields so a source PASS can still be an alias `UNKNOWN`, a sampled `REJECT`, or an unintegrated proposal.

## Snapshot boundary

Work started at `2026-08-12T12:48:26-04:00`. The initial strict/post-strict freeze completed at `2026-08-12T12:51:20-04:00`; Batch 1 terminal context was then extended before ledger derivation. At `2026-08-12T13:03:38-04:00`, all 57 original source files still matched their copies, establishing one common hash boundary. All copied inputs are read-only under `snapshot/`. `summary.json.snapshot_manifest` records each snapshot path, original source path, byte size, and SHA-256.

No network request, API call, clone, cache read/write, build, corpus rerun, staging, commit, reset, clean, or push was performed. The only repository inspection was:

    git -c gc.auto=0 -c maintenance.auto=false status --short --branch

The checkout was intentionally dirty. No conclusion depends on its later status.

### Primary input hashes

| Input | SHA-256 |
|---|---|
| strict-200-v3 `ledger.jsonl` | `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| strict-200-v3 `summary.json` | `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e` |
| strict-200-v3 `supplement.json` | `09a45c145313862f2d60b47cfe1df23bce9a1d7d3b6140592a913a364dfcbd4d` |
| strict-200 closure report | `e255c227967b921dd1b69e740edf0dccb5de4df655b73029ec204b51755e458b` |
| Alias-free Batch A | `a7dd3db373af0fae98c10f8c96c58180cf80fc132fb6fb53fedbd44f3aae22c2` |
| OpenClaw closure | `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| Main aggregate | `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| Batch B | `318912fbc789ef7f0708044d2041c24fa69198f878c2c668b04af86031d4616e` |
| Batch C | `b1e03cb193003ebbba83b73b8d8bbcbcd72f02148ba00812967a2721e60a8ffd` |
| Batch D | `3a8482a6badb0b8bff5dbf64adc18b37493c68dc56a25598be91ee3be7e727cd` |
| Batch E | `f889a12dbdace54f678b2c4cb8b203e76a57583f778d83a7b29052e7a99c27ad` |

The strict summary's `afc810ce...` value is also verified. It is the SHA-256 of canonical UTF-8 JSON with non-ASCII text preserved, whereas `0cc19a49...` is the JSONL byte hash. They are different digest contracts, not a row-count discrepancy.

### Batch 1 correction and terminal hashes

All 12 Batch 1 shard terminal results were copied. Their `result.json` byte hashes are:

| Shard | Status | SHA-256 |
|---|---|---|
| alias-qa | PARTIAL | `c8764ac7f162b50399f6afc0da57d5fe5992d3017c4fbd0b89b4f9c741ff5f51` |
| coolify-tail | COMPLETE | `99c1fbcd644d27edc8b02f50416e4cbded96d9001624e265641ca8573abc1630` |
| fresh-advisories | COMPLETE | `2c5d1e041e26e5e239ec31ac97d5f7a1333d6631b50ec6da857d313bd8e64e03` |
| ledger-qa | COMPLETE | `bbafde4df5c77bdac338d602c834f99fdbb26b50065ed6b046564932ad7e2c71` |
| mcp-js-ecosystem | PARTIAL | `f9ef2c57b3125009603b46ad76d99cc56c27d208bedd1549a1475d3119a90bfa` |
| negative-controls | COMPLETE | `aabec899fd8b426429266378323fe01cd03e91674c7a72d47ffe5cd0d9d706a7` |
| openclaw-tail | COMPLETE | `51255be05c41b417f17bc426d6d048bfb316f0a6728511a418b9660d2be9db90` |
| python-ecosystem | PARTIAL | `fa5941b031a04895e33f2cad4ffb13568d564917caf45a74ebb92f8726220d70` |
| repro-qa | COMPLETE | `23f96dd671384b52eca35afaea019b30eddb9c51ac2e6de08efaf515970c44b1` |
| squash-lineage | COMPLETE | `a2b1d6f899da7ce67e54ce91c7b41756d20b03d5875f4cfe1ef2a44bf07d13d2` |
| systems-ecosystem | COMPLETE | `f50366bca7dec7635e9f57f7bd1d9f12f51a83890191f98ea625d13b3e07ec5f` |
| unknown-recovery | COMPLETE | `7d832ec3b7eeb7e8de75b462cb9f56478735f9ebcc1f48ff803924b2c8defc99` |

The row-level correction artifacts used directly are:

| Artifact | SHA-256 |
|---|---|
| ledger QA `reconciliation.json` | `8ffc475fb67a17b22ae5421045dffd9280abc75efab701a1963dbaad538d7537` |
| alias QA `ledger.jsonl` | `2b844af298f85345b4354bf980b59e379db4b51796b08759cc1400ed8ddf1e85` |
| alias QA `summary.json` | `3a1501f1d1b70e887de25ac6b54d6c182f0d6577f39da4820bae1cfc18ef3347` |
| negative-controls `report.md` | `d07164e6f4a5e2b36a802cdd6c6dd3c4638a028840993e38b867dc42feeea62a` |
| unknown-recovery `recommendation-ledger.jsonl` | `944a0027a558468be4a2bef235e610927c5f18c85e8e77fb24eeb6c21293ecc7` |
| squash-lineage `snapshot.json` | `e7f05541e3ee40014b0909d46d8df133b60ce2248be9fdb5c9c0defe27095485` |

## Reconciled source rows

Canonical source components by tier and current row state are:

| Tier | PASS | REJECT | NARROW | UNKNOWN | Canonical rows |
|---|---:|---:|---:|---:|---:|
| Strict released | 122 | 0 | 2 | 1 | 125 |
| Incomplete-remediation released | 41 | 3 | 0 | 3 | 47 |
| Incomplete-remediation commit-only | 8 | 0 | 0 | 3 | 11 |
| Strict commit-only | 1 | 0 | 0 | 0 | 1 |
| Total | 172 | 3 | 2 | 7 | 184 |

The `PASS=172` total in this status table is across released and commit-only tiers. It is not the broad released count and must not be quoted as one.

### Exact duplicate instances

Both duplicate occurrences remain in `ledger.jsonl` with `row_state=DUPLICATE` and every counting flag false:

1. `post:coolify-shell-grammar@batch-e` duplicates `post:coolify-shell-grammar@main`: CVE-2026-42204 / GHSA-CHG4-63HM-XV9X, `coollabsio/coolify`, the bare-ampersand shell validator, fix member `817128c5...`.
2. `post:coolify-activity-scope@batch-e` duplicates `post:coolify-activity-scope@main`: CVE-2026-34167 / GHSA-962V-GXMW-56HC, the ActivityMonitor missing-team fail-open, fix member `3e0d48fa...`.

These remove one released and one commit-only source occurrence: 173 becomes <=172 and 186 becomes <=184.

### Batch 1 negative-control outcomes

The three sampled rejects are:

| Row | Outcome | Count effect |
|---|---|---|
| Gitea OAuth reactivation, CVE-2026-55987 / GHSA-VRHC-JJFC-M3M3 | `REJECT` | AI member had the safe predicate; later human degradation created the residual |
| GitPython positional tag `--file`, GHSA-3WXW-XV34-2FRG | `REJECT` | Same TagReference/create, guard, and file-read residual series as GHSA-3F7W-8RR8-F37F |
| Scriban lazy multiplication, GHSA-89CF-6HMV-8RXM | `REJECT` | Same multiplication/LoopLimit residual series as GHSA-Q6RR-FM2G-G5X8 |

The sampled `NARROW` row is Hermes CVE-2026-49956 / GHSA-MGXW-V6RH-WCV6: retain only the distinct session-search hunk/mechanism because candidate `d2b27f6f...` also occurs in a frozen strict component.

The sampled `UNKNOWN` row is Coolify CVE-2026-34198 / GHSA-CGJ8-7M5Q-X5GV: the cold-cache contribution and release interval are code-supported, but durable atomic AI attribution is unresolved.

Combining these controls with the exact duplicate correction gives bounded projections, not final totals:

| Projection | Strict document rows | Broad released | Widest |
|---|---:|---:|---:|
| Source envelope | 125 | <=172 | <=184 |
| Exclude the 3 known rejects | 125 | <=169 | <=181 |
| Also exclude the sampled causal UNKNOWN from a confirmed projection | <=124 | <=168 | <=180 |
| Conditional: File Browser umbrella is also duplicate | <=124 | <=167 | <=179 |

The `NARROW` row remains one component only under its narrowed claim. These projections still do not resolve alias-QA unknowns or unsampled causal rows.

### Alias QA actions

- `ADD_ALIAS`: Coolify TrustHosts adds GHSA-CGJ8-7M5Q-X5GV; Argo ArtifactGC adds GHSA-48P8-G2FX-3WWM.
- `SPLIT`: OpenClaw Feishu webhook keeps only webhook-scoped evidence for GHSA-XH72-V6V9-MWHC; its blank card-action-token mechanism is outside that row.
- `REMOVE_ID`: the two Batch E duplicate instances above are non-counting. The public IDs stay on their canonical rows.
- `UNKNOWN`: MISP mass assignment, OmniFaces combined resources, Gitea draft attachment, Gitea OAuth, PraisonAI JWT default, and Gitea private-org members retain unresolved identity/fix-set gates.
- Frozen strict alias amendments remain four and were not reopened.

The case-normalized source inventories are 200 frozen strict IDs and 121 post-strict official IDs after the two additions, with zero baseline overlap. The combined 321-ID inventory is a source inventory only, not a publication-grade count.

### Preserved unresolved identity collision

`post:filebrowser-scoped-fs@canonical` stays `UNKNOWN`. It names CVE-2026-54094 / GHSA-239W-M3H6-CH8V on the same `847d08bd -> 7c2c0a11 -> 64511ce4` chain and the same delete/dangling-write residual mechanisms that Batch D splits into CVE-2026-55667 and CVE-2026-55668. No deterministic subtraction is made.

## Batch 1 outcomes outside the current maxima

Five source-reported positive proposals are explicit `BATCH1_PENDING_PROPOSAL` rows with `source_verdict=PASS`, `row_state=UNKNOWN`, and all counting flags false:

- AutoGPT CVE-2026-72922 / GHSA-349P-3C3R-8MJR: one proposed strict component.
- n8n-mcp GHSA-75HX-XJ24-MQRW: one proposed strict component.
- n8n-mcp GHSA-8G7G-HMWM-6RV2: two proposed strict mechanisms and one proposed incomplete-remediation mechanism under one advisory identity.

They do not silently change 125/172/184. Cross-shard alias, duplicate, negative-control, and released-containment integration has not superseded those current source envelopes.

The 12 unknown-recovery recommendations and 10 squash-lineage edges are also explicit non-counting controls. `RESOLVED_REJECT` is scoped to named routed edges; it is not a class-wide proof of human origin. Three recovery rows remain `BLOCKED`, and two route-control rows remain `UNKNOWN`.

Other Batch 1 terminal reports are frozen and summarized in `summary.json`, but their every negative/unknown row was not normalized into this component ledger. This is one reason `integration_ready` remains false.

## Coverage and blockers

Closed:

- all 110 strict positive rows materialized;
- all 76 post-strict positive instances materialized;
- two exact duplicates explicit and non-counting;
- all 20 sampled negative-control outcomes attached to canonical components;
- all post-strict alias actions explicit;
- all 12 Batch 1 terminal results hashed;
- 12 unknown-recovery and 10 squash-lineage machine controls materialized;
- five new positive proposals visible but non-counting.

Not closed:

- only 20 of 74 post-strict semantic rows received the adversarial causal-control audit;
- all post-strict rejected/unknown document controls are not exhaustively normalized;
- six alias-QA actions remain `UNKNOWN`, and Feishu requires scoped split handling;
- File Browser umbrella/split identity remains unresolved;
- post-strict candidate edges are still source pointers where the Batch 1 machine ledger recorded only exact fixes;
- new Batch 1 proposals have not passed unified cross-shard admission.

Therefore `integration_ready=false`, `source_envelopes.final_count=null`, and no final component total is emitted.

## Reproduction and validation

The builder and verifier use only the standard library and only the copied snapshot:

    python3 autoresearch/herdr-260812-b2-unified-ledger/build.py
    python3 autoresearch/herdr-260812-b2-unified-ledger/verify.py

The verifier checks all 57 snapshot hashes, JSONL parseability, unique row keys, allowed status values, public-ID formats, source-reference hashes, candidate/fix SHA formats, duplicate targets, tier arithmetic, the 125/172/184 envelopes, 15/3/1/1 control outcomes, alias actions, 200/119/121 public-ID identities, strict canonical hash contract, non-counting route/proposal rows, and `integration_ready=false`.

One early attempt to extend the snapshot received an expected permission refusal because the owned snapshot directory had already been made read-only. Owner write was restored only on the owned directories, the additional files were copied, and the entire snapshot was made read-only again. No shared path was affected.

## Claim boundary

This artifact proves snapshot byte provenance, row enumeration, case-normalized public-ID membership, declared repo/mechanism/fix identities, source-tier arithmetic, exact duplicate instances, and recorded QA dispositions. It does not independently prove exploitability, AI authorship, same-mechanism causality, advisory identity, or released containment.

Routing, ancestry, tests, source recovery, tag containment, shared candidates/fixes, and model output remain diagnostic. `REJECT` applies only to its recorded edge or duplicate count; `NARROW` applies only at its recorded scope; `BLOCKED` and `UNKNOWN` remain unresolved; commit-only rows never enter a released count.
