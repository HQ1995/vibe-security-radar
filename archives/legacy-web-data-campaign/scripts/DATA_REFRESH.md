# Resumable data refresh

Rebuild the source delta and candidate union from the immutable
`source-before-final` baseline before generating campaign batches:

```bash
uv run --project cve-analyzer python scripts/build_source_delta.py
uv run --project cve-analyzer python scripts/build_data_refresh_batches.py
uv run --project cve-analyzer python scripts/build_legacy_collision_inventory.py
uv run --project cve-analyzer python scripts/migrate_legacy_collision_caches.py
```

`build_source_delta.py` defaults to `formal_full`. It schedules every current
alias class under the current analyzer epoch, including classes with historical
cache files. Developer-only reuse of the weaker historical cache partition must
be requested explicitly with `--population-policy incremental`; that delta is
marked release-ineligible and the formal runner rejects it.

Check for upstream drift without writing source files, Git refs, locks, or the
receipt:

```bash
uv run --project cve-analyzer python scripts/refresh_source_inputs.py --check
```

Exit status `0` proves that every local input matched its remote during that
source's sequential check window and that the schema-3 source receipt binds the
same installed bytes. Exit status `1` reports source or receipt drift;
`2` reports an unsafe input or an unavailable/ambiguous remote proof. The JSON
separates `receipt_valid` (the rolling receipt still binds local bytes) from
`receipt_current` (the receipt also matches all current check observations).
Apply a complete refresh before rebuilding the delta:

```bash
uv run --project cve-analyzer python scripts/refresh_source_inputs.py
```

The refresh command holds the campaign-global lock and creates a rolling
cutoff: each source is captured at its own immutable, independently verified
version. It stages all HTTP bodies and fast-forwards complete Git mirrors only
after exact default-branch discovery. A normal mirror fetch forces
`fetch.fsckObjects` and `transfer.fsckObjects`, accepts a fetched branch tip
that is equal to or a descendant of the advertised tip, and then requires both
advertised-to-fetched and local-to-fetched ancestry. The strict post-fetch
state runs full fsck, so a force-push, missing object, corrupt object, or
non-fast-forward history fails closed. Legacy shallow, partial/promisor,
sparse, or worktree-configured
caches enter a migration-only preflight: their static main config must contain
the exact expected origin, then a new unfiltered full clone is staged without
reusing any old object. The staged clone must retain the old HEAD as an
ancestor, pass full `git fsck`, pass the strict exact-worktree validator, and
bind its checkout to the exact tip recorded by
`refs/remotes/origin/HEAD -> origin/<branch>` before an
interruption-recoverable directory exchange. A later upstream fast-forward
does not invalidate that already fetched immutable tip. Later transactional
failure restores the old cache. Ordinary Git capture has a 128 MiB stdout and
2 MiB stderr hard
bound with fail-closed pipe-drain status; full cloning has a separate four-hour
deadline and preserves the campaign's 120 GiB floor plus 16 GiB staging
headroom. Strict mirrors require exact origins,
clean worktrees, self-contained object/ref storage, and symlink-free current
and remote trees. The first strict capture in every independent operation runs
bounded `git fsck --full --strict` so missing or corrupt objects reachable
through HEAD/history fail closed. Repeated captures inside the same refresh,
delta build, or campaign runner may reuse only a bounded process-local success
entry keyed by the resolved path, HEAD/tree OIDs, and a fresh stat digest of
the complete object/ref store plus Git control files. Any metadata drift forces
a new full fsck; failures never enter the cache. Only the disposable
legacy-cache migration preflight skips this proof.
The source contract targets a case-sensitive, UTF-8-capable
Linux filesystem because the official Gemnasium tree currently contains paths
that alias under case folding. NVD feed installation binds `gzSize`, compressed SHA-256,
decompressed size/SHA-256, JSON shape, and stable before/after metadata. The
official OSV `ecosystems.txt` is fetched with a stable HEAD/GET/HEAD proof,
stored beside the archives, and parsed as UTF-8 lines so ecosystem names that
contain spaces remain intact. Its sorted, duplicate-free safe names derive the
exact `<ecosystem>.zip` inventory dynamically. Every derived archive binds its
GCS generation, size, ETag/MD5, base64 MD5, SHA-256, stable CRC32C metadata,
and bounded ZIP/JSON validation. Python's standard library provides no CRC32C
primitive, so local CRC32C recomputation remains outside the receipt contract.
Each ZIP is rejected before central-directory materialization when the physical
archive exceeds 1 GiB, its central directory exceeds 512 MiB, or its declared
inventory exceeds 5,000,000 members. JSON records are streamed in bounded chunks
with a 128 MiB per-member, 16 GiB per-archive expanded-size, and one-hour
validation limit. Non-conforming OSV primary IDs stay outside the candidate
identity set and enter a bounded per-archive quarantine report; valid aliases
from the same record remain usable, while OSV `related`/`upstream` relationships
remain separate identities. Each recorded invalid primary or alias contains its
member name, a preview of at most 256 strict UTF-8 bytes, the full value's
SHA-256, and its Unicode code-point length. Exceptional values are represented
only through that bounded preview; no unbounded value field is persisted. An
archive with more than 1,000 invalid primaries fails closed as source
corruption. NVD validation caps both the gzip and decompressed JSON
input at 1 GiB before parsing. TERM and HUP become catchable interruptions;
obsolete archive removals enter the rollback ledger before unlink, and any
failure rolls back files and Git fast-forwards before withholding a new receipt.

The atomically written
`.ai-slop/state/data-refresh/source-remote-check-now.json` records the captured Git
OIDs, NVD metadata digests, the OSV ecosystem manifest proof, and every derived
OSV GCS generation. The runner rejects legacy fixed-inventory receipts and
revalidates schema 3 against every installed byte. The schema-3
`remote_parity: true` field is retained for release compatibility and means
that every entry matched its remote inside its own capture window. It does not
claim one simultaneous upstream snapshot. `checked_at_utc` records transaction
completion; the immutable per-source OIDs, digests, and generations define the
exact rolling cutoff. A later `--check` can therefore report fresh upstream
drift while `receipt_valid` remains true.

`build_source_delta.py` verifies the baseline `SHA256SUMS`, proves each saved
Git HEAD is an ancestor of the clean current mirror, compares NVD records by
canonical content, derives the complete current OSV archive inventory from the
content-addressed ecosystem manifest, and member-diffs
the preserved OSV archives. The historical baseline deliberately retained the
two OSV archives that changed (`GIT.zip` and `npm.zip`). The other current
archives are fully validated and content-addressed with the explicit
`baseline_not_preserved` status; they contribute no inferred delta. The output
candidate file contains exactly one analysis subject per scheduled alias class.
The source delta persists complete class membership, eligible seed IDs,
source-record digests, merged GIT-range/fix/reference evidence, and the source
snapshot binding. Supplemental baseline, delta, and adjudicated-corpus subjects
become explicit singleton classes when no current source class owns them.
`scripts/analysis_contract.py` independently hashes analyzer Python source, the
AI signature registry, `pyproject.toml`, and `uv.lock`; generated source
snapshots and campaign plans stay outside that epoch to avoid a circular cache
identity.
Its NVD reader checks the 1 GiB compressed and decompressed limits in 1 MiB
chunks under a one-hour deadline before bounded-buffer JSON parsing. NVD and
OSV files are opened with `O_NOFOLLOW`; descriptor content hashes and full
`fstat`/path identities bind the bytes used by semantic parsing. ZIP EOCD
preflight and every member read use that same owned descriptor, followed by a
close-time content and identity guard. For a formal population, the batch
builder consumes only the persisted alias-class manifest and its content
digests. Repository identities are scheduling affinity, so a large repository
may be split across bounded class batches while the analyzer's existing
clone/update locks protect its shared mirror. Incremental compatibility mode
retains the archive-rescan grouping path. Both outputs are staged and fsynced,
and any input drift aborts publication.

`run_data_refresh.sh` executes the current formal campaign with a fixed
analysis contract. Sync the analyzer environment once before running it:

```bash
uv sync --project cve-analyzer --frozen
```

The launcher resolves the repository root, changes into it, and replaces its
shell process with `cve-analyzer/.venv/bin/python scripts/run_data_refresh.py`.
The launcher PID is therefore the runner PID, so `TERM` and `HUP` reach the
runner's process-group cleanup. Run it directly without an outer `| tee`, `uv
run`, or command-substitution parent; the runner already writes durable batch
logs under `.ai-slop/logs/data-refresh/`.

Campaign and read-only source-lock paths are opened one component at a time with
directory file descriptors, `O_DIRECTORY`, and `O_NOFOLLOW`. Every opened
component and lock file is checked with pre-open `stat`, post-open `fstat` and
post-open identity/link-count comparison, so intermediate-directory or final
lock-file replacement races fail closed.

- no-token elimination first, with no model transport admitted
- distribution/advisory repositories (for example `ubuntu-cve-tracker`) are
  metadata-only lead sources: they may contribute package, version, alias, and
  patch-reference evidence, but they are never cloned or blamed as vulnerable
  code targets; the pipeline resolves their records to an upstream source
  repository before code analysis
- repository role and execution cost are independent classifications: large
  upstream code repositories such as Linux or Chromium remain valid code
  targets, but each execution wave admits at most one heavyweight batch while
  filling the remaining CPU budget with ordinary repositories
- exact `Co-authored-by` repo indexing before blame; reachable AI ancestors
  and squash-PR members become stable causal edge IDs, while blame is ranking
  support and never a candidate veto; repo/ref-generation-bound singleflight
  ensures all CVEs sharing a large repository reuse one exact ref scan instead
  of concurrently repeating `git for-each-ref`
- large shallow/promisor repositories use one recent parent-topology scan per
  repository instead of one `rev-list` per fix; fix SHAs outside local refs
  enter a separately cached, blobless root-fetch/topology pass, and missing
  objects, shallow boundaries, or fetch failures remain explicit incomplete
  evidence rather than a no-match result
- `gemini-3.5-flash-lite` at `low` reasoning for screening only
- `gpt-5.6-luna` at `max` reasoning for causal verification only
- separate content-addressed approvals for Flash and Luna; approving Flash
  cannot admit a Luna request, and the Flash result manifest must be sealed
  before the exact Luna request plan exists
- `CVE_ANALYZER_FROZEN_LOCAL_SOURCES=1`, which disables advisory-source
  downloads, clones, and pulls inside every analyzer child process
- stage-specific API/cache/result directories and process-locked budget ledgers;
  every physical HTTP retry records its exact canonical request-body SHA-256,
  subject, repository, logical turn, and retry index before transport
- Git clones and repository-level analysis results use the durable
  project-local `.ai-slop/cache/cve-analyzer/` root shared across compatible
  campaign epochs; campaign-specific derived data remains isolated under its
  content-addressed campaign directory
- repo-component-aware no-token shards sharing a host-sized local worker budget
  (logical CPUs minus a bounded OS/coordinator reserve, capped at 112); the
  current 128-CPU host runs up to 16 analyzer children with 7 workers each,
  while known repositories remain disjoint across concurrent children and
  Flash/Luna remain single-child so model concurrency is not multiplied
- a shared SQLite-WAL GitHub governor under the campaign directory, targeting
  60% of the observed quota, preserving at least 20%, and allowing at most 16
  requests in flight across child processes
- configured model concurrency and rate governors, a 180-second request timeout, and a
  16,384-token output floor for `max` reasoning; one incomplete response may
  retry at up to 32,768 tokens
- v4 stage-owned artifacts: exact no-token results, evidence-availability and
  screening-route projections, screening deltas,
  repository-granular verification deltas, and subject-level verification
  aggregates; unchanged stage contracts reuse exact hits and execute only misses
- a 120 GiB free-space floor before and after every executed batch
- a content-addressed local-source snapshot covering the cvelistV5, GitHub
  Advisory Database, and Gemnasium Git mirrors, the 2025/2026 NVD gzip feeds,
  the OSV ecosystem manifest, and every manifest-derived OSV bulk zip
- a versioned durable Git-fsck receipt at
  `.ai-slop/state/data-refresh/git-fsck-receipts-v1.json`; reuse still
  revalidates repository layout/config, index and worktree bytes, HEAD/tree,
  and the full object/ref metadata digest, while any object/ref mutation or
  malformed/old receipt forces a new `git fsck --full --strict`

Before scanning the full population, build the prediction-blind no-token pilot:

```bash
cve-analyzer/.venv/bin/python scripts/build_no_token_pilot.py select
```

This writes 1,000 subjects under
`.ai-slop/state/data-refresh/no-token-pilot-v1/<pilot-id>/`: 100 mapped and
100 unmapped classes in each of `<=2023`, `2024`, `2025`, `2026`, and
GHSA-only. The companion Source v3 ground-truth report is stage-scoped: it
must show zero false positives and zero false negatives across exact author
pairs, known-AI co-author trailers, and complete known-tool attribution lines.
It makes no Flash, Luna, causality, or population-accuracy claim. Preflight or
execute the two frozen 500-subject sampling lanes as deterministic,
repo-component-aware execution shards through the no-token-only runner with:

```bash
scripts/run_data_refresh.sh --run-no-token-pilot \
  <pilot-dir>/selection.json --dry-run --execute-after-dry-run
```

The runner uses up to 16 repo-disjoint child processes with a campaign-bound
host-sized worker budget (7 workers each, 112 total on the current 128-CPU
host), seals only terminal subjects, and writes the evaluation beside the
immutable selection. Batch exit code 1 is treated as a request for per-subject
validation, not as a transport crash; only validated terminal siblings are
sealed and retryable subjects remain explicit. It never enters the Flash or
Luna phases. The standalone `evaluate` subcommand remains available for
auditing an already sealed result directory. The combined preflight mode reuses
strict source validation in one process; a separate dry-run followed by a
second command intentionally repeats fail-closed Git validation.

Every result is projected into exactly one no-token route:

- `screenable`: explicit AI authorship evidence exists and the subject belongs
  in the cheap-model queue
- `no_screening_value`: the current frozen source/fix/BIC/attribution contract
  has a complete exhaustion proof, so a paid call has no useful input
- `deferred_retryable`: evidence is missing, stale, transiently unavailable, or
  otherwise incomplete; it must not be mistaken for a negative

Paid planning remains blocked if any subject is missing, contains model output,
has deferred or incomplete coverage, lacks a complete no-value proof, or loses
an old blame-derived candidate. A weighted candidate estimate below 200 is a
manual-audit warning rather than a semantic reason to discard upstream source
repositories.

Population-quality claims require a separate real-data audit. Build a blind,
repo-disjoint packet from a frozen Source v3 row manifest with
`scripts/build_source_audit_packet.py select`; score it only after two distinct
adjudicators provide complete, agreeing labels. Disagreement or an
`inconclusive` label keeps `quality_claim_ready=false`.

After rebuilding the formal delta and batches, seal the no-token results and
the exact Flash-only plan. All prices, request bounds, retry/call bounds, and
the hard ceiling are explicit operator inputs; inspect current provider and
gateway metadata immediately before supplying them:

```bash
scripts/run_data_refresh.sh --prepare-screening-plan \
  --screening-input-usd-per-million-tokens <price> \
  --screening-output-usd-per-million-tokens <price> \
  --screening-max-input-tokens <bound> \
  --screening-max-output-tokens <bound> \
  --screening-max-calls-per-candidate <bound> \
  --verification-input-usd-per-million-tokens <price> \
  --verification-output-usd-per-million-tokens <price> \
  --verification-max-input-tokens <bound> \
  --verification-max-output-tokens <bound> \
  --verification-max-calls-per-candidate <bound> \
  --llm-cost-ceiling-usd <ceiling>
```

The screening plan reserves and reports only Flash calls and Flash cost. Luna
pricing and bounds are carried forward as provisional inputs, but Luna has zero
calls and zero reserved cost in this plan. Only after Flash results are sealed
does the runner apply those bounds to the exact screening-positive repository
requests and produce the separately approvable Luna cost plan. The same hard
ceiling is enforced independently at both boundaries.

The command stops after writing `screening-plan-v1.json`. Approve only that
reported digest to run Flash. Flash execution seals both
`screening-result-manifest-v1.json` and `verification-plan-v1.json`, then stops
again. Luna remains impossible until its separately reported digest is
approved:

```bash
scripts/run_data_refresh.sh --approve-screening-plan <screening-plan-sha256>
scripts/run_data_refresh.sh --approve-verification-plan <verification-plan-sha256>
```

Campaign construction semantically replays source-delta generation once from
the frozen inputs, including discovery, aliases, cache partitioning, and the
candidate union. It compares the replayed delta and candidate bytes with the
committed artifacts. Coordinated edits to counts, hashes, and both artifacts
therefore still fail closed.

OpenClaw is an independent, release-ineligible regression population. It is not
a formal campaign prerequisite and cannot block the all-repository scan. Run
its bounded 24-class pilot and exact full-population smoke through the separate
entry point. Pilot prices and token bounds are explicit inputs. Query the
configured gateway's model metadata immediately before the pilot and record
those values in the command:

```bash
uv run --project cve-analyzer python scripts/run_openclaw_regression.py pilot --dry-run \
  --screening-input-usd-per-million-tokens <price> \
  --screening-output-usd-per-million-tokens <price> \
  --verification-input-usd-per-million-tokens <price> \
  --verification-output-usd-per-million-tokens <price> \
  --screening-max-input-tokens <bound> \
  --screening-max-output-tokens <bound> \
  --verification-max-input-tokens <bound> \
  --verification-max-output-tokens <bound> \
  --screening-max-calls-per-candidate <bound> \
  --verification-max-calls-per-candidate <bound> \
  --pilot-cost-ceiling-usd 25 \
  --pilot-max-attempts 72

uv run --project cve-analyzer python scripts/run_openclaw_regression.py pilot \
  --screening-input-usd-per-million-tokens <price> \
  --screening-output-usd-per-million-tokens <price> \
  --verification-input-usd-per-million-tokens <price> \
  --verification-output-usd-per-million-tokens <price> \
  --screening-max-input-tokens <bound> \
  --screening-max-output-tokens <bound> \
  --verification-max-input-tokens <bound> \
  --verification-max-output-tokens <bound> \
  --screening-max-calls-per-candidate <bound> \
  --verification-max-calls-per-candidate <bound> \
  --pilot-cost-ceiling-usd 25 \
  --pilot-max-attempts 72
```

The runner selects exactly 24 OpenClaw alias classes by hashing the persisted
formal parent manifest and class IDs. It stores the selection, one immutable
batch, and a process-locked budget ledger under
`.ai-slop/state/data-refresh/pilots-v1/<pilot-id>/`. Every HTTP attempt and retry
must reserve its maximum price before transport. The first run fixes one
absolute 60-minute deadline; resume preserves that deadline and all completed
or abandoned reservations. The class cap, 72-attempt cap, USD 25 cap, request
input/output bounds, and process-group timeout are independent. A pilot marker
always carries `artifact_kind=pilot` and `formal_release_eligible=false`, and
formal release validation rejects it.

Copy the completed command's `pilot_id` into the smoke command. The operator
must record both hard smoke budgets explicitly:

```bash
uv run --project cve-analyzer python scripts/run_openclaw_regression.py smoke --dry-run \
  --pilot-id <pilot-id> \
  --smoke-cost-ceiling-usd 25 \
  --smoke-max-attempts 72

uv run --project cve-analyzer python scripts/run_openclaw_regression.py smoke \
  --pilot-id <pilot-id> \
  --smoke-cost-ceiling-usd 25 \
  --smoke-max-attempts 72
```

Smoke preflight fully replays the pilot completion and binds it to the current
source snapshot, analysis contract, alias-class manifest, OpenClaw checkout,
and attested pricing contract. It projects the pilot's attempt count, known
cost floor, and fail-closed reservation ceiling across the full current
OpenClaw class population. Both projected attempts and the reservation ceiling
must fit the recorded smoke budgets; the shared admission ledger also enforces
hard maxima of 72 attempts and USD 25. The dry run performs these checks and
writes no artifacts.

The smoke batch contains every current OpenClaw alias class exactly once. Its
content-addressed artifacts live under
`.ai-slop/state/data-refresh/openclaw-smokes-v1/<smoke-id>/`. `status.json` records
every expected class, all six analysis-stage outcomes, and its terminal or
incomplete reason. Any execution error or incomplete class withholds
`completion.json` and the `current.json` gate pointer. Repeating the same
command resumes the same bounded artifact and deadline. A changed pilot,
manifest, checkout, contract, pricing proof, or operator budget produces a new
smoke identity.

The regression completion remains under its own state root and can be compared
across analyzer revisions. It is evidence about that focused population only;
formal scan readiness does not consume its `current.json` pointer.

Inspect the first pending formal batch without writing logs or state:

```bash
scripts/run_data_refresh.sh --dry-run --limit 1
```

The formal dry-run reports only the selected formal batches. A missing, stale,
or incomplete OpenClaw regression never blocks this path.

Resume the partially processed legacy batch:

```bash
scripts/run_data_refresh.sh --batch legacy-001
```

Run up to three pending safe batches. Static legacy-origin collisions are
rechecked through the production cache resolver at startup. A batch proceeds
when every affected request resolves to its exact independent host-qualified
path. Resolver failures, path drift, symlinks, and legacy-path aliases remain
blocked. The explicit skip keeps only those unresolved batches pending:

```bash
scripts/run_data_refresh.sh --limit 3 --skip-legacy-origin-collisions
```

Formal batches execute in manifest order. A legacy batch participates only when
its analysis subjects are absent from the formal grouped manifest; overlap is
rejected or deduplicated as a complete legacy subset. Writable results, API
responses, and derived-search caches live under a content-addressed campaign
directory at `.ai-slop/state/data-refresh/campaigns-v1/<campaign-id>/`. The
campaign identity binds the exact source snapshot, code/data contract, model,
reasoning effort, worker count, and cache policy. Canonical historical caches
remain read-only.

Successful markers live under
`.ai-slop/state/data-refresh/refresh-runner-v1/completed/`; stable append-only logs
live under `.ai-slop/logs/data-refresh/`. A marker records the batch digest and
exact command contract. It also records the full canonical source inventory,
each Git HEAD/tree/origin, each NVD/OSV file size and SHA-256, and one aggregate
source SHA-256. Its result manifest binds the size and SHA-256 of every staged
result. Every formal result also produces one class receipt covering
`source_discovery`, `fix_resolution`, `bic_resolution`,
`signal_classification`, `causal_verification`, and `adjudication`. Each stage
receipt chains exact class/source evidence, analyzer/signature epoch, model
transport, repository and fix inputs, result digest, and prior-stage output.
Matching markers reuse that exact proof; receiptless or old-epoch work re-enters
the plan. A changed code contract, plan, batch, or source snapshot invalidates
the old marker and reruns the batch. Drift
before, during, or after a child process withholds completion. Missing,
symlinked, malformed, wrong-origin, or dirty source inputs fail closed before
publication state can advance.

Explicit `--cve-list` children enumerate and parse the frozen local OSV zip
inventory regardless of its 24-hour cache TTL. Missing or malformed archives
terminate the child without a network fallback. Git advisory mirrors and NVD
feeds are consumed from the runner-validated snapshot; analyzer setup never
updates those shared paths while parallel batches are active.

Result validation accepts `no_fix_commits` only when
`fix_resolution=exhausted_no_match` carries non-empty, digest-backed receipts
for every configured method. A cap, timeout, clone failure, skipped advisory,
unreachable fix, unsupported scope, missing repository identity, or
`incomplete`/`error` stage keeps the class and batch pending. An exhausted
upstream search requires every downstream stage to be `not_applicable`.
`signal_classification=exhausted_no_match` likewise requires the exact
commit-metadata, squash-decomposition, and PR-body method set for every
repository-qualified BIC. Each subject carries input/output digests. GitHub
lookup errors, ambiguous cached negatives, missing repository scope, and an
associated PR whose decomposition was not proved become `incomplete`; they
cannot become a completed negative result.
Unknown categories, `no_ai_activity`, non-string error fields, and incomplete
Tier-0 telemetry also remain pending. Failed, interrupted, low-disk, and
collision-skipped batches receive no marker and stay rerunnable. Git
subprocesses disable terminal prompts and inherit no terminal input. The runner
never deletes or moves repository caches.

Required discovery LLM stages also fail closed. A LiteLLM transport error,
malformed structured response, exhausted `max_output_tokens` retry, or model
drift becomes `llm_error`; it cannot silently degrade into a negative finding
or a completed marker.

Run the detector proof after every planned marker exists:

```bash
uv run --project cve-analyzer python scripts/evaluate_detector_quality.py
```

Fixed-contract metrics are emitted only when the evaluator rehashes the whole
plan, proves exact plan/result inventory equality, validates every schema-7
marker and campaign receipt, and reads every adjudicated input from the staged
campaign directory. An incomplete campaign is reported as a mixed historical
snapshot and cannot support a fixed-contract release claim.

After all markers pass, create the formal Web generation with:

```bash
uv run --project cve-analyzer python scripts/generate_web_data.py \
  --heldout-selection scripts/heldout_studies/selection-<sha256>.json \
  --heldout-labels scripts/heldout_studies/labels-<sha256>.json \
  --recall-selection scripts/heldout_studies/recall-selection-<sha256>.json \
  --recall-labels scripts/heldout_studies/recall-labels-<sha256>.json \
  --recall-report .ai-slop/state/data-refresh/end-to-end-recall-current.json
```

The generator holds the campaign-global lock through proof and promotion. It
reproduces the precommitted held-out selection from the exact campaign and
evaluates its independent labels in process. Formal promotion requires complete
denominators and both independent precision and conditional-recall point
estimates and one-sided 95% exact lower bounds at or above 0.95. The recall
claim covers the discovered raw AI-signal candidate population; advisory and
signature discovery remain explicit exclusions. Any inconclusive label,
infrastructure error, unresolved result, selection/label drift, campaign,
source, contract, result-manifest, recall-inventory, or recall-report drift
blocks promotion. The generator requires
zero end-to-end coverage failures and protected exclusions, complete independent
recall labels, a non-null recall estimate, and exact Git artifact-order replay.
Both the end-to-end recall point estimate and its family-wise 95% interval lower
bound must meet the release receipt's recall target. Missing, incomplete, API/PR
errored, uncached, and absent campaign results remain coverage failures and never
count as detector negatives.
The current held-out study IDs overlap the mandatory protected roots, so the
formal receipt remains unavailable until a separately sealed protected-class
census is incorporated.

The adjudication-backed publication report is a curation-consistency check: it
proves that the published allowlist matches the same adjudications that govern
inclusion and exclusion. Independent held-out evidence supplies the detector
accuracy claim.

The generator first writes and validates a per-generation evidence bundle at
`.ai-slop/state/data-refresh/release-evidence-v1/<generation_id>/`, including the
full reports, sealed held-out and recall selections, both independent label
artifacts, campaign contract and result manifest, publication manifest, source
snapshot and remote cutoff, release receipt, and a canonical SHA-256 manifest.
Campaign batches and completion
markers are archived as exact bytes; every raw campaign result is streamed with
no-follow opens into a bounded `campaign-results/` inventory. The archive also
records the exact alias-class projection and bounded protected-input bytes.
The archived source snapshot must retain the exact schema-2 inventory for all
three Git mirrors, every NVD feed, the OSV ecosystem manifest, every OSV
archive, and the schema-3 remote-cutoff proof; correlated hash resealing cannot
replace that inventory with a partial or self-declared shape.
Validation rebuilds the runner command and content-addressed campaign identity,
projects all raw results, reconstructs the complete alias population, replays
protected-ID extraction/alias expansion, and requires an exact deterministic
selection match. Publication curation archives the exact adjudication corpus,
alias projection, and ordered publication index, then replays the evaluator from
those inputs. Evidence archival is a fail-closed prerequisite for atomic
promotion; an existing generation is accepted only when every archived digest
and proof relationship still matches exactly. A durable
`release-evidence-v1/activations/pending/<generation_id>.json` binds the approved
candidate before promotion. After promotion and a final full input/live-release
check, it is finalized as `activations/<generation_id>.json`. Finalization is
idempotently reconcilable from the pending record.
