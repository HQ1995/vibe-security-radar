# Published Web data pipeline

`scripts/generate_web_data.py` projects cached analyzer results into the JSON
artifacts consumed by the dashboard.

```text
analysis cache
  -> loader.py
  -> filters.py
  -> entry_builder.py
  -> severity.py / languages.py / stats.py
  -> schema.py
  -> writer.py
  -> web/data/
```

Run the generator from the repository root after populating the analyzer
cache:

```bash
python3 scripts/generate_web_data.py \
  --heldout-selection scripts/heldout_studies/selection-<sha256>.json \
  --heldout-labels scripts/heldout_studies/labels-<sha256>.json \
  --recall-selection scripts/heldout_studies/recall-selection-<sha256>.json \
  --recall-labels scripts/heldout_studies/recall-labels-<sha256>.json \
  --recall-report .ai-slop/state/data-refresh/end-to-end-recall-current.json
uv run --project cve-analyzer python scripts/evaluate_publication_quality.py
```

Formal publication archives and receipts bind the exact recall selection,
independent labels, recomputed report, detector inventory ID, protected-census
digest, and protected-overlap count. Schema-4 recall selection keeps protected
classes out of random sampling while sealing an exact-once census bound to the
authoritative roots, formal alias manifest, and source snapshot. Schema-3 recall
labels bind independent dual-review census adjudications to that seal. Coverage
failures, incomplete census coverage, unresolved or `UNKNOWN` labels, null
recall, and artifact drift block receipt creation. A complete census contributes
exact counts to the whole-population recall estimate and clears the protected
overlap blocker.

`audit_adjudications.json` is the versioned, CVE-level causal ground-truth
corpus. `AI_CAUSAL` records force independently verified misses into the
publication. `NOT_AI_CAUSAL` and `INCONCLUSIVE` records, together with their
declared aliases, are release-blocking exclusions. Every record names a
repository-contained evidence artifact under `scripts/audit_results/` or the
curated override file.

The publication evaluator reports schema-2 curation precision and curation
recall. These values check that the published allowlist matches the
adjudications that govern its inclusion and exclusion. Their scope is
publication-curation implementation consistency; independent held-out evidence
supplies detector accuracy. It leaves `INCONCLUSIVE` records outside the
curation sample, reports them as `inconclusive_excluded`, and hard-fails on any
leaked known-negative, inconclusive, or unadjudicated page.

Independent detector precision and conditional recall come from the sealed
selection/label workflow in `scripts/HELDOUT_QUALITY.md`. Formal generation
reproduces the selection from the current campaign, evaluates the independent
labels in process with statistical certification required, and blocks on any
inconclusive, infrastructure, unresolved, stale, malformed, or incomplete proof.

## Published generation

```text
web/data/
├── index.json       { generation_id, generated_at, total, ids } manifest
├── cves/<ID>.json   one generation-bound `CveEntry` per file
├── stats.json       generation-bound aggregates for exactly those entries
└── release-receipt.json
                     successful evaluation and campaign proof for that generation
```

Per-CVE files keep data reviews focused: adding or removing a vulnerability
adds or removes one file, and an attribution correction changes one small
artifact.

Before publication, equivalent advisory IDs are collapsed into one entry with
a `CVE-*` ID preferred when available. The alias index combines the local
GitHub Advisory Database checkout with `~/.cache/cve-analyzer/osv-bulk/*.zip`;
the OSV supplement covers CVE/GHSA pairs that exist only in a current OSV bulk
record. Malformed archives and records are logged and skipped as whole alias
inputs, so partial data cannot create an inferred equivalence.

`writer.py` treats this directory as a generation:

1. Validate every entry, the manifest, stats, identifier/filename safety,
   duplicate ids, and cross-file aggregates in memory.
2. Write all artifacts into a sibling staging directory and re-read them
   through the fail-closed consumer.
3. Compute a canonical SHA-256 `generation_id` over the ordered entries and
   aggregates, then embed it in the index, stats, and every per-CVE file.
4. Require a schema-4 release receipt with the same `generation_id` and
   `generated_at`; exact curation/held-out report, selection, and label hashes;
   exact end-to-end recall selection, label, report, and inventory hashes; the
   protected-census manifest digest, overlap count, and completion bit; an exact
   verifier source/dependency manifest bound to trusted Git commit and tree
   objects; at least
   95% certified independent precision and conditional recall; complete
   denominators; an end-to-end recall point and family-wise 95% interval lower
   bound at or above the receipt recall target; and `evaluation_complete: true`
   plus `release_safe: true`.
   The formal Python entry disables bytecode writes before importing repository
   modules; any pre-existing ignored bytecode or native-extension shadow remains
   a verifier-contract failure.
5. Promote the staged directory with Linux `renameat2(RENAME_EXCHANGE)` while
   holding the parent-directory publication lock. If a recoverable exception
   interrupts post-exchange durability work, restore the previous generation.

Before step 5, the generator durably archives the complete proof under
`.ai-slop/state/data-refresh/release-evidence-v1/<generation_id>/`. Each write-once
bundle contains the campaign diagnostic report, publication-curation report,
held-out selection, independent labels, held-out report, recall selection,
recall labels, recomputed recall report, campaign contract and result manifest,
publication file manifest, exact source snapshot and
remote-cutoff receipt, and the staged release receipt. `manifest.json`
binds the fixed artifact inventory with raw-file and canonical-JSON SHA-256
digests plus one canonical bundle digest. The generator re-reads the archive,
checks every cross-artifact digest against the release receipt, and blocks
promotion on any missing, extra, unsafe, changed, or mismatched artifact.
It also validates the exact schema-2 Git/NVD/OSV source inventory and replays
the selection-before-label commits only in the verifier's trusted repository;
the evidence bundle cannot choose its own Git trust anchor.
The archive is a candidate until promotion succeeds. Before the directory
exchange, the generator durably writes an evidence-bound candidate record at
`.ai-slop/state/data-refresh/release-evidence-v1/activations/pending/<generation_id>.json`.
After promotion it rechecks the campaign, protected inventory, held-out
artifacts, live publication, and receipt, then creates
`activations/<generation_id>.json` and removes the pending record. A finalization
failure leaves a verifiable candidate record that the idempotent activation
reconciler can finish after live-release verification.

Python readers share the parent lock and observe one complete directory. The
Next.js reader also checks the shared `generation_id`, so a concurrent
promotion during a build fails closed instead of combining files. Static HTML
embeds that identity and the postbuild verifier compares every generated app
page and the formal receipt with the current index. A legacy `cves.json` and
stale per-CVE files disappear with the old generation after a successful
promotion.

The schema-4 recall selection seals every protected alias class that overlaps
the formal inventory in a separately hashed `protected_census` sub-artifact.
Schema-3 recall labels bind exact-once independent adjudications to that census
digest. Release stays blocked for a missing, unresolved, `UNKNOWN`, drifted, or
tampered census; a complete census contributes exact finite-population counts to
the end-to-end recall estimate while remaining outside random sampling.

Accepted filenames use the schema's path-safe vulnerability ID contract: an
ASCII letter or digit followed only by ASCII letters, digits, dots,
underscores, or hyphens. This supports CVE, GHSA, OSV, JLSEC, GO, HSEC, and
future advisory families. `writer.py` rejects separators, traversal,
whitespace, hidden-file names, symlinked publication boundaries, duplicate
ids, omitted files, and extra files.

## Schema contract

`schema.py` is the Python source of truth for `CveEntry`, `CvesIndex`, and
`StatsData`.

- The producer validates before publication.
- `ts_types.py` generates `web/src/lib/types.generated.ts` from the same
  definitions.
- Python release gates validate committed artifacts and publication invariants.
- `web/src/lib/data.ts` performs a second fail-closed manifest/file check at
  build and revalidation time.

Regenerate or check TypeScript types after a schema edit:

```bash
python3 scripts/web_data/ts_types.py
python3 scripts/web_data/ts_types.py --check
```

## Consumers

- `web/src/lib/data.ts` assembles the ordered in-memory `CvesData` view.
- `scripts/pipeline_funnel.py` loads the same validated generation for funnel
  diagnostics. Missing or inconsistent artifacts terminate diagnostics so a
  partial publication cannot be reported as zero entries.

## Module map

| Module | Role |
| --- | --- |
| `loader.py` | Read analysis caches and supplementary metadata |
| `filters.py` | Apply publication inclusion rules |
| `entry_builder.py` | Project analyzer models into public entries |
| `severity.py` | Normalize severity and CVSS |
| `languages.py` | Infer affected languages |
| `stats.py` | Build aggregate counts |
| `schema.py` | Validate the Python/JSON/TypeScript contract |
| `ts_types.py` | Generate TypeScript interfaces |
| `writer.py` | Validate, stage, promote, and read complete generations |
