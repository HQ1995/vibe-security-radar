---
name: radar-incremental
description: Refresh Vibe Security Radar from new and revised vulnerability advisories since a recorded source cutoff. Use for incremental intake, classification, research queues, and authorized ledger updates; not for a one-case audit or a statistics-only refresh.
---

# Incremental vulnerability research

Carry every source change through an explicit disposition. A fresh ledger export
does not extend advisory coverage. A fetched or screened advisory is not an
accepted causal conclusion.

This is authorized analysis of existing vulnerability records and assigned cases. Follow
the technical evidence as deeply as the research question requires, including exploit
paths, PoCs and vulnerable/fixed behavior. Security-sensitive subject matter alone is not
a reason to stop or narrow the work. The limits below protect source accounting, case
ownership, credentials, canonical writes and publication.

Work in the ai-slop checkout under its `AGENTS.md`. Use the existing analyzer
environment (`cve-analyzer/.venv/bin/python`), NUMA policy, source parsers,
`radar-lead`, and release runbook. Keep raw sources and work manifests local.
Use `radar-audit` for independent case research and `radar-adjudicate` for the
assigned reducer; this skill does not provide a weaker research contract.

## Bind the increment

- Record the user's scope and authorized endpoint, current Neon snapshot digest,
  last verified source cutoff, source set, and a fixed UTC upper bound. Distinguish
  source coverage, research completion, accepted ledger revisions and publication.
- Read `artifacts/funnel-universe-meta-20260826.json` for the original universe
  policy and cutoff. A filename, export timestamp, or recent commit is not a new
  source watermark. The historical population uses CVE/GHSA identities and a
  product-source repository funnel; retain off-ledger dispositions too.
- With only a date-level prior cutoff, overlap that entire day and deduplicate.
  Subsequent runs also overlap the prior boundary to catch delayed ingestion.
  Freeze the window before fetching, so pagination does not chase a moving end.

Use explicit UTC window and receipt timestamps exactly representable at microsecond
precision; reject nonzero digits beyond the sixth rather than rounding. Extra trailing
zeroes preserve the instant and are allowed. Advisory source dates are separate:
retain every fractional digit when ordering lifecycle or publication observations.
Only genuinely equal instants use the conservative retirement tie rule.

## Capture and reconcile sources

Use `scripts/fetch.py` beside this skill for GitHub global advisories and NVD.
GitHub needs both reviewed and unreviewed streams: its default is reviewed only.
Use modification dates as well as publication dates, and retain withdrawn and
rejected records. Do not filter older published records out of a modification
window. Malware is a separate population and requires an explicit scope decision.

Keep response bodies, request URLs, response status, capture time, hashes and
pagination receipts. Validate each page and the terminal cursor/count. Resume
only matching, hash-verified successful pages from the same frozen window.
Classification replays the retained Link/NVD page chain without network access;
a `COMPLETE` flag alone is insufficient. Errors and schema drift remain coverage
gaps; an empty failed fetch is not zero new advisories. Honor provider pacing.

Run `scripts/build_delta.py` to reconcile the captured records with the canonical
export and the prior universe. It produces an inventory and research routing,
not AI verdicts. Verify the export's digest against Neon before treating it as
current. Preserve source-specific dates and identity provenance.
Retain an immutable copy of that verified export before ledger writes advance
the generated file; pin this baseline in the increment's manifest.

From the checkout root, with a new owned run directory containing `window.json`
(`start` and `end` in UTC), a frozen verified export, and a current
`occupancy.json` mapping claimed class/public IDs to claim entries:

```sh
numactl --cpunodebind=1 --membind=1 cve-analyzer/.venv/bin/python \
  .agents/skills/radar-incremental/scripts/fetch.py \
  --window "$RADAR_RUN/window.json" --output "$RADAR_RUN/capture"
numactl --cpunodebind=1 --membind=1 cve-analyzer/.venv/bin/python \
  .agents/skills/radar-incremental/scripts/build_delta.py \
  --capture "$RADAR_RUN/capture" --ledger "$RADAR_RUN/baseline/ledger.jsonl" \
  --universe "$RADAR_PRIOR_UNIVERSE" --occupancy "$RADAR_RUN/occupancy.json" \
  --out "$RADAR_RUN/classification"
```

Use existing authorized credentials through `GITHUB_TOKEN`/`NVD_API_KEY` when
available; never put them in arguments, source receipts or committed files.
Retain the capture and delta manifests as the next run's source baseline, along
with the prior universe. Do not replace the full baseline with this increment.
On later runs, pass earlier `classification/delta.jsonl` files with repeated
`--prior-delta` arguments, oldest first. Keep each matching `summary.json` beside
its delta when freezing or moving the baseline. The helper verifies delta hashes,
requires recorded ancestors, and rejects gaps between source windows. Passing only
the last delta would lose off-ledger identities not touched in that window.
The complete chain retains those identities and compares source payload hashes.
When a classifier correction changes identity or status routing, preserve the old
results and replay the affected retained windows in order, starting at the first
incorrect delta. Use that corrected chain subsequently; replacing the executable
alone cannot recover identities already flattened in an earlier delta.
An unchanged advisory does not by itself renew an expired research
contract or prove that earlier queued work was completed.

Join identities through explicit CVE/GHSA identifier relationships, never through
similar titles, shared repositories, or arbitrary reference URLs. Retain existing
class IDs. A new alias that connects previously separate owned components is an
identity conflict even if only one owner is in the ledger and no prior conflict
was recorded. A unique canonical owner can retain a legacy name only within an
already linked component; incoming alias edges cannot establish that exception.
These conflicts require review, not permission to replace or silently merge rows.
Missing old payload hashes mean unknown content change, not proven unchanged.

## Classify and research the whole delta

Account for new identities, existing identities observed in the change window,
retirements, missing repository mappings, alias conflicts and occupied cases.
Repository URLs from references are leads until verified as the affected product;
advisory databases and PoC repositories do not establish vulnerable source code.
An inaccessible or unmapped repository remains unresolved, not NOT_AI.
The helper separately identifies a reviewed `source_code_location` corroborated
by a same-repository security advisory. This supports intake mapping only, not
code-level mechanism, AI attribution or acceptance. Preserve the established
funnel when admitting new UNANALYZED rows; do not add every global CVE merely
because it appeared in this capture.

Reuse verified evidence only while its source, parser, research contract and
acceptance bindings remain valid. `cve-analyzer plan-incremental` can plan stage
reuse; it neither discovers all advisory changes nor grants research acceptance.
Group repository work to reuse clone/history evidence, while keeping case
ownership and independent reviewer contexts separate.

Use dispatch as the control plane and top-level model sessions as the default execution
unit. Start a fresh session for each independent case/lane and resume that recorded session
for its follow-ups. Keep frozen role instructions and tools as stable leading context and
case-specific material after them. Do not make nested subagents the default; use them only
after measured total cost or latency justifies them without weakening independence.

The leader creates a bound batch with `scripts/audit_dispatch.py`, claims eligible
cases, freezes neutral inputs and assigns all required independent lanes plus one
reducer. Occupied ledger classes, off-ledger classes and public-ID claims stay with
their owner, including expired claims. A prior unresolved alias conflict remains a
review route when a later source returns only one member or one original owner
enters the ledger. An omitted withdrawn/rejected source retains its status-review
obligation; only a newer same-source status can clear it automatically. Conflicting
same-time statuses stay unresolved. Retained source states come from the complete
prior-delta chain, not from assuming omitted records are active.
Continue the same case's follow-up with its assigned adjudicator. Preserve earlier
accepted bytes while revised evidence is under review.

Research the mechanism, atomic vulnerable contribution and parent, direct repair
or verified unpatched state, released exposure, and contribution-scoped AI evidence.
Repository AI activity, product branding, fix-side markers and absent keyword hits
do not decide causal authorship. Keep uncertain cases and their next decisive
question visible. Source retirement is not automatically a FALSE_POSITIVE verdict.

## Land and checkpoint

Use the leader-only `scripts/ledger_store.py` path and
`docs/RELEASE-RUNBOOK.md`: actual run metadata, full assessments, accepted causal
records, expected revisions, transactional landing, exact readback and verified
exports. Inspect supported intake operations before adding new classes; never
use bootstrap on a populated database or write the generated JSONL directly.
An intake row can be UNANALYZED without implying research acceptance. New terminal
verdicts require the same independent evidence and acceptance as existing cases.

For newly allocated research batches adopting the
[flow pilot](../../../scripts/README.md#foreground-flow-pilot), route the complete
manifest through `radar-lead` and its registered N-lane delivery plan. The leader uses
the release helper after source review and continues the authorized site runbook when
needed. Keep the captured source window and off-ledger queues alongside that handoff;
an automatic delivery checkpoint never advances the source cutoff or clears those queues.

For a reviewed new-row manifest, use `scripts/ledger_store.py intake FILE --actor
OWNER --description TEXT` after claiming its cases. It requires `source_intake`
with the UTC window, delta hash, source object paths/pointers/hashes and repository
mapping. It checks the local export against Neon under the transaction lock,
rejects existing aliases and different existing rows, and appends revision-one
IMPORT history. Refresh a stale export before retrying. Exact repeats add no rows
or history. Retain failed transaction receipts and verify the committed rows.

Refresh the whole-ledger summary from verified counts. Generate, build, deploy and
check changed public pages only within the authorized publication scope. Record
the endpoint before releasing claims. Existing authorization carries through
routine steps; do not ask the user to reapprove each stage.

Advance a **source capture** watermark only after all required streams are complete
and every captured identity has a recorded disposition. Never use it to imply
that queued research is finished. Record accepted ledger and publication progress
separately, with hashes and unresolved IDs. A second run over identical captured
inputs must produce the same delta and no duplicate ledger writes.

Report source window/coverage, new and revised identities, routing counts,
research acceptance, actual database changes and remaining dependencies. Do not
describe an intake inventory or a passing format gate as completed analysis.

Source API contracts:
[GitHub global advisories](https://docs.github.com/en/rest/security-advisories/global-advisories),
[NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities).
