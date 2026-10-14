---
name: radar-incremental
description: Bring new and revised vulnerability advisories into Vibe Security Radar since the recorded source watermark - capture GitHub and NVD streams for a frozen window, reconcile identities against the ledger and prior deltas, admit eligible new rows as UNANALYZED, advance the watermark and hand the admitted cases to radar-lead for research. Run by the leader; not for researching a case.
---

# Radar incremental

The leader runs this skill. It ends with a manifest of newly admitted cases, which
[radar-lead](../radar-lead/SKILL.md) researches like any other case. Capturing or admitting
an advisory is source accounting, never a research conclusion.

Run from the repository root with `.venv/bin/python` (see `scripts/requirements.txt`)
under `numactl --cpunodebind=1 --membind=1`. Use `GITHUB_TOKEN`/`NVD_API_KEY` from the
environment when available; never put them in arguments or files.

## 1. Freeze the window

Read `artifacts/source-watermark.json`. The new window starts at its `next_window_start`
(the whole boundary day before the last watermark, so delayed ingestion is caught) and
ends at a fixed UTC instant now, at most microsecond precision. Create a fresh run
directory `R=.ai-slop/state/incremental-<END>` and write `$R/window.json`
(`start`, `end`, `inclusive: true`). Never move the end while fetching.

## 2. Freeze the baseline

```sh
python3 scripts/ledger_store.py check          # must report jsonl_byte_identical: true
cp artifacts/funnel-account-20260817.jsonl $R/baseline-ledger.jsonl
python3 scripts/claims.py list > $R/occupancy.jsonl
```

## 3. Capture

```sh
python3 .agents/skills/radar-incremental/scripts/fetch.py --window $R/window.json --output $R/capture
```

It captures six streams (GitHub reviewed and unreviewed, both withdrawn streams, NVD
published and modified) with page receipts, pacing and no automatic retries.
`capture/coverage.json` must say `COMPLETE`. A failed or empty page is a coverage gap,
not zero advisories; resume only into the same frozen window.

## 4. Classify

```sh
python3 .agents/skills/radar-incremental/scripts/build_delta.py --capture $R/capture \
  --ledger $R/baseline-ledger.jsonl --universe .ai-slop/sources/universe/universe.jsonl \
  --occupancy $R/occupancy.jsonl --prior-delta <each delta_chain path, oldest first> \
  --out $R/classification
```

Pass the whole `delta_chain` from the watermark; passing only the last delta loses
off-ledger identities. Identities join only through explicit CVE/GHSA relationships, never
titles, shared repositories or reference URLs. The routing counts in `summary.json` are open
queues: `REPOSITORY_DISCOVERY`, `PRODUCT_SOURCE_REVIEW` (beyond what step 5 admits),
`EXISTING_SOURCE_REVALIDATION`, `ADVISORY_STATUS_REVIEW` (withdrawn or rejected sources),
`IDENTITY_CONFLICT` (a new alias joining separately owned components; never merge rows to
resolve it) and `EXISTING_OWNER_HANDOFF`. Record them; none is a verdict.

## 5. Admit and land the intake

```sh
python3 .agents/skills/radar-incremental/scripts/intake_rows.py --delta $R/classification/delta.jsonl \
  --capture $R/capture --universe .ai-slop/sources/universe/universe.jsonl \
  --prior-delta <same chain> --out $R/intake
python3 scripts/ledger_store.py intake $R/intake/new-ledger-rows.jsonl --actor <leader> \
  --description "Incremental intake <start>..<end>"
```

`intake_rows.py` applies the unchanged funnel policy: new identities (or linked off-ledger
precursors) with an active reviewed GitHub advisory published inside the window, one
reviewed product repository corroborated by a same-repository advisory, and no ledger row,
conflict or occupancy. Original-universe identities go to `deferred.jsonl` for review
rather than widening the policy. `intake` writes the rows atomically as revision-one
`UNANALYZED`, refuses foreign occupancy and stale exports, and adds nothing on an exact
repeat. Read back the inserted rows with `ledger_store.py get` and run `check` again.

## 6. Advance the watermark

```sh
python3 .agents/skills/radar-incremental/scripts/watermark.py $R
```

It refuses an incomplete capture or a delta not classified against the complete recorded
chain, then copies the delta into `.ai-slop/sources/deltas/` and records it. Commit the
updated `artifacts/source-watermark.json` with the refreshed export.

## 7. Hand off and report

Give `$R/intake/manifest.txt` to radar-lead (step 2, `radar_case.py prepare`) with the
window end as `--cutoff`. Report the window and stream coverage, components classified, rows
admitted and deferred, each open queue's count, the ledger change set, and that research
on the admitted cases is still pending.

## References

| Read | When |
| --- | --- |
| [../radar-lead/references/ledger.md](../radar-lead/references/ledger.md) | Before landing intake: row fields and statuses |
| [../radar-lead/references/operations.md](../radar-lead/references/operations.md) | For claims and the shared command environment |
