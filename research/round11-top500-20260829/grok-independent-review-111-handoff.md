# Grok handoff: Round11 remaining 111 independent reviews

这份文件可直接交给 Grok。任务是给 Round11 尚未进入 389-case second pass 的
111 份 canonical primary 做真正独立二审，不是复述 primary，也不是直接改账。

## Frozen scope and readiness

- Scope source: set difference between the 500 frozen `manifest.jsonl` rows and
  the 389 physical `independent-review/wXXX.json` files.
- Exact assignments: `research/round11-top500-20260829/grok-independent-review-111-assignments.jsonl`.
- Cases: **111**; unique workers: **111**; all 111 primaries and bundles exist.
- All 111 bundle hashes match the frozen manifest; all 111 clone directories exist.
- Primary-verdict snapshot: `{'NOT_AI': 108, 'EVIDENCE_GAP': 2, 'FALSE_POSITIVE': 1}`.
- The assignment row freezes both `bundle_sha256` and current `primary_sha256`.
  Stop that case as `BLOCKED` if either hash no longer matches.

Workers, exactly:

`w350 w380 w381 w383 w385 w386 w388 w390 w391 w392 w393 w394 w396 w399 w401 w402 w403 w405 w406 w407 w408 w410 w411 w412 w413 w414 w415 w416 w417 w418 w419 w420 w421 w422 w423 w424 w425 w426 w427 w428 w429 w430 w431 w432 w433 w434 w435 w436 w437 w438 w439 w440 w441 w442 w443 w444 w445 w446 w447 w448 w449 w450 w451 w452 w453 w454 w455 w456 w457 w458 w459 w460 w461 w462 w463 w464 w465 w466 w467 w468 w469 w470 w471 w472 w473 w474 w475 w476 w477 w478 w479 w480 w481 w482 w483 w484 w485 w486 w487 w488 w489 w490 w491 w492 w493 w494 w495 w496 w497 w498 w499`

## Required execution model

Use **111 fresh clean contexts, one context per worker**. Each context may read only:

1. `docs/AUDIT-PROTOCOL.md`, `docs/DATA-SCHEMA.md`, and this handoff;
2. its one exact assignment row;
3. its exact frozen bundle and canonical primary;
4. that case's clone and first-party advisory/CVE/commit/PR/tag/release sources.

A reviewer must not read another case, any existing `independent-review` result,
`independent-review-disagreement.md`, `disagreement-rereview/`, campaign verdict
histograms, or another reviewer's output. Do not share conclusions between contexts.
All heavy local work must run under `numactl --cpunodebind=1 --membind=1`.

Each reviewer writes only its assignment's `review_out`. Do not modify primary
records, the assignment manifest, reports, roster, website, clones, or any ledger.

## What each reviewer must independently establish

Review vulnerability first and AI attribution second. Explicitly establish:

1. the real vulnerability mechanism and complete source-to-sink;
2. the smallest surviving public atomic BIC;
3. absence of that mechanism in the BIC's immediate parent;
4. squash/merge/member decomposition, excluding moves, imports, refactors, and reverts;
5. affected and fixed release membership from exact objects;
6. the direct fixing commit, or a verified explicit unpatched state;
7. AI role from BIC-local evidence only.

Do not infer a missing gate. A named human author/committer on the actual BIC, with
no AI/bot/generator/co-author marker, supports `NOT_AI`; absence of an AI trailer
alone does not close identity when the object is an anonymous/placeholder/huge
untraceable snapshot. Published-but-contradicted advisories may be `FALSE_POSITIVE`
only when the claimed vulnerability itself is disproved; merely imprecise impact or
release metadata normally requires correction, not a false-positive verdict.

## Exact output schema

Top-level keys, in this order:

```text
worker, review_agent_id, class_id, case_id, repo, primary_verdict,
review_verdict, protocol_checks, findings, corrected_fields, remaining_gap
```

`review_verdict` is exactly one of `CONFIRMED`, `CORRECTION_REQUIRED`,
`EVIDENCE_GAP`, or `BLOCKED`. `protocol_checks` must contain these keys:

```text
vulnerability_mechanism
atomic_bic
immediate_parent_absence
squash_member_decomposition
affected_release_membership
fixed_release_membership
direct_fix_or_unpatched
bic_only_ai_attribution
```

Every check must say `PASS`, `FAIL`, or `GAP` and cite exact evidence. Commit IDs
must be full 40-hex. `findings` is a list of concrete findings. `corrected_fields`
contains only exact proposed replacements for canonical primary fields; it is empty
for `CONFIRMED`. `CORRECTION_REQUIRED` requires at least one corrected field.
`EVIDENCE_GAP` and `BLOCKED` require a precise non-empty `remaining_gap`.
A mechanically valid record is not complete unless all causal checks were actually
researched. `review_agent_id` must identify the clean context that did the work.

## Acceptance and return package

Return all 111 JSON files plus a short aggregate report containing:

- physical result count and exact missing/extra/duplicate worker IDs;
- review-verdict histogram;
- every `CORRECTION_REQUIRED`, `EVIDENCE_GAP`, and `BLOCKED` worker ID;
- confirmation that all input hashes matched;
- confirmation that no primary, ledger, report, roster, website, or clone was changed.

Completion means **111 physical files, 111 unique assigned IDs, every file parses,
every schema/identity/hash check passes, and every claimed causal gate has evidence**.
A partial batch must be reported as partial; do not call it complete.

## Local acceptance command

After Grok returns the files, run from repository root:

```bash
numactl --cpunodebind=1 --membind=1 python3 - <<'PY'
import hashlib, json
from pathlib import Path

root = Path('.')
lane = root / 'research/round11-top500-20260829'
assignments = [json.loads(x) for x in (lane / 'grok-independent-review-111-assignments.jsonl').read_text().splitlines() if x.strip()]
expected_keys = ['worker','review_agent_id','class_id','case_id','repo','primary_verdict','review_verdict','protocol_checks','findings','corrected_fields','remaining_gap']
check_keys = {'vulnerability_mechanism','atomic_bic','immediate_parent_absence','squash_member_decomposition','affected_release_membership','fixed_release_membership','direct_fix_or_unpatched','bic_only_ai_attribution'}
allowed = {'CONFIRMED','CORRECTION_REQUIRED','EVIDENCE_GAP','BLOCKED'}
out = lane / 'independent-review-111'
paths = sorted(out.glob('w[0-9][0-9][0-9].json'))
assert len(assignments) == len(paths) == 111
assert {p.stem for p in paths} == {a['worker'] for a in assignments}
by_worker = {a['worker']: a for a in assignments}
for path in paths:
    a = by_worker[path.stem]
    assert hashlib.sha256((root / a['bundle']).read_bytes()).hexdigest() == a['bundle_sha256']
    assert hashlib.sha256((root / a['primary']).read_bytes()).hexdigest() == a['primary_sha256']
    r = json.loads(path.read_text())
    assert list(r) == expected_keys
    assert (r['worker'], r['class_id'], r['case_id'], r['repo'], r['primary_verdict']) == (a['worker'], a['class_id'], a['case_id'], a['repo'], a['primary_verdict'])
    assert r['review_verdict'] in allowed and set(r['protocol_checks']) == check_keys
    assert r['review_agent_id'] and isinstance(r['findings'], list) and isinstance(r['corrected_fields'], dict)
    if r['review_verdict'] == 'CONFIRMED': assert not r['corrected_fields']
    if r['review_verdict'] == 'CORRECTION_REQUIRED': assert r['corrected_fields']
    if r['review_verdict'] in {'EVIDENCE_GAP','BLOCKED'}: assert str(r['remaining_gap'] or '').strip()
print({'ok': True, 'reviewed': len(paths)})
PY
```

## Explicit boundary

These results are review findings only. They do not become canonical corrections
until a separate reconciliation checks each proposed field against the cited objects.
Do not append to or finalize the canonical ledger as part of this task.
