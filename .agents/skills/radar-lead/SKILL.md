---
name: radar-lead
description: Coordinate Vibe Security Radar case research end to end - select cases from the ledger or a new intake, run independent auditors, one adjudicator and a fresh-session review per case with scripts/radar_run.py, land accepted research in the canonical ledger and prepare publication. Use for coordination, recovery, landing and release; not for researching a case yourself.
---

# Radar lead

Contract `2026-10-14.1`. You own case selection, dispatch, acceptance, ledger landing and
publication. Research rules live in [AUDIT-PROTOCOL](../../../docs/AUDIT-PROTOCOL.md) and
[ADJUDICATION-PROTOCOL](../../../docs/ADJUDICATION-PROTOCOL.md); commands in
[scripts/README.md](../../../scripts/README.md); landing and publication in the
[release runbook](../../../docs/RELEASE-RUNBOOK.md).

Keep your own context administrative: statuses, paths, hashes and next questions. Case
evidence stays in each case's workspace, where auditors, the adjudicator and the reviewer
read it in their own fresh sessions.

## Inputs

- The user's scope and authorized endpoint: `research` (handoff only) or `ledger`
  (land accepted research). Publication is a separate, explicit authorization.
- A runner profile: start from `scripts/runner.example.json`; keep the real one local
  (`.ai-slop/runner.json`). Check it once with a harmless multi-turn prompt before a run.
- Run every command from the repository root with `.venv/bin/python` under
  `numactl --cpunodebind=1 --membind=1` (see AGENTS.md).

## 1. Select cases

Write a manifest with one `class_id` per line. For new advisories, take the manifest that
[radar-incremental](../radar-incremental/SKILL.md) admitted. For the existing ledger, read
the export (after `ledger_store.py check` shows `jsonl_byte_identical: true`) in this order:

1. `AI_ROOT_CAUSE`/`AI_CODE_FLAWED` rows without `causal_research` (they are public);
2. `NOT_AI` rows whose `notai_review_state` is `CAUSAL_REVIEW_PENDING`;
3. `PARTIALLY_ANALYZED`, then `UNANALYZED`.

Start a new run with about five cases and inspect them before scaling.

## 2. Run

```sh
python3 scripts/radar_run.py admit --run <run> --manifest <file> --leader <you> \
  --endpoint ledger --profile .ai-slop/runner.json --cutoff <source cutoff UTC>
python3 scripts/radar_run.py run --run <run> --parallel 4
python3 scripts/radar_run.py status --run <run>
```

`admit` claims each case, retains its advisory records as a neutral packet, freezes one
contract per role and registers both auditors. `run` advances each case through both
auditors, the adjudicator and a reviewer, each in a fresh sandboxed session, under the
node-memory gate. Read `status`, not the workers' output:

| Phase | Next step |
| --- | --- |
| `READY_TO_LAND` | Land (step 4). |
| `HOLD` | Inspect the named task's receipts in `research/<batch>/.logs/` and index. For an ordinary runtime fault confirm the worker stopped, write an inspection (`batch`, `task`, `binding_sha256`, `attempt_id`, `classification`, `previous_work_stopped: true`, `evidence` pins) and use `radar_run.py resume`; never retry blindly. |
| `RETURNED` | The review named a decisive question. Continue the same adjudicator as a labeled continuation (`radar_flow.py migrate`, scripts/README.md). |
| `SAFETY_STOP` | An upstream refusal stopped the run. Preserve it, tell the user, and do not resume, rephrase or switch models until they resolve the upstream configuration. |
| `FOREIGN_HOLD` | Another owner holds the case; arrange a real handoff. |

## 3. Review one case

The reviewer session runs this section for one case; you can run it yourself the same way.
Read the adjudicator's sealed delivery and the auditors' reports, then check the decisive
claims against primary evidence:

- the parent of the claimed introducing change, under matched configuration and authority;
- the real caller of the claimed repair and any material omitted route;
- the object that carries each AI marker, and the activity it discloses;
- that report, record, `impact` and `remaining_gap` agree.

Write `leader-review.json` with `decision` `ACCEPT` or `RETURN`, a substantive `basis`,
`evidence` entries from the delivery's `files`, and for RETURN the `next_question`.
Accept a BLOCKED decision only when the blocker is researched, not an execution failure.

## 4. Land

```sh
python3 scripts/radar_run.py land --run <run>
```

Accepted research lands through `radar_release.py`: every attempt is stored as a scan run
and assessment, the frozen reduction gate is rerun on all lanes, the row is finalized at
its admitted revision, read back, the export is verified and the exact claim is released.
A non-AI verdict clears `site_scope`/`site_tier`. A researched blocker keeps the row
unchanged and stores its assessments. A changed row, duplicate TP alias or stale export
holds the case.

## 5. Publish (separate authorization)

New or changed AI rows need editorial inputs before the site can be regenerated. In a
scratch worktree, run `python3 scripts/publish_tp_ledger.py --from-export`; each error
names what is missing:

1. `missing reader summary`: add an entry to `scripts/publication-curation.json`
   (`case_id`, `class_id`, `mechanism`, `code_evidence.summary`) written as public prose
   from the accepted `causal_research` - no SHAs, paths or `PR #`.
2. `missing published_at`: add the advisory's first-party publication date, from the
   retained advisory record, to `scripts/first-party-advisory-dates.json`.
3. `no code comparison`, listing/fix SHA mismatches: rebuild code evidence with
   `python3 scripts/build_missing_code_evidence.py artifacts/funnel-account-20260817.jsonl`
   (`FORCE_IDS="<case ids>"` for a case whose research changed).

Repeat until it passes, then follow the runbook: `npm run research:data:sync`,
`npm run build`, `npm run research:data:check` in `web/`, commit, and push `main` only with
the user's authorization (a push deploys). Verify each changed page live.

## Close

Record each case's outcome in `status` before releasing anything; `land` releases claims
itself. Report separately: cases researched, accepted, blocked, held; rows landed with
revisions; publication done or pending; remaining questions with their owner.
