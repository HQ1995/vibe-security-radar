---
name: radar-lead
description: Coordinate Vibe Security Radar case research from a local Codex or Claude Code session - select cases, start two or more independent auditors on different preferred models, an adjudicator and a reviewer per case as fresh local sessions, seal and check their work with scripts/radar_case.py, land accepted research in the canonical ledger and prepare publication. Use for coordination, recovery, landing and release; not for researching a case yourself.
---

# Radar lead

Contract `2026-10-15.1`. You run in the local session the user started; every other role is a
fresh session you start on one of the preferred models in [models.json](models.json). You own case selection, claims, sealing,
acceptance, ledger landing and publication. Keep your context administrative: `status`,
paths and next questions. Subagents reply with a short summary; read case evidence only when
you review a case yourself.

## Inputs

- The user's scope and authorized endpoint: research only, or ledger landing. Publication is
  a separate, explicit authorization.
- Run every command from the repository root with `.venv/bin/python` under
  `numactl --cpunodebind=1 --membind=1`.

## 1. Select cases

Write a manifest with one `class_id` per line. For new advisories, take the manifest that
[radar-incremental](../radar-incremental/SKILL.md) admitted. For the existing ledger, read the
export (after `ledger_store.py check` shows `jsonl_byte_identical: true`) in this order:

1. `AI_ROOT_CAUSE`/`AI_CODE_FLAWED` rows whose `causal_research` has no `protocol_version`:
   older-standard conclusions, and public;
2. other rows whose `causal_research` has no `protocol_version`;
3. `PARTIALLY_ANALYZED`, then `UNANALYZED`.

Skip rows with `duplicate_of_class_id`.

Start a new run with about five cases and inspect them before scaling.

## 2. Prepare

```sh
python3 scripts/radar_case.py prepare --run <run> --manifest <file> --leader <you> --cutoff <source cutoff UTC>
```

It claims each case, retains its advisory records as the neutral packet and records the
repository commit that carries the contract. A case another owner holds stays `FOREIGN_HOLD`.
Each case gets two independent auditors; add `--auditors N` (up to the number of auditor
models) for more opinions.

## 3. Run each case

Work on several cases at once within the host's subagent limit. For each case:

1. **Auditors.** Give each lane a different auditor model from [models.json](models.json)
   and start it as a fresh session with the command in
   [operations](references/operations.md#operating-arrangement); its prompt is exactly what
   `prompt --role auditorK --model <model>` prints. Start all lanes together.
2. **Seal.** When every lane has replied, `compare` shows where the models disagree (by
   dimension, with each lane's model); then run `seal`.
3. **Adjudicator.** Start it the same way on an adjudicator model, and run `check` when it
   replies.
4. **Reviewer.** Start it the same way on a reviewer model, or for a small run do section 4
   yourself and write `reviewer/review.json`.

Read `status`, not the subagents' work:

| Phase | Next step |
| --- | --- |
| `HOLD` | Do what `next` says. Send the listed `problems` back to the same subagent and rerun the step. If a subagent died without delivering, prompt its role again and tell the new subagent its directory holds an unfinished attempt it may continue. |
| `CHECKED` | Review (step 4), then land (section 5). |
| `RETURNED` | Run `reopen`, then give the review's `next_question` to the adjudicator as a labeled continuation, and `check` again. |
| `STOPPED` | A refusal or operating stop. Tell the user; do not resume, rephrase or switch models until they resolve it. |
| `FOREIGN_HOLD` | Another owner holds the case; arrange a real handoff. |

If any subagent reports a safety refusal, or the host refuses a turn, run
`stop --run <run> --case <NNN> --reason <what happened> --evidence <file>` and tell the user.

## 4. Review one case

The reviewer runs this section for one case; you can run it yourself the same way. Read the
adjudicator's report and record and every auditor's report, then check the decisive claims
against primary evidence:

- the parent of the claimed introducing change, under matched configuration and authority;
- the real caller of the claimed repair and any material omitted route;
- the object that carries each AI marker, and the activity it discloses;
- that report, record, `impact` and `remaining_gap` agree.

Write `reviewer/review.json` with `decision` `ACCEPT` or `RETURN`, a substantive `basis`,
`evidence` entries (absolute path and SHA-256 of sealed files under the case), and for RETURN
the `next_question`. Accept a BLOCKED outcome only when the blocker is researched, not an
execution failure.

## 5. Land

```sh
python3 scripts/radar_case.py land --run <run>
```

It stores one scan run and assessment per role, then finalizes accepted research at the
revision recorded by `prepare`, reads it back, verifies the export and releases the claim. A
non-AI verdict clears `site_scope`/`site_tier`. A researched blocker lands as status `BLOCKED`
with its EVIDENCE_GAP record. A changed row, duplicate TP alias, stale export or unreadable
earlier finalize holds the case.

## 6. Publish (separate authorization)

New or changed AI rows need editorial inputs before the site can be regenerated. In a scratch
worktree run `python3 scripts/publish_tp_ledger.py --from-export`; each error names what is
missing:

1. `missing reader summary`: add an entry to `scripts/publication-curation.json` (`case_id`,
   `class_id`, `mechanism`, `code_evidence.summary`) written as public prose from the
   accepted `causal_research`, without SHAs, paths or `PR #`.
2. `missing published_at`: add the advisory's first-party publication date, from the
   retained advisory record, to `scripts/first-party-advisory-dates.json`.
3. `no code comparison`, listing or fix SHA mismatches: rebuild code evidence with
   `python3 scripts/build_missing_code_evidence.py artifacts/funnel-account-20260817.jsonl`
   (`FORCE_IDS="<case ids>"` for a case whose research changed).

Repeat until it passes, then build, commit, and push `main` only with the user's
authorization (a push deploys). Verify each changed page live.

## Close

Report separately: cases researched, accepted, blocked, held; rows landed with revisions;
publication done or pending; remaining questions with their owner.

## References

| Read | When |
| --- | --- |
| [operations.md](references/operations.md) | How each host starts a subagent, running a lane on any Magpie model, the case directory, every `radar_case.py` command, claims |
| [ledger.md](references/ledger.md) | Before landing or editing canonical data: row fields, statuses, published-case rules |
| [release.md](references/release.md) | Manual landing, recovery after a failed write, and the build, deploy and verify steps |
| [assignments/](assignments/) | The templates `prompt` fills; change them there, not in the printed prompts |
| [models.json](models.json) | The preferred models for each role; the only ones `prompt` accepts |
| [../radar-adjudicate/references/protocol.md](../radar-adjudicate/references/protocol.md) | When reviewing a case or judging a returned question |
| [../radar-audit/references/protocol.md](../radar-audit/references/protocol.md) | When a review needs a question's exact requirement |
