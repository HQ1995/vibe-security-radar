# Operations

Commands for the research workflow, run from the repository root with the repository
environment and the NUMA binding in [AGENTS.md](../../../../AGENTS.md):

```sh
uv venv .venv && uv pip install --python .venv/bin/python -r scripts/requirements.txt
numactl --cpunodebind=1 --membind=1 .venv/bin/python scripts/<tool>.py ...
```

## Operating arrangement

The workflow runs inside a local Codex or Claude Code session. The session that loads
radar-lead is the leader; every other role is a fresh Codex session it starts on a
preferred model.

| Role | Skill | Owns |
| --- | --- | --- |
| Leader | radar-lead, radar-incremental | Selection, claims, sealing, acceptance, canonical writes, publication |
| Auditor (two or more) | radar-audit | `research/<run>/<NNN>/auditor1` ... `auditorN` |
| Adjudicator | radar-adjudicate | `research/<run>/<NNN>/adjudicator` |
| Reviewer | radar-lead, "Review one case" | `research/<run>/<NNN>/reviewer/review.json` |

Every role runs on a model from [models.json](../models.json), the project's preferred
models; `prompt` refuses any other model and refuses giving two auditors of one case the same
model. Auditors are DeepSeek V4.1 Flash and Claude Haiku 5.5, one each per case; GLM-5.3-Flash
is off the auditor list (it delivered 15 of 29 attempts, mostly ending in tool-call loops).
The adjudicator and reviewer use GLM-5.3, or Daybreak when Magpie's codex provider is signed in.
Change the list there, not per run.

Start each role as a fresh Codex session on the local Magpie gateway, in the background from
the leader's shell (either host), one per role:

```sh
P=research/<run>/<NNN>/scratch/<role>
A=$(python3 scripts/radar_case.py prompt --run <run> --case <NNN> --role <role> --model <model> --host codex-magpie)
printf '%s' "$A" | python3 .agents/skills/radar-lead/scripts/role_session.py --model <model> \
  --scratch $P --out research/<run>/<NNN>/<role>
```

Prompt the lanes of one case a few seconds apart: `prompt` rewrites `case.json`, and two at the
same instant can drop one role's record. Start all auditors of a case before waiting, and wait for
every one before `seal`; `reply.md` holds each summary and `session-status.json` how the session
ended (exit 0, 124 timeout, 125 stopped for a tool loop). A stopped loop or timeout is an
execution failure: start the lane again on a model it has not failed on.

`role_session.py` fixes the session settings rather than inheriting the user's Codex config:
reasoning effort `xhigh` for every model, Haiku included (the personal default `max` made Haiku
sessions spend their budget on 100k-token responses: 8 of 8 delivered at `xhigh`, 11 of 28 at
`max`; the gateway usage log shows the effort each request carried), no cross-session memory, compaction at 500k tokens (the preferred models hold
1M), and no MCP servers, sub-agents, goals or image generation (their tool schemas cost about 31k
tokens per request). It stops a session that repeats the same tool call 12 times in a row (GLM
sessions looped on one command for up to an hour). If the session has not written REPORT.md and
record.json after 30 minutes, it resumes the same session once with a finish-now note; sessions
that wrote REPORT.md early delivered 22 of 24 times, those that did not 12 of 40. The timeout stays
75 minutes. The prompt goes in on stdin
so no session can read another's assignment from the process list. `curl -s http://127.0.0.1:3425/v1/models` shows what the gateway serves.
A session that has written `reply.md` can still linger. Before stopping one, confirm which lane it
is with `readlink /proc/<pid>/fd/1`, which names its `session.log`; process lists do not show the
lane. A `429 Too Many Requests` that exhausts Codex's retries ends the session without a reply:
start the same role again on the same model once the provider answers, and say its directory
holds an unfinished attempt.
A reply is not proof that the files changed. Before prompting the reviewer, confirm that
`check --dry-run` reports the outcome the reply states and, after a reopen, that the deliverables
differ from the archived `adjudicator-vN`; if they do not, prompt the role again and say so.

Each session starts with no conversation history. That, the read limits in its assignment
and sealing keep the lanes independent; isolation is by instruction, not by sandbox, so
never put one lane's findings into another lane's prompt.

## Case directory

```text
research/<run>/run.json, STOP               leader
research/<run>/<NNN>/case.json              leader: identity, base revision, claim, contract commit, roles and models
                     state.json             leader: phase and next step
                     manifest.txt, inputs/  neutral packet: question and advisory records with receipts
                     assignments/<role>.md  the exact prompt each subagent received
                     auditor1/, auditor2/   one auditor each; read-only after seal
                     adjudicator/           read-only after a passing check
                     reviewer/review.json
                     scratch/<role>/        scratch clones and experiments; never sealed
                     SEAL.json, decisions.json, gate.json, land/
```

## Case commands

```sh
python3 scripts/radar_case.py prepare --run <run> --manifest <class ids> --leader <name> --cutoff <UTC> [--auditors N]
python3 scripts/radar_case.py prompt --run <run> --case <NNN> --role <role> --model <model> [--host <h>]
python3 scripts/radar_case.py lint <role directory>
python3 scripts/radar_case.py seal --run <run> --case <NNN>
python3 scripts/radar_case.py compare --run <run> --case <NNN>
python3 scripts/radar_case.py check --run <run> --case <NNN> [--dry-run]
python3 scripts/radar_case.py reopen --run <run> --case <NNN>
python3 scripts/radar_case.py land --run <run> [--case <NNN>]
python3 scripts/radar_case.py status --run <run>
python3 scripts/radar_case.py stop --run <run> --case <NNN> --reason <text> [--evidence <file>]
```

- **prepare** reads each row (`ledger_store.py get`), holds a case another owner occupies,
  claims the rest, retains its advisory records from GitHub and NVD with receipts, and
  records the repository commit that carries the contract. `--auditors N` (default 2, at most
  the number of auditor models) sets how many independent lanes each case gets.
- **prompt** prints and saves the assignment for one role (`auditor1` ... `auditorN`,
  `adjudicator`, `reviewer`) on a model allowed for that role, and records the model and host. The adjudicator's prompt needs
  every lane sealed; the reviewer's needs a passing check.
- **lint** checks a role directory: required files, class ID, protocol version, the
  research-work sidecar and its receipts. Workers run it themselves.
- **compare** shows, for each research dimension and field, what every delivered lane (and
  the adjudicator, once it delivers) concluded, with its model. It reads records only.
- **seal** needs every lane to lint clean, records their record-gate results and the hash
  of every file, and makes the files read-only. Until then nothing is sealed and the
  auditors can still fix their work.
- **check** verifies the sealed lanes, builds `decisions.json` from the adjudicator's
  `decision.json` and runs the reduction gate on every lane. A pass (ACCEPTED, or a
  researched BLOCKED) seals the adjudicator; otherwise its problems go back to the
  adjudicator. `--dry-run` writes nothing.
- **reopen** keeps a checked adjudication and its review as `adjudicator-vN/` and
  `reviewer-vN/` and gives the adjudicator a writable copy for a labeled continuation.
- **land** validates the review, stores one scan run and assessment per role, then
  finalizes the research at the prepared revision with readback and an export check (a
  researched blocker lands as `BLOCKED`), and releases the claim. It never
  repeats a finalize whose result it cannot read back.
- **stop** records an upstream refusal or operating stop; `prepare` and `prompt` refuse new
  work in the run until it is resolved with the user.

## Claim commands

The shared log is `artifacts/claims/claims.jsonl` (local, never published); always run this
checkout's `scripts/claims.py`.

```sh
python3 scripts/claims.py claim --class-id <id> --owner <leader> --scope <batch>
python3 scripts/claims.py list [--class-id <id>] [--all]
python3 scripts/claims.py release --class-id <id> --owner <leader> --claim-id <receipt id>
```

Claims mean occupied or free, never research progress. Keep the receipt ID; neither another
owner nor an old receipt can release a newer acquisition. Leases expire after 24 hours but an
expired foreign claim still blocks ledger writes: find the owner, confirm the work stopped, write a
stopped-work handoff and release it with its own claim ID.

## Incremental intake

`fetch.py`, `build_delta.py`, `intake_rows.py` and `watermark.py` live with the
[radar-incremental](../../radar-incremental/SKILL.md) skill, which gives their order.
`artifacts/source-watermark.json` records the verified source cutoff and the full delta chain;
its data files are kept in `.ai-slop/sources/`. Frozen batches from before 2026-10-14 that
imported `cve_analyzer` replay with `PYTHONPATH=<worktree at f857e3f>/cve-analyzer/src`.

## Publication

`publish_tp_ledger.py` builds `web/src/generated/research-data.json` from Neon (or a
digest-matching export) plus the committed editorial inputs in `scripts/*.json`;
`site_preflight.py` (which also checks `scripts/publication_adjudications.json`) and
`check_advisory_links.py` gate the build. The radar-lead skill's Publish section lists the inputs a
new or changed AI case needs; [release](release.md) covers build, deploy and live verification.

Offline tests: `python3 -m pytest scripts/tests .agents/skills/radar-audit/scripts
.agents/skills/radar-lead/scripts .agents/skills/radar-incremental/scripts`. They use
fixture deliveries, real gates and fake ledgers; they never contact Neon.
