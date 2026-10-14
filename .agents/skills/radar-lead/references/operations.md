# Operations

Commands for the research workflow, run from the repository root with the repository
environment and the NUMA binding in [AGENTS.md](../../../../AGENTS.md):

```sh
uv venv .venv && uv pip install --python .venv/bin/python -r scripts/requirements.txt
numactl --cpunodebind=1 --membind=1 .venv/bin/python scripts/<tool>.py ...
```

## Operating arrangement

The workflow runs inside a local Codex or Claude Code session. The session that loads
radar-lead is the leader; every other role is a fresh subagent it starts with the host's
own tools.

| Role | Skill | Owns |
| --- | --- | --- |
| Leader | radar-lead, radar-incremental | Selection, claims, sealing, acceptance, canonical writes, publication |
| Auditor (two or more) | radar-audit | `research/<run>/<NNN>/auditor1` ... `auditorN` |
| Adjudicator | radar-adjudicate | `research/<run>/<NNN>/adjudicator` |
| Reviewer | radar-lead, "Review one case" | `research/<run>/<NNN>/reviewer/review.json` |

| Host | Starting a subagent |
| --- | --- |
| Claude Code | The Agent tool with the assignment text as the prompt; its `model` choice covers the Claude models. Start several in the background and wait for their notifications. |
| Codex | Spawn a subagent with the assignment text. |
| Any model on Magpie, from either host | One CLI session per lane, in the background (below). |

The models on the local Magpie gateway are listed by `curl -s http://127.0.0.1:3425/v1/models`
(GPT, Claude, DeepSeek, Grok, GLM, Gemini, MiMo and others). Start a lane on one of them:

```sh
P=research/<run>/<NNN>/scratch/<role>; mkdir -p $P
A=$(python3 scripts/radar_case.py prompt --run <run> --case <NNN> --role <role> --model <model> --host <codex|claude>-magpie)
codex exec -c model_provider=magpie -m <model> --skip-git-repo-check \
  --output-last-message $P/reply.md "$A" > $P/session.log 2>&1
claude -p --dangerously-skip-permissions --model <model> "$A" > $P/reply.md 2> $P/session.log
```

Use either command; both reach every model the gateway serves. Run one per lane in the
background and wait for all of them before `seal`.

A subagent starts with no conversation history. That, the read limits in its assignment
and sealing keep the lanes independent; isolation is by instruction, not by sandbox, so
never put one lane's findings into another lane's prompt. Give every auditor a different
model; a different model is a more independent opinion.

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
python3 scripts/radar_case.py prompt --run <run> --case <NNN> --role <role> [--model <m> --host <h>]
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
  records the repository commit that carries the contract. `--auditors N` (default 2) sets
  how many independent lanes each case gets.
- **prompt** prints and saves the assignment for one role (`auditor1` ... `auditorN`,
  `adjudicator`, `reviewer`) and records the model and host. The adjudicator's prompt needs
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
- **land** validates the review, stores one scan run and assessment per role, then either
  finalizes accepted research at the prepared revision with readback and an export check,
  or closes a researched blocker without changing the row, and releases the claim. It never
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
expired foreign claim still blocks ledger writes: find the owner and arrange a real handoff.
`pick` and `sweep` are disabled.

## Incremental intake

`fetch.py`, `build_delta.py`, `intake_rows.py` and `watermark.py` live with the
[radar-incremental](../../radar-incremental/SKILL.md) skill, which gives their order.
`artifacts/source-watermark.json` records the verified source cutoff and the full delta chain;
its data files are kept in `.ai-slop/sources/`. Frozen batches from before 2026-10-14 that
imported `cve_analyzer` replay with `PYTHONPATH=<worktree at f857e3f>/cve-analyzer/src`.

## Publication

`publish_tp_ledger.py` builds `web/src/generated/research-data.json` from Neon (or a
digest-matching export) plus the committed editorial inputs in `scripts/*.json`;
`site_preflight.py`, `check_advisory_links.py` and `build_publication_adjudications.py
--verify-committed` gate the build. The radar-lead skill's Publish section lists the inputs a
new or changed AI case needs; [release](release.md) covers build, deploy and live verification.

Offline tests: `python3 -m pytest scripts/tests` and the skill's `scripts/` tests use
fixture deliveries, real gates and fake ledgers; they never contact Neon.
