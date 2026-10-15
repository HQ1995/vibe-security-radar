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
model. Auditors rotate over GLM-5.3-Flash, DeepSeek V4.1 Flash and Claude Haiku 5.5; the
adjudicator and reviewer use GLM-5.3, or Daybreak when Magpie's codex provider is signed in.
Change the list there, not per run.

Start each role as a fresh Codex session on the local Magpie gateway, in the background from
the leader's shell (either host), one per role:

```sh
P=research/<run>/<NNN>/scratch/<role>; mkdir -p $P
A=$(python3 scripts/radar_case.py prompt --run <run> --case <NNN> --role <role> --model <model> --host codex-magpie)
codex exec -c model_provider=magpie -c features.memories=false -c model_auto_compact_token_limit=500000 -m <model> --skip-git-repo-check \
  --output-last-message $P/reply.md "$A" > $P/session.log 2>&1
```

Start all auditors of a case together and wait for every one before `seal`; `reply.md` holds
each summary. `features.memories=false` keeps Codex's cross-session memory from carrying one session's findings
into another. The preferred models hold 1M tokens; compacting at 500k instead of a lower
personal default keeps a long audit from losing and re-reading its references. `curl -s http://127.0.0.1:3425/v1/models` shows what the gateway serves.

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

Offline tests: `python3 -m pytest scripts/tests` and the skill's `scripts/` tests use
fixture deliveries, real gates and fake ledgers; they never contact Neon.
