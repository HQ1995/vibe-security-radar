# Case lifecycle and release

Use this for claims, handoff, ledger landing and website publication. Research rules
remain in [audit protocol](../../radar-audit/references/protocol.md) and
[adjudication protocol](../../radar-adjudicate/references/protocol.md); command details are in
[operations](operations.md). Run commands from the repository root
with the NUMA binding in [AGENTS.md](../../../../AGENTS.md), except where `web/` is specified.

The normal path is **leader claim -> N independent reports -> adjudication -> finalize
in Neon -> generate site data -> deploy and verify -> release**. Stop at the authorized
endpoint. `release` only clears occupancy; completed work and unfinished handoffs use
the same operation, with their different outcomes recorded in the case state.

## What each record means

| Record | Purpose | What changes it |
| --- | --- | --- |
| `artifacts/claims/claims.jsonl` | Whether a case is occupied and by whom | Leader's `claim`, then `release` with the same receipt ID |
| Frozen reports and adjudication decisions | What was researched and accepted | Auditors' owned reports, then one adjudicator's synthesis |
| Neon `ledger_rows` | The canonical ledger; the database and the ledger are the same source | Leader's `finalize`, with assessments and revision history in Neon |
| `artifacts/ledger.jsonl` | Generated recovery export of that ledger | Automatic export after `finalize`, or `export` |
| `web/src/generated/research-data.json` | Website projection of ledger rows and committed editorial inputs | `research:data:sync`; a deployment makes it live |

Only the leader writes canonical data. By default that same leader dispatches work,
accepts deliverables and owns release through live verification; a separate adjudicator
owns causal research. Roles, workspaces and shared claims follow the
[operating arrangement](operations.md#operating-arrangement). Combine roles only
when the user explicitly names that arrangement. Record the run,
intended changes and authorized endpoint once. Continue to
that endpoint without asking again at each routine step; research-only scope ends at
handoff. Keep the last verified step, receipts and next action beside the frozen research
files, without modifying the frozen decision file to record release progress.

## 1. Claim and finish the assigned work

`radar_case.py prepare` claims the whole case once and records its receipt ID in
`case.json`; auditors, the adjudicator and the reviewer take no claims. After both reports
are sealed, the adjudicator researches and delivers for leader acceptance. A researched
evidence gap differs from a crash or timeout; neither becomes accepted merely because a
subagent returned. The [case commands](operations.md#case-commands) carry each step.

Read occupancy with `list --class-id <id>`. A foreign holder, including an expired or
historical slot claim, blocks new ownership and ledger writes. Arrange a real handoff
before releasing it. Keep the leader's claim through the authorized endpoint, including
live verification when publication is in scope. Record the outcome, then release with
the original receipt ID. For unfinished handoffs, preserve outputs and the next question
and stop the old attempt before release. `claimed: false` establishes only availability.

## 2. Land accepted research in Neon

`radar_case.py land` performs this whole section per case (scan runs and assessments,
finalize, readback, export check, claim release); the steps below describe what it does
and how to do it by hand.

The release owner checks the final manifest, all auditor inputs, accepted records,
decisions and gate receipts under the frozen adjudication contract. Re-run the gate on
the final bytes before ingestion. A researched blocker lands as status `BLOCKED` with its
EVIDENCE_GAP record; it is not published.

Prepare assessments and revision-checked patches using the [data contract](ledger.md#ledger-rows).
Each assessment needs a recorded, active `run_id`, an explicit stable `assessment_id`,
the actual `base_ledger_revision`, agent identity and full reasoning/raw output. The leader
registers actual attempts with `ledger_store.py run-start`; preserve the real model,
prompt and source snapshot. Do not invent new run metadata to fill missing provenance.
Each patch carries `expected_revision`, supporting `assessment_ids` and the complete
updated `row`. Check current revisions (`ledger_store.py get <class-id>`), envelope
validity, advisory IDs and duplicate TPs. Ensure `row.causal_research` preserves the
accepted synthesis and canonical publication fields agree with it.

```sh
python3 scripts/ledger_store.py assessment-add <assessments.jsonl>
python3 scripts/ledger_store.py finalize <patches.jsonl> --actor <claim-owner> --description <run and case>
python3 scripts/ledger_store.py check
```

`assessment-add` saves evidence; it does not decide `ledger_rows`. `finalize` commits
the patch batch atomically with revision history, then automatically exports it. No
separate normal-path `export` is needed here. Check the returned change set, read back
the changed rows and compare their revisions/content to the prepared patches. Require
`check`'s `jsonl_byte_identical: true`; its exit code alone does not establish equality.
Save these receipts; release the case here only if ledger landing is the authorized
endpoint, otherwise retain it through the remaining work. Complete each scan
run with `ledger_store.py run-complete <run-id>` only after all its assessments are stored.
These are separate operations; neither `finalize` nor closing a run closes claims.

## 3. Generate and check the website

A new or changed AI case needs committed editorial inputs before generation can pass. Run
`python3 scripts/publish_tp_ledger.py --from-export` in a scratch worktree; it names each gap:
a reader summary and mechanism in `scripts/publication-curation.json`, the advisory's
first-party date in `scripts/first-party-advisory-dates.json`, and code evidence rebuilt with
`scripts/build_missing_code_evidence.py artifacts/ledger.jsonl`
(`FORCE_IDS=<case ids>` when research changed an already published case). Write the summary
as public prose from the accepted `causal_research`, without SHAs, paths or PR numbers.

Only when a landed change needs publishing, run in `web/`:

```sh
npm run research:data:sync
npm run verify:live
npm run build
npm run research:data:check
```

`sync` already runs export, the envelope gate and the publisher with
`--prefer-export`. It reads Neon; the export is used only when its SHA-256 matches the
Neon snapshot, otherwise the publisher reads Neon rows. Never hand-edit exports or the
generated payload. Update required editorial inputs from the accepted evidence, then
regenerate; do not use an allowlist or drop a failing case to make a gate pass.

`verify:live` fetches every published fix commit and advisory link; run it whenever the
payload changes and do not push data that fails it. The build itself stays offline: it checks
committed publication adjudications, the offline site preflight (including the committed
fix-object witness) and tests, so a deploy never depends on GitHub or advisory hosts. Inspect changed case content, additions/removals and counts
against the landed rows. For the offline payload check, run `publish_tp_ledger.py
--from-export` in a scratch root with the same inputs and compare the generated payload:
only `snapshot.generated_at`, ledger counters and `snapshot.ledger` provenance may differ.
Keep CI/tests off Neon; ordinary `dev`/`build` use generated data and do not sync it.

## 4. Deploy and verify the result

Commit the reviewed payload with its required overlays and push `main` within the
authorized scope. Cloudflare Pages Git integration builds `web/` into `out/` using
committed data, without Neon credentials; its build command installs `pytest` and runs
`npm run build`. Use `Deploy Pages (manual, from Neon)` only for a direct Neon republish,
not as another step after the Git deployment.

Record the deployed commit and verify the expected content on every changed public
case, including intended removals. Use the canonical uppercase ID and trailing slash:
`curl -sL -o /dev/null -w '%{http_code}' https://vibesecradar.com/cves/<UPPERCASE-ID>/`.
A 200 response alone does not prove the new content is live. Report research acceptance,
verified ledger landing and verified publication separately; local generation is not
publication, and a non-public verdict needs no new public case page.
After the authorized endpoint is verified and recorded, release the leader's claim
using the saved receipt ID.

## Resume after a failure

| Failure | Resume from |
| --- | --- |
| Foreign claim | Inspect its holder and saved work; obtain a real handoff and release before writing. Lease expiry does not release occupancy. |
| Interrupted `assessment-add` | Inspect `history <class-id>`; reuse the exact payload and IDs only while its run is active. Existing IDs are skipped, not compared or updated; revised evidence needs a new ID and `supersedes_assessment_id`. |
| Revision conflict or ambiguous `finalize` failure | Read `get` / `history` first. The transaction may have committed before export failed. If the intended rows landed, recover with `export` and `check`; otherwise reconcile the current revision before preparing a new patch. Never blindly replay a write. |
| Site generation, build or deployment failure | Keep the accepted research and landed ledger; fix the failed downstream step and repeat affected checks. If research itself changes, reopen its decision and land a new revision. |
| Leftover claims | Inspect `list --class-id <id>`, confirm the former work stopped and release that exact owner/receipt (plus historical slot when applicable). Ledger status cannot prove that current work has stopped. |
