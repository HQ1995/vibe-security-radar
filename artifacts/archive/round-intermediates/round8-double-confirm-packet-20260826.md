# Round8 double-confirm packet — 2026-08-26

Purpose: hand this to an independent reviewer to double-confirm the round8
causal-research wave (202 cases, one record per case). Everything below was
re-verified against the current repo state on 2026-08-26; verification
commands are included so the reviewer can re-run them from scratch.

## What round8 claims

202 PARTIALLY_ANALYZED ledger rows were researched per
`docs/AUDIT-PROTOCOL.md` (BIC = smallest first-writer commit; moves /
renames / refactors / squash aggregates are carriers, never BIC; AI role
judged only from signals on that BIC; one clean subagent context per case).

Headline verdicts (freshly recomputed, not from memory):

| Verdict | Count | Cases |
|---|---|---|
| NOT_AI | 195 | — |
| AI_ROOT_CAUSE | 3 | w076 anubissbe/projecthub-mcp, w080 hulupeep/mcp-ui-probe, w166 astralisone/rive-mcp-server-core |
| AI_CODE_FLAWED | 2 | w020 budibase/budibase (codex/* branch convention), w195 dynatrace-oss/dynatrace-mcp (Copilot co-author) |
| BLOCKED | 2 | w087 anthropics/claude-code (closed-source, no BIC obtainable), w189 guardrails-ai/guardrails (supply-chain publish, no in-repo introducer) |

Unpatched (fix_sha null), 15 cases: w007, w023, w076, w078, w080, w087,
w088, w092, w093, w129, w155, w166, w168, w183, w197.

AI-written AND unpatched: exactly 3 — w076, w080, w166 (all MCP-server
repos, Claude Code generated-with markers on the BIC).

## Files to review

| File | What it is |
|---|---|
| `.ai-slop/state/research-queue/round8/cases-202.jsonl` | Canonical 202 targets; 0-based line index N ↔ worker wNNN. **Trust only this file for class_id** (dispatch headers had typos; workers self-resolved via prompt contract). |
| `.ai-slop/state/research-queue/round8/records-wNNN.jsonl` | Per-case verdict record, exactly one 18-key JSON line each (w000–w201). |
| `.ai-slop/state/research-queue/round8/prompt-wNNN.txt` | The full per-worker instruction contract (method + gate semantics). |
| `.ai-slop/state/research-queue/round8/case-<class_id>.json` | Per-case bundle (advisory text, ranges, references) — the only prior knowledge a worker was allowed. |
| `artifacts/funnel-account-20260817.jsonl` | The ledger; round8 landed under keys `round8_research` / `round8_verdict` / `round8_research_source`, with `status` flipped to the verdict. |
| `artifacts/funnel-account-20260817.jsonl.bak-round8-20260826` | Pre-merge ledger backup (24,124 rows) — diff target for the landing. |
| `scripts/update_ledger_round8_20260826.py` | Landing script (check-only mode available). |
| `scripts/audit_record_gates.py` | Fact gates (identity / 40-hex BIC / fix-or-unpatched). |
| `artifacts/round8-verdict-report-20260826.md` | Human-readable report. |
| `artifacts/round8-landing-report-20260826.json` | Machine-readable landing summary. |
- **Note (2026-08-26 evening)**: after round8 landed, a separate
  `leftover-unanalyzed` lane intake added 5,469 UNANALYZED rows
  (24,124 → 29,593 ledger rows; `existing_status_changed: 0` — pure
  addition, see `artifacts/leftover-unanalyzed-merge-report-20260826.json`).
  Round8's 202 rows are verified byte-identical and untouched.
  Consequences for the commands below:
  - total-row assertions: expect 29,593, not 24,124; class_id-keyed
    checks are unaffected.
  - the full-ledger diff vs `.bak-round8-20260826` now shows 5,873
    changed lines (404 round8 + 5,469×2 intake). For a round8-only
    diff, filter to the 202 class_ids in cases-202.jsonl, or take a
    fresh pre-review copy of the ledger and diff that.

## Reviewer re-run commands (all verified 2026-08-26)

All heavy commands pinned to NUMA node 1 (`numactl --cpunodebind=1 --membind=1`).

1. Record presence + shape + canon + gates, per case:

```bash
cd /home/hanqing/agents/ai-slop
python3 - <<'EOF'
import json, subprocess
RD='.ai-slop/state/research-queue/round8'
cases=[json.loads(l) for l in open(f'{RD}/cases-202.jsonl')]
assert len(cases)==202
EXPECT={'class_id','case_id','repo','advisory_ids','bug_semantics','flaw_origin',
'introducer_sha','introducer_parent','introducer_parent_absent',
'squash_decomposed','decomposed_shas','ai_marker','verdict','fix_sha',
'direct_fix_sha','evidence','reasoning','remaining_gap'}
bad=[]
for i in range(202):
    f=f'{RD}/records-w{i:03d}.jsonl'
    lines=[l for l in open(f).read().splitlines() if l.strip()]
    r=json.loads(lines[0])
    if len(lines)!=1 or set(r.keys())!=EXPECT or r['class_id']!=cases[i]['class_id']:
        bad.append(i); continue
    g=subprocess.run(['python3','scripts/audit_record_gates.py',f],
                     capture_output=True,text=True)
    if g.returncode!=0 or g.stdout.strip()!='ok': bad.append(i)
print('FAIL:',bad if bad else 'none — 202/202 pass')
EOF
```

2. Ledger landing integrity (round8_research byte-identical, status flipped):

```bash
python3 - <<'EOF'
import json
cases=[json.loads(l) for l in open('.ai-slop/state/research-queue/round8/cases-202.jsonl')]
by={json.loads(l)['class_id']: json.loads(l) for l in open('artifacts/funnel-account-20260817.jsonl')}
bad=[]
for i,c in enumerate(cases):
    row=by[c['class_id']]
    rec=json.loads(open(f'.ai-slop/state/research-queue/round8/records-w{i:03d}.jsonl').readline())
    if not (row.get('round8_research')==rec
            and row.get('round8_verdict')==rec['verdict']
            and row['status']==rec['verdict']
            and row.get('round8_research_source')==f'round8/records-w{i:03d}.jsonl'):
        bad.append(i)
print('ledger mismatches:', bad if bad else 'none — 202/202 verified')
print('rows:', len(by), '(expect 24124)')
EOF
```

3. Ledger diff vs backup — exactly 202 rows changed, only the five
   round8_* keys plus status:

```bash
diff <(python3 -c "import json;[print(json.dumps(json.loads(l),sort_keys=True)) for l in open('artifacts/funnel-account-20260817.jsonl.bak-round8-20260826')]" ) \
     <(python3 -c "import json;[print(json.dumps(json.loads(l),sort_keys=True)) for l in open('artifacts/funnel-account-20260817.jsonl')]" ) | grep -c '^[<>]'
# expect 404 changed lines (202 removed + 202 added)
```

4. Landing dry-run (must print summary without writing):

```bash
numactl --cpunodebind=1 --membind=1 python3 scripts/update_ledger_round8_20260826.py --check-only
```

## Where to focus skepticism (highest-value checks)

1. **The 5 AI verdicts** — these flip ledger status to terminal TP and are
   the load-bearing claims. For each, independently verify:
   - `introducer_sha` really is the smallest first-writer (re-run
     `git log -S` / `git log -L` in the clone under
     `.ai-slop/state/repos/<owner>_<repo>/`; watch for rename chains —
     w020 budibase and w195 dynatrace-mcp evidence fields name the paths);
   - the AI marker is on the **BIC itself**, not a fix-side commit
     (fix-side markers are demoted per protocol — 73/202 records contain
     such demotions, e.g. Claude/GPT/Copilot/Cursor co-authors on fixes);
   - w020 is the subtle one: no on-commit marker; the AI attribution
     rests on Budibase's `codex/*` branch convention (PR #18771 merged
     from `codex/fix-public-role-global-grants`; 31 such merges since
     3.38.0). If you reject branch-name inference, this one weakens to
     "unattributable" — decide and document.
2. **The 3 unpatched AI cases** (w076/w080/w166) — verify `fix_sha=null`
   by sweeping all refs of the clone for a fix (`git log --all -S<needles>`
   scoped per path; repo-wide `-S --all` times out on big repos). w166's
   HEAD == BIC (project dead).
3. **w189 guardrails BLOCKED** — this was leader-reclassified from a
   gate-failing NOT_AI: the malicious 0.10.1 was never committed in-repo
   (tags skip it; exhaustive `+version =` enumeration over
   `git log --all -p -- pyproject.toml` shows 0.9.3 → 0.10.0 → 0.10.2).
   Confirm no in-repo introducer exists before accepting BLOCKED.
4. **w087 claude-code BLOCKED** — closed-source CoworkVMService; confirm
   no obtainable BIC before accepting.
5. **Squash decompositions** (58/202 records `squash_decomposed=true`)
   — sample a few, confirm `decomposed_shas` are the real underlying
   writer commits and the squash is not itself recorded as BIC.

## Known soft spots (recorded, not hidden)

- w048/w059 records were leader-takeovers early in the wave (worker
  deaths); w064, w066, w108, w124, w084 were leader-written after
  repeated worker failures. Their records carry full evidence chains.
- Dispatch headers for w173, w174, w176, w177, w178, w180, w183 carried
  wrong class_ids (hand-typed); all records canon-match
  `cases-202.jsonl` — the prompt-file contract resolved them. Any
  record whose class_id does NOT match cases-202.jsonl is a bug; the
  sweep shows none.
- Advisory-vs-repo conflicts (open-webui 0.6.44 tag gap; ghost
  v6.21.1-vs-advisory ancestry; vllm w129 explicit unpatched) were
  resolved by trusting git tag state and recording both facts in
  evidence — review those three records if you want a second opinion on
  that policy.
- Gate semantics: closed verdicts require a 40-hex introducer_sha;
  structurally introducer-less cases (supply-chain, closed-source) must
  land BLOCKED, not NOT_AI. w189 was reclassified accordingly.

## Contact points in ledger

- Review target rows: ledger rows whose `class_id` is in
  `cases-202.jsonl` (202 rows, all previously PARTIALLY_ANALYZED, now
  terminal per verdict).
- After review, corrections should follow the round7-correction pattern:
  `scripts/apply_round7_correction_20260826.py` (rewrite lane record +
  patch ledger keys, backup first).
