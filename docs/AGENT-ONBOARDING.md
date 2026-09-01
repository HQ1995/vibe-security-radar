# Agent Onboarding

Short path for a new audit agent to start producing verified ledger verdicts
and publish-safe data. Read this before touching any code or data.

Compacts the three legacy slash-commands (independent audit / false-negative
audit / deep verify) that were moved out of .claude/commands/ into this
document.

## 0. The one-sentence job

Independently decide whether AI-written code introduced a security
vulnerability (opened the vulnerable path, or left a fix incomplete), then
record the judgment in the ledger so the site can publish it.

Three hard rules:

1. **No mechanical scanning.** Understand the vulnerability's root cause and
   full lifecycle before judging the AI role. git blame on the fix file is
   a starting point, never the answer.
2. **AI fixing a bug != AI causing it.** An AI co-author on the *fix* commit
   means AI helped remediate; it is not evidence the bug is AI-introduced.
3. **Vulnerability first, AI second.** Establish the real vuln and its BIC
   before looking at AI signals. Never search for an AI-marked commit and
   then call it the BIC.

## 1. Map of the repo (what each piece is for)

| Path | What it is | Writable by |
|------|-----------|-------------|
| artifacts/funnel-account-20260817.jsonl | Deterministic GitHub recovery export of the canonical ledger | leader only (ledger_store.py export) |
| artifacts/ledger-history/ | Immutable audit history (assessments, versions, change-sets) | sync tooling |
| scripts/ledger_store.py | Neon ledger access: assessment-add, finalize, export, connect | leader only |
| scripts/audit_lock.py | Per-CVE claim lock (claim/release/check/list) | any audit agent |
| scripts/audit_queue.py | Picks next CVE per queue (--fp/--fn/--stats) | any audit agent |
| scripts/publish_tp_ledger.py | Builds web/src/generated/research-data.json DB-first | leader only, via this script |
| scripts/site_preflight.py | Publication gates before web build | leader only |
| web/src/generated/research-data.json | Generated site data | NEVER by hand |
| research/ | Lane dumps. Evidence files (result.json, report.md, cases.jsonl, manifests) tracked; heavy dumps ignored | owning lane |
| docs/AUDIT-PROTOCOL.md | How a case gets judged (principles) | - |
| docs/DATA-SCHEMA.md | Field semantics, ledger schema | - |
| docs/AGENT-OWNERSHIP.md | File ownership + conflict rules | - |

## 2. Pick a target and lock it

    cd ~/agents/ai-slop/scripts

    # Pick from a queue (or pass an explicit CVE/GHSA id)
    python3 audit_queue.py            # default queue
    python3 audit_queue.py --fn       # false-negative queue
    python3 audit_queue.py --stats    # queue health

    # Claim before starting (parallel safety). Claims auto-expire after 2h.
    python3 audit_lock.py claim <CVE-ID> --worker "$(hostname)-$$"

If the claim fails, the target is held by another session - pick the next one.
**On any early exit (error, timeout, missing data), release the claim before
stopping.**

## 3. Independent investigation (do this FIRST, before any cached result)

Read only the fix commits / repo URL from the cache - not the full verdict,
which would anchor your reasoning to the pipeline's conclusion:

    jq '{fix_commits: [.fix_commits[] | {sha, repo_url}]}' \
      ~/.cache/cve-analyzer/results/<CVE-ID>.json

If this fails (missing file, null fix commits), release the claim and stop.

1. **Understand the vuln.** git show <fix_sha> in
   ~/.cache/cve-analyzer/repos/<owner>_<repo>/. Identify the vulnerable
   construct, the secure replacement, and the vuln type (injection, auth
   bypass, traversal, ...). Check every fix commit - pick the one with the
   *actual* security fix, not changelogs/tests.
2. **Trace the vulnerable code to its origin.** Find the commit that FIRST
   wrote the insecure pattern. Watch for moves, renames, refactors, and
   extractions - a blamed commit that just moved existing code is not the
   origin. On squash merges, decompose and find which sub-commit wrote the
   vulnerable lines.
3. **Check AI on the origin commit.** git show --format=fuller <sha> and
   look for Co-Authored-By trailers (Claude/Copilot/...), bot emails
   (noreply@anthropic.com, Copilot@users.noreply.github.com), AI markers in
   the message. Judge the AI role from signals on that BIC only.
4. **Verify causality.** Confirming the origin commit actually CREATED the
   vulnerability: git show <sha>^:<file> | grep <pattern>. If the pattern
   existed before, the commit is not the true origin - keep tracing.

## 4. Compare with the pipeline

Read the code first, then the cached result:

- cve-analyzer/src/cve_analyzer/models.py - data structures/verdicts
- cve-analyzer/src/cve_analyzer/scoring.py - confidence computation
- cat ~/.cache/cve-analyzer/results/<CVE-ID>.json - the pipeline's conclusion

Compare your origin commit + AI signal + verdict with the pipeline's. When
they differ, classify the discrepancy (e.g. shallow-blame, wrong-fix,
signal-on-fix, cosmetic-blame, scoring-bug, stale-cache). Do not force a
fixed taxonomy - describe what actually happened.

## 5. Record the judgment

Findings are validated by scripts/audit_record_gates.py. Verdict classes and
field semantics are in docs/DATA-SCHEMA.md. The ledger write path is
leader-only via ledger_store.py; as an audit agent you hand the final record
to the leader rather than writing the ledger directly.

Key verdict distinctions (from AUDIT-PROTOCOL.md):

- **NOT_AI** = a real vulnerability with human authorship.
- **FALSE_POSITIVE** = the advisory itself is wrong or withdrawn. Check the
  CVE.org record before closing; withdrawn_at in the GitHub advisory is not
  authoritative.
- **EVIDENCE_GAP** = missing lineage/history; never infer AI absence from a
  structurally valid record.

## 6. False-negative audit (when asked)

Investigate CVEs the pipeline found "no AI signal" on, to catch:
missing_pattern (AI tool not in detection patterns), format_variant
(co-author trailer format not matched), squash_loss (signal on sub-commit
lost in squash), pr_only_signal / bot_review (AI via PR metadata).

Same claim/free protocol as Section 2, with --fn queue. Before saving each
finding, triage improvement value: is it a first occurrence or a pattern?
What's the blast radius? Which file would change? Assign FIX / OBSERVE /
WONTFIX.

## 7. Deep verification (when asked)

Re-verify confirmed TPs with a single-model deep verifier. Prereqs:

    export LITELLM_API_BASE="http://localhost:8000/v1"
    export CVE_LLM_MODEL_OVERRIDE=gpt-5.6-luna
    export CVE_LLM_STRICT_MODEL=1
    export CVE_REASONING_EFFORT=max

Then, from cve-analyzer/ (global flags before the subcommand):

    CVE_LLM_MODEL_OVERRIDE=gpt-5.6-luna CVE_LLM_STRICT_MODEL=1 \
      CVE_REASONING_EFFORT=max \
      uv run cve-analyzer --verbose analyze <CVE-ID> \
        --llm-verify --force-verify --verify-model gpt-5.6-luna

Do NOT use --no-cache - the pipeline cache is cheap; the verifier has its own
API cache. --force-verify marks existing verdicts stale first so a failed
pass cannot publish an earlier verdict. Run 5-10 concurrent batches.

## 8. Hand-off checklist

Before you stop:

- [ ] Release the claim (python3 scripts/audit_lock.py release <id>)
- [ ] Finding saved via save_finding to ~/.cache/cve-analyzer/audit/findings.json
- [ ] Final record handed to the leader (for ledger_store.py assessment-add/finalize)
- [ ] Lane evidence files committed if it was a research lane (result.json,
      report.md, cases.jsonl, manifest) - never force-add a dump dir
