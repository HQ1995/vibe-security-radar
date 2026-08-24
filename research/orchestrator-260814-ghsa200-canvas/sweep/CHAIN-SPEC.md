# Chain-tracing worker spec: who introduced the original vulnerability in an IR chain

Owner: your own output dir. Proposal worker; leader replays every PASS.

## Method - agentic first, git as evidence lookup only

Do NOT treat git blame or SZZ ancestry walking as the oracle. They mis-attribute
renames/squashes/refactors and time out on large repos. Your job is to UNDERSTAND
the mechanism, then find which change created it. Order:

1. Read the advisory (local advisory-database) and the fix diff to name the exact
   mechanism: which code, what invariant, what the fix changes.
2. Read the vulnerable code at the pre-fix state (git show fix^:<file>) and reason
   about which step in its history could have created the flaw (new surface,
   removed check, changed parsing, copied code).
3. Look up candidate history with bounded git commands only:
   - git log -S'<unique vulnerable snippet>' --oneline -- <file> (pickaxe),
   - git show <candidate> to READ the candidate's actual diff and judge whether it
     creates the mechanism (not a rename/refactor/whitespace hit),
   - git log --oneline -500 fix -- <file> for context.
   Deepen at most 500 commits. Every git command timeout 30s.
4. Decide BIC_AI YES only when you have READ the BIC's diff and it demonstrably
   introduces the vulnerable mechanism AND carries an explicit AI identity.
   Otherwise BIC_AI=NO or UNKNOWN. A blame attribution you could not verify by
   reading the diff is UNKNOWN, never evidence.
5. If the BIC is itself a security fix that was later bypassed (chain hop), repeat
   one hop back with the same agentic method until a non-security or non-AI origin.

## Task

For each row in autoresearch/orchestrator-260814-ghsa200-canvas/sweep/chain-backward-6.jsonl
(ghsa, repo, fix, summary), trace the introduction of the ORIGINAL vulnerability
as above.

The repos live in /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>.

## Outputs (English only)

- result.json: per-row chain: BIC sha, author, AI identity evidence, chain depth,
  evidence commands run, verdict BIC_AI YES/NO/UNKNOWN.
- cases.jsonl: one row per advisory, gates filled only if BIC_AI=YES.
- report.md: full chain narrative per row.

## Hard constraints

- Only your owned dir writable; never edit ledgers/web/scripts; never commit/push;
  no credentials; no GitHub API; never convert missing evidence into FAIL.
