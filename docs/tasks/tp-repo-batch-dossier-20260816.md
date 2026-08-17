# TP repo-batch dossier protocol (2026-08-16, no GitHub API)

## Goal

Study each advisory completely, using LOCAL git clones and OSV only.
No api.github.com calls. Ever.

## Inputs

- .ai-slop/state/laneB2/repo-batches/batch-<N>-repos.json (repo order)
- .ai-slop/state/laneB2/repo-batches/batch-<N>-cases.json (cases with case_id,
  repo, fix_sha, fixed_version, hint)

## Clone pool (bounded, delete as you go)

- Pool dir: .ai-slop/repos/batch-<N>/
- For each repo in repo_order: git clone --filter=blob:none
  https://github.com/<repo>.git .ai-slop/repos/batch-<N>/<repo>
- Total pool cap 100G. After finishing a repo's cases, DELETE the clone:
  rm -rf .ai-slop/repos/batch-<N>/<repo>

## Per case (local walk)

1. Advisory text: curl -sS -m 20 'https://api.osv.dev/v1/vulns/<case_id>'
   (mixed-case GHSA). Read mechanism, fixed version, affected ranges.
2. fix_sha is given. In the local clone: git show <fix_sha> --stat and
   git show <fix_sha> to see the mechanism files and the fix lines.
3. Find the introducer: git log --format='%H %an %ae %ad %s' -- <mechanism-file>
   before the fix; find the commit that ADDED the flawed lines
   (git blame <fix_sha>^ -- <file> or git log -S '<flawed-line>').
4. AI check on the introducer commit: git show <sha> --format=full for
   trailers/author/bot markers. Marker must sit on the commit itself.
5. Verdict: B1_AI_FAULT / B2_NOT_AI / B3_BLOCKED (same dossier fields).

## Output

- .ai-slop/state/laneB2/repo-batches/batch-<N>-results.jsonl — one JSON per case,
  same order: case_id, repo, mechanism, source, guard, sink,
  introduced_by{sha,author,date,ai,marker}, contributors[],
  fixed_by{sha,complete}, ai_role, verdict, evidence, reasoning

## Acceptance

- Every B1 has introduced_by.sha + marker + line refs.
- Every B2 names the human introducer with evidence.
- No api.github.com calls; OSV only for advisory text.
