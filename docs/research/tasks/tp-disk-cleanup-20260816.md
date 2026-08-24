# Disk cleanup (2026-08-16, /home at 98%)

## Goal

Free space safely. Strictly bounded deletion: only the allowlist below.
Everything else is read-only analysis.

## Allowlist (delete ONLY these, nothing else)

- /home/hanqing/agents/ai-slop/.ai-slop/checkpoints/
- /home/hanqing/agents/ai-slop/.ai-slop/cache/
- /home/hanqing/agents/ai-slop/.ai-slop/logs/
- /home/hanqing/agents/ai-slop/.ai-slop/tmp/
- /home/hanqing/agents/ai-slop/.ai-slop/test-runtime/
- /home/hanqing/agents/ai-slop/web/.next/
- /tmp/*.patch and /tmp/*.log only

## Protect (NEVER touch)

- /home/hanqing/agents/ai-slop/.ai-slop/state/  (all mining artifacts)
- /home/hanqing/agents/ai-slop/.ai-slop/repos/
- /home/hanqing/agents/ai-slop/artifacts/
- /home/hanqing/agents/ai-slop/research/  (11.7GB manifested pools)
- /home/hanqing/agents/ai-slop/web/ (except web/.next)
- /home/hanqing/.cache/  (advisory-database, cvelistV5 used by publish)
- anything not in the allowlist

## Procedure

1. du -sh each allowlist dir; report sizes first.
2. Delete allowlist contents (find DIR -mindepth 1 -delete is fine; never
   delete the top-level .ai-slop or its state/repos subdirs).
3. Report: before/after sizes, freed total, and df -h /home.

Do not clean anything else, do not touch git, do not stop the dev server.
Reply with the freed-total line and the df line.
