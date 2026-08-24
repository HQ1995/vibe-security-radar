# Adjudication report - unr-adj-slice-7.jsonl

## Verdict first

25/25 rows UNKNOWN, 0 countable. No row can be accepted under CONTRACT.md because the
advisory mechanism is not named anywhere accessible, and every candidate AI commit is a
fix/hardening or a non-security behavior change - none introduces a vulnerability.

## Blockers (unchanged after evidence gathering)

1. No advisory description. Every row's packet `summary` is empty. The 25 GHSA IDs are
   unreviewed: absent from the local github-reviewed advisory-database clone (only
   `advisories/github-reviewed/` exists) and OSV returns HTTP 404 (`Vulnerability not found`).
   GitHub API is out of scope, so identity_gate cannot close (mechanism unnamed).
2. Candidate commits are not vulnerability origins. Each candidate diff was fetched via git
   smart-HTTP into /home/hanqing/.cache/ghsa200-sweep-fetch and read directly. All are
   fixes/hardening or non-security changes (see inventory). Removing any of them would more
   plausibly reintroduce a bug than eliminate one, so but_for_gate and ai_hunk_gate cannot
   show an AI-authored vulnerable hunk.

## Candidate commit inventory (all diffs read directly)

| repo | sha (short) | subject | AI marker (verified) | nature |
|---|---|---|---|---|
| ImageMagick/ImageMagick | 89a9974 | chore: remove legacy vsprintf fallback in drawing-wand.c (#8796) | Co-authored-by Claude Sonnet 4.6 <noreply@anthropic.com> | hardening: deletes 8 lines of dead vsprintf fallback |
| ImageMagick/ImageMagick | bd4a469 | Fix double-free in SVG gradientTransform/transform parsing (#8583) | Co-authored-by Claude Opus 4.6 <noreply@anthropic.com> | fix: introduces token_value local to stop DestroyString double-free |
| open5gs/open5gs | c42d7b7 | pfcp: add defensive resets for FAR/URR optional fields in Create handlers | Co-Authored-By Claude Opus 4.6 <noreply@anthropic.com> | hardening: clears presence-driven fields |
| open5gs/open5gs | d28e2f7 | pfcp: use find_or_add in Create FAR/QER/URR handlers and make Remove idempotent | Co-Authored-By Claude Opus 4.6 <noreply@anthropic.com> | fix: corrects PFCP lookup + idempotent Remove |
| zalando/skipper | 2b361b5 | Fix oidc profile review findings | Co-authored-by Copilot <223556219+Copilot@users.noreply.github.com> | fix: validates OIDC profiles, fixes filter ordering |
| zalando/skipper | 5fffa73 | fix: improve bearerinjector logging for missing credentials (#3957) | developed with AI assistance (Claude Code); Co-authored-by Claude Opus 4.6 | fix: logging message only |
| pypa/pip | 8b692a6 | Improve retry configuration for firewall environments | author copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com> | non-security: urllib3 retry/backoff tuning |
| pypa/pip | 4f9820c | Initial plan | author copilot-swe-agent[bot] | empty commit, no diff (not in candidate_set) |

## Per-row gates

All 25 rows carry the same gate matrix: identity_gate=UNKNOWN, ai_hunk_gate=UNKNOWN,
topology_gate=UNKNOWN, but_for_gate=UNKNOWN, fix_reversal_gate=UNKNOWN,
release_gate=UNKNOWN, uniqueness_gate=UNKNOWN. AI identity markers are present (verified)
so the marker sub-condition of ai_hunk_gate is met, but no vulnerable hunk can be identified
because the mechanism is unnamed; therefore the gate as a whole stays UNKNOWN.

| # | ghsa | repo | published | verdict |
|---|---|---|---|---|
| 1 | GHSA-J6F7-9C5W-9R2Q | ImageMagick/ImageMagick | 2026-07-10T15:31:40Z | UNKNOWN |
| 2 | GHSA-26M2-2WHW-VFV9 | ImageMagick/ImageMagick | 2026-07-11T15:30:23Z | UNKNOWN |
| 3 | GHSA-84MH-5FQ7-7FX5 | ImageMagick/ImageMagick | 2026-07-11T15:30:23Z | UNKNOWN |
| 4 | GHSA-84WP-3VXV-VR3V | ImageMagick/ImageMagick | 2026-07-11T15:30:23Z | UNKNOWN |
| 5 | GHSA-X98X-MP75-V6M4 | ImageMagick/ImageMagick | 2026-07-11T15:30:23Z | UNKNOWN |
| 6 | GHSA-FHRJ-R6WW-VQ67 | ImageMagick/ImageMagick | 2026-07-11T15:30:24Z | UNKNOWN |
| 7 | GHSA-VG96-JMXW-665F | ImageMagick/ImageMagick | 2026-07-11T15:30:24Z | UNKNOWN |
| 8 | GHSA-2VFM-V289-H559 | open5gs/open5gs | 2026-07-14T21:32:15Z | UNKNOWN |
| 9 | GHSA-XQMC-7954-658R | ImageMagick/ImageMagick | 2026-07-15T12:32:02Z | UNKNOWN |
| 10 | GHSA-9JV5-JCQ7-XWW3 | ImageMagick/ImageMagick | 2026-07-15T12:32:04Z | UNKNOWN |
| 11 | GHSA-MQFP-WCWX-W65X | ImageMagick/ImageMagick | 2026-07-15T12:32:04Z | UNKNOWN |
| 12 | GHSA-PWCW-F3FJ-7VR2 | ImageMagick/ImageMagick | 2026-07-15T12:32:04Z | UNKNOWN |
| 13 | GHSA-V799-GFW3-G83C | ImageMagick/ImageMagick | 2026-07-15T12:32:04Z | UNKNOWN |
| 14 | GHSA-WH42-3HF2-JJ9P | ImageMagick/ImageMagick | 2026-07-15T12:32:04Z | UNKNOWN |
| 15 | GHSA-24C8-2Q6J-8JW4 | ImageMagick/ImageMagick | 2026-07-15T12:32:05Z | UNKNOWN |
| 16 | GHSA-3MHH-97MG-5HXP | ImageMagick/ImageMagick | 2026-07-15T12:32:05Z | UNKNOWN |
| 17 | GHSA-3VP3-XRM3-4FV5 | ImageMagick/ImageMagick | 2026-07-15T12:32:05Z | UNKNOWN |
| 18 | GHSA-3W79-77CJ-G7X9 | ImageMagick/ImageMagick | 2026-07-15T12:32:05Z | UNKNOWN |
| 19 | GHSA-42MF-MH48-7GJJ | ImageMagick/ImageMagick | 2026-07-15T12:32:05Z | UNKNOWN |
| 20 | GHSA-848J-9X6V-4M2Q | ImageMagick/ImageMagick | 2026-07-15T12:32:05Z | UNKNOWN |
| 21 | GHSA-F6RF-QWCR-G39Q | ImageMagick/ImageMagick | 2026-07-15T12:32:05Z | UNKNOWN |
| 22 | GHSA-MFM8-5JQR-JW5C | ImageMagick/ImageMagick | 2026-07-15T12:32:05Z | UNKNOWN |
| 23 | GHSA-P75F-H73C-3RCP | zalando/skipper | 2026-07-24T00:32:34Z | UNKNOWN |
| 24 | GHSA-C28X-M839-79FQ | ImageMagick/ImageMagick | 2026-07-25T12:31:39Z | UNKNOWN |
| 25 | GHSA-QWM4-QH6W-59XR | pypa/pip | 2026-07-29T21:30:59Z | UNKNOWN |

## Evidence / replay commands

```
sha256sum autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj-slice-7.jsonl
# -> d4bc020c28c5a77358ae4880e0b7fbedb11fb170cb719ac35136279967112d99
git -C /home/hanqing/.cache/ghsa200-sweep-fetch/ImageMagick__ImageMagick show 89a9974e40136a1ecf36b168d9420e0b551d6f97 bd4a469adb6ddb2bdcb856a3d307420268675b09
git -C /home/hanqing/.cache/ghsa200-sweep-fetch/open5gs__open5gs show c42d7b7d9b930b5b421b02c5ad3625129e78ac60 d28e2f7f49f084bed6020440b0b54a784fbce56a
git -C /home/hanqing/.cache/ghsa200-sweep-fetch/zalando__skipper show 2b361b5e2000feb431d15d4c642f57b4a06f08d4 5fffa73fc09845f472c71784bcb6627bd04a16fd
git -C /home/hanqing/.cache/ghsa200-sweep-fetch/pypa__pip show 8b692a61fe3660e3c8ce158916182f58cd304566
# OSV (no result): curl https://api.osv.dev/v1/vulns/GHSA-J6F7-9C5W-9R2Q -> 404 Vulnerability not found
```

## Conclusion

0 new countable cases. This slice does not move the 200-case target; the remaining gap is
external-supply-bound (new advisories with named mechanisms), consistent with STATUS.md.
