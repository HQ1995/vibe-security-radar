# Unmarked-AI-Commit Blind Spot: Gap Quantification and Leads

Mission dir: `autoresearch/herdr-260815-aimarker-blindspot/`
Date: 2026-08-15. Method: local git only (GIT_NO_LAZY_FETCH=1), no GitHub API, no network.

## Headline

1. The census confirms the lead's quantitative hypothesis, but the gap is
   **not uniform**: `openai_gpt_codex` text=5084 vs marked=244 (**20.8x**),
   `cursor` 1332 vs 743 (**1.79x**), `claude_flow` 987 vs 247 (**4.0x**).
   `claude` (1.14x) and `copilot` (0.93x, over-marked) are comparatively well-covered.

2. Two concrete blind-spot mechanisms were isolated mechanically, both of which
   the census's `trailer|author` "marked" definition structurally misses:
   - **Repo-specific attribution conventions** — `Made-with: Cursor`,
     `generated with Claude`, `authored with Codex`, etc. (198 commits across
     12 repos; 170 are `Made-with: Cursor`). These are not `Co-Authored-By`
     trailers, so they are never "marked".
   - **Generic AI markers with no tool name** — `[AI]` / `[AI-assisted]`
     subject suffixes (230 commits, 218 of them in openclaw/openclaw). These
     match none of the census's 5 family regexes, so they are invisible to both
     the `marked` and `text` counts.

3. **32 ranked LEADS** (see `leads.jsonl`), all security-relevant: 9 vulnerable
   ("candidate") commits and 23 security-fix commits. 1 names a specific tool
   (`Made-with: Cursor`, relyra). 31 are generic-`[AI]`, tool unknown. 27 of
   the 32 are new (5 correspond to the 4 already-admitted "generic" cases).

4. **Tool for the 4 generic cases: UNKNOWN.** No citable local source names a
   tool (details below). Not fabricated.

## Method

1. Read the sweep census `ai-commit-census.json` and its generator
   `scripts/build_ai_commit_census.py` to pin the exact semantics of
   `trailer` / `author` / `text` / `marked`.
2. Re-scanned the 66 cloned repos (the census's per-repo set) over the same
   window `2025-05-01..2026-08-16` with three local-only signals:
   - **attribution verb + tool** (`made-with`, `generated with`, `authored
     with`, `built with`, … followed by a tool name),
   - **generic marker** (`[AI]`, `[AI-assisted]`, `[AI-generated]` in subject),
   - a broad "strong AI phrasing" regex (reusing the sweep's `fetch_markers.py`
     pattern) to size the full unmarked pool.
3. Cross-referenced every signal hit against a security-SHA set built from
   `web/src/generated/research-data.json` (candidate_set + fix_authorship
   fixes) plus the sweep `fixrefs.jsonl` fix_refs.
4. Manually pulled full commit bodies for the security-relevant hits to
   separate real AI-attribution from noise (human `Co-authored-by:`, the
   maintainer `RuFlo <ruv@ruv.net>` persona, `github-actions[bot]`, UI-word
   "cursor", `CodeRabbit review feedback`, and a human named "Devin Robison").

## Gap quantification (census, 160,719 commits, 66 repos)

| family | marked | trailer | author | text | text−marked | text/marked |
|---|---:|---:|---:|---:|---:|---:|
| claude | 18,217 | 17,678 | 598 | 20,686 | +2,469 | 1.14x |
| claude_flow | 247 | 247 | 0 | 987 | +740 | 4.00x |
| copilot | 4,526 | 3,384 | 2,538 | 4,204 | −322 | 0.93x |
| cursor | 743 | 732 | 38 | 1,332 | +589 | 1.79x |
| openai_gpt_codex | 244 | 164 | 83 | 5,084 | +4,840 | 20.84x |

Interpretation: `text` is a sensitivity-only proxy (any prose mention of the
keyword). The `text−marked` column is an **upper bound** on the blind spot, not
a count of missed AI commits. `openai_gpt_codex` is inflated by repos that
merely talk about OpenAI/GPT APIs; the 20.8x figure is dominated by prose
noise, not 4,840 missed true positives.

The two stronger, lower-noise signals below are the actionable core of the
blind spot.

### Signal A — attribution-verb conventions (198 commits)

`Made-with: Cursor` / `generated with Claude` / `authored with Codex` … with no
`Co-Authored-By` tool trailer.

| tool | count |
|---|---:|
| cursor | 170 |
| claude | 24 |
| codex | 2 |
| gpt | 1 |
| gemini | 1 |

Top repos: decolua/9router 57, openclaw/openclaw 57, szTheory/relyra 50,
ruvnet/ruflo 8, ruvnet/agentic-flow 8. `Made-with: Cursor` is a stable
convention in at least relyra (50/732 commits) and decolua/9router (57).

### Signal B — generic `[AI]` / `[AI-assisted]` markers (230 commits)

| repo | count |
|---|---:|
| openclaw/openclaw | 218 |
| actualbudget/actual | 9 |
| ChurchCRM/CRM | 1 |
| go-gitea/gitea | 1 |
| mlflow/mlflow | 1 |

These commits self-report AI assistance but name no tool. They match none of the
census family regexes (`claude|anthropic`, `copilot`, `cursor`,
`codex|gpt-|openai`, `claude-flow`), so they are invisible to the census's
`marked` **and** `text` counts. openclaw also has *specific* attributions
(`Made-with: Cursor` ×51, `generated with Claude` ×2, `authored with Codex`
×1, etc.), but the dominant convention is the tool-less `[AI]` suffix.

## Tool identification — the 4 generic cases

All four are openclaw/openclaw. Commit-level evidence (full message + author):

| case | candidate sha | marker in commit | author / co-author |
|---|---|---|---|
| GHSA-2HFG-4FH4-QP7F | e0b8ddc1 | `[AI-assisted]` + `Co-authored-by: Devin Robison <drobison@nvidia.com>` | Michael Appel `<mappel@nvidia.com>` |
| GHSA-2X93-H3HG-2XFP | b75ad800 | `[AI]` | Pavan Kumar Gondhi `<pgondhi@nvidia.com>` |
| GHSA-3FP5-V549-9V66 | 8e41c118 | `[AI]` | Pavan Kumar Gondhi |
| GHSA-J4CX-JVQ7-79VM | 17ceca86 | `[AI]` | Pavan Kumar Gondhi |

Findings:

- The only markers are `[AI]` / `[AI-assisted]` (tool-less) and a **human**
  co-author (`Devin Robison`, NVIDIA). No commit body names Claude, Copilot,
  Cursor, Codex, GPT, or any other tool.
- PR caches are stale: `gh_pr_commits/openclaw/openclaw/pulls/` tops out at
  PR #49025, while these four are PRs #63889, #66040, #87292, #79006. No PR
  body for them exists in `gh_commit_prs`, `gh_pr_commits`, `gh_pr_detail`,
  `gh_commit_prs_complete_v2`, or `gh_commit_resolve`.
- **Conclusion: tool = UNKNOWN.** No citable local source. The `Devin` string
  in two commits is the human "Devin Robison", not the Devin AI agent.

## Leads (see leads.jsonl)

32 leads, all with `{repo, sha, role, signal, tool, excerpt, security_note,
fix_sha, confidence, status="LEAD"}`.

- 9 are **candidate** (vulnerable) commits that a security fix later addressed;
  23 are **fix** commits whose security fix is itself AI-marked.
- 1 lead has a specific tool: `szTheory/relyra` `2aeba972d433`
  (`Made-with: Cursor`) — candidate for GHSA-JV46-XFWM-36J7 / CVE-2026-49454
  (cause `validation_fail_open`), fix `2e456897af31`.
- 31 are generic `[AI]`/`[AI-assisted]`, tool unknown, all in openclaw/openclaw.
  Representative security topics: SSRF guards (zalo/qqbot/webchat/browser),
  exec shell-wrapper injection, secret redaction bypass, TOCTOU in exec
  preflight, approval-auth empty-list bypass, workspace file boundary escapes.

The 4 already-admitted generic cases contribute 5 of the 32 (4 candidates
e0b8ddc1 / b75ad800 / 8e41c118 / 17ceca86, plus the 2HFG fix 3d93174c). The
remaining 27 are new leads.

## Caveats / claim boundaries

- `text` (and `text−marked`) is prose-sensitivity only; it is an upper bound,
  not a missed-commit count. Do not report 4,840 (or any raw gap) as true
  positives.
- "Strong phrasing" still has false positives: UI-word "cursor", `CodeRabbit
  review feedback`, "Claude Code plugin marketplace" (mention, not authorship),
  and a human "Devin Robison". These were excluded from the final lead set by
  reading the actual bodies.
- The 7 census-missing repos have no usable local history (empty clone or none); their gap is
  unquantified.
- All 31 generic leads carry an *explicit* self-report marker (`[AI]`); they are
  "tool-unknown" leads, not "fully unmarked" leads. The only fully-convention
  lead (no `[AI]`, no trailer) is the relyra `Made-with: Cursor` commit.
- No tool was assigned to the 4 generic cases because no local source names one.
- Confidence is uniformly `medium`: signal is explicit and security-relevant,
  but tool attribution (where given) rests on a single repo convention, not a
  formal marker.
