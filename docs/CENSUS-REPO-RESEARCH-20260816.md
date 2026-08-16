# Census repo-level AI-commit queue (2026-08-16)

Research-only. Computed from local official snapshots. No GitHub API. No tracked files modified.

## 0. Usable-class definition (computed)

Official census window is `2025-05-01T00:00:00+00:00` .. `2026-08-09T23:59:59.999999+00:00`
(`build_current_official_census.py`: `SINCE <= published < 2026-08-10`).

| set | count | how |
|---|---:|---|
| alias classes | 84,798 | `alias_classes.jsonl` / `summary.json` |
| WITHDRAWN in `states` | 382 | computed |
| REJECTED in `states` | 363 | computed |
| both | 7 | computed |
| usable = no WITHDRAWN/REJECTED | **84,060** | 84,798 − 382 − 363 + 7 |
| subjects in window | 159,714 | all `subjects.jsonl` rows |

That matches the task’s 84,060. Date-missing records are a separate file
(`blocked_missing_date.jsonl`, 5,789) and are not alias-classes.

## 1. File / field map — where repositories live

**They do not live in the census files.**

### `alias_classes.jsonl` (84,798)

Fields only: `analysis_subject`, `class_id`, `member_ids`, `published`, `sources`, `states`.
No repo, no package, no URL.

### `subjects.jsonl` (159,714)

Fields only: `id`, `aliases`, `date_known`, `in_window`, `lane`, `modified`, `path`, `published`, `source`, `state`.

`path` is the snapshot member path, not a code repo. `lane` is
`cve_list_v5` / `unreviewed` / `github-reviewed`.

### Other census files

- `blocked_missing_date.jsonl`: same subject schema, `date_known=false`.
- `summary.json`: counts + source-archive pins. No repos.
- `new_vs_2026-07-24*.json`: enrichment-queue delta vs 2026-07-24, not a repo index.

### Where a repo actually is (local, no API)

| source | local artifact | repo-bearing fields |
|---|---|---|
| GHSA | `current-source-snapshots/advisory-database-71ca7b6916b1fb164168b4bb6050d2676e5a8d6a.tar.gz` | `references[].url` (`PACKAGE`, commit, sometimes bare `github.com/owner/repo`); rare `affected[].ranges[].repo` when `type=GIT` |
| CVE List V5 | `cvelistV5-11ff8d6bde24923d36a0f18758aa2ffaaac220d6.tar.gz` | `containers.*.references[].url` only. `affected[]` is vendor/product/CPE, not a git repo |
| NVD | `current-source-snapshots/nvd/nvdcve-2.0-2025.json.gz` + `2026` | reference URLs. **Added 0 repos / 0 classes** on top of CVE+GHSA |
| OSV | `current-source-snapshots/osv/*.zip` (local) | `affected.ranges[type=GIT].repo` + commit/package URLs. Allowed here for field semantics / extra identities |

GHSA `affected[].package` is `{ecosystem, name}` (e.g. Packagist `moodle/moodle`). That is **not** a clone target.

Existing parsers already in-tree (reuse, do not rewrite):

- `cve_analyzer.git_url.parse_commit_url` / `parse_repo_url`
- `scripts/cohort/commit_urls.py:parse_foreign_commit_url` (cgit/gitweb/gitiles/kernel-stable)
- `scripts/cohort/advisories.py:commit_reference_rows_from_record`
- `cve_analyzer.ghsa_local`: first GIT range repo, else first `PACKAGE` URL

**Do we need live OSV/GHSA HTTP?** No. Snapshots are enough to attach a repo to a class when one is named. Live OSV is not required for field semantics.

**Unresolvable without a later source:** 44,979 / 84,060 usable classes have **no** parseable repo in official CVE+GHSA (and NVD added none). Those stay `UNSCANNABLE` until a later snapshot names a repo. OSV attached repos to 32,037 classes and added 422 identities; the class-level union of (official ∪ OSV) was **not** recomputed.

## 2. Distinct repositories for the 84,060 (computed)

Parser: `parse_commit_url` ∪ `parse_foreign_commit_url` ∪ `parse_repo_url`, lowercased `host/owner/repo`.

Two buckets:

- **any**: every parseable hosting URL (includes issue/PR/tree/security-advisory pages that still parse as a repo).
- **precise**: commit URL, foreign commit URL, GHSA `PACKAGE` URL, or OSV/GHSA `GIT` range `repo`. This is the clone queue.

### Official CVE + GHSA only

| metric | count | status |
|---|---:|---|
| usable classes | 84,060 | computed |
| classes with ≥1 any-repo | 39,081 | computed |
| classes with exactly 1 any-repo | 35,978 | computed |
| classes with >1 any-repo | 3,103 | computed |
| classes with 0 official repo | **44,979** | computed |
| classes with ≥1 precise-repo | 24,319 | computed |
| distinct any-repos | 9,123 | computed |
| distinct precise-repos | 4,646 | computed |
| of which github.com (any) | 8,907 | computed |
| of which github.com (precise) | 4,493 | computed |
| NVD increment | 0 classes, 0 repos | computed |

Top any-hosts (official): github.com 8907, gitlab.com 45, android.googlesource.com 30, gerrit.wikimedia.org 23, gitlab.freedesktop.org 17, gitlab.gnome.org 16.

### Official ∪ local OSV

| metric | count | status |
|---|---:|---|
| OSV records that map into usable classes | 56,550 | computed |
| of those with a parseable repo | 54,078 | computed |
| OSV classes with any-repo | 32,037 | computed (OSV-only; overlap with 39,081 not unioned) |
| OSV-only new any-repos | 422 | computed |
| OSV-only new precise-repos | 1,504 | computed (mostly `GIT.zip`) |
| **union distinct any-repos** | **9,545** | computed |
| **union distinct precise-repos** | **6,150** | computed |
| union github.com any | 9,301 | computed |
| union github.com precise | 5,946 | computed |

Largest OSV increment: `GIT.zip` (+392 any / +1,469 precise). Android.zip +23. Ecosystem zips (npm/PyPI/Go/…) mostly duplicate official GHSA PACKAGE/commit URLs.

**Answer to Q2:** there is no single repo field in the census. After resolving local snapshots:

- **6,150** distinct precise/cloneable repos (claim-grade queue)
- **9,545** distinct any-parseable repos (high-recall, noisier)
- **44,979** usable classes remain officially repo-less

## 3. Already covered by our pool vs new (computed)

Task’s “10,083 advisories, 5,824 repos” is **not** “all rows in the two files”. Recomputed:

| pool definition | advisories | repos | status |
|---|---:|---:|---|
| `fixrefs.jsonl` raw | 17,757 | 5,414 raw / 5,371 casefold | computed |
| `nofix-advisories.jsonl` raw | 4,119 | 1,144 | computed |
| raw union | 21,876 | 5,870 raw / **5,824 casefold** | computed |
| dated fixrefs ∪ all nofix (`build_ledger_summary.py` advisories) | **10,083** | 2,442 dated repos | computed |
| casefold(all fixrefs ∪ all nofix) = task’s 5,824 | 21,876 | **5,824** | computed |

Exact script behavior: dated fixrefs (5,964 ids) ∪ all nofix (4,119 ids) = **10,083** advisories. Repo set in that script adds every nofix repo and every **dated** fixref repo → **2,442**. The **5,824** figure is the casefolded union of **all** fixrefs + all nofix, i.e. the whole historical first-party GHSA-reviewed fixref inventory plus nofix, not the in-window advisory denominator.

Use 5,824 as “repos we have already touched in the GHSA200 sweep files”, not as “in-window official coverage”.

Compare census github identities (`owner/repo`, lowercased) to that 5,824-set:

| census set | in pool 5,824 | new vs pool | status |
|---|---:|---:|---|
| official any github (8,907) | 2,653 | 6,254 | computed |
| official precise github (4,493) | 2,565 | 1,928 | computed |
| union any github (9,301) | 2,699 | **6,602** | computed |
| union precise github (5,946) | 2,660 | **3,286** | computed |

3,171 pool repos are **not** in the official-census github set (historical / out-of-window / not in these 84,060 classes).

In-window pool repos only: 2,442. Almost all of those (2,422) sit inside the official any-github set.

## 4. Existing repo-level AI scan artifacts (reuse, do not rescan)

The 66-repo canvas census is **not** the largest scan.

| artifact | repos | what it is | reuse? |
|---|---:|---|---|
| `autoresearch/orchestrator-260809-0539/current-ai-scan/` | **8,909 scanned / 8,455 complete / 454 incomplete / 2,992 HAS_AI** | Source v3 `cohort_ai_commit_scan`, `since=2025-05-01`, 434,422 AI commits | **primary reuse** |
| same dir `commits.jsonl` | 434,422 rows | per-commit tools/signals/shas | reuse as HAS_AI evidence |
| `CURRENT_OSV_FIX_INDEX.json` | 2,992 AI repos indexed; 2,367 matched | OSV fixes intersecting the AI-repo set | reuse for fix join, not a scan |
| `current-unified-fix-index/` | 1,506 repos / 13,138 classes with a public fix-ref | **filtered to the 2,992 AI repos** | not a census-wide repo list |
| `sweep/ai-commit-census.json` | 66 scanned (7 missing/failed), 23,977 marked | the “66-repo census” | already have; do not treat as the queue |
| `sweep/fetch_markers.py` + `fix-marker-scan.json` | fix-commit only | blobless fetch of advisory fix SHAs | reuse for fix-commit AI flag, not whole-repo |
| `herdr-260813-ghsa200-commitfirst-gn/` | 580 listed / 578 scanned / 358 HAS_AI | routing-only marker scan | subset |
| `herdr-260813-ghsa200-commitfirst-af/repo-scan-status.jsonl` | 923 / 548 HAS_AI / 4 not SCANED | same | subset |
| `orchestrator-260810-0613/ai-scan*` | 4 repos | residual | ignore |
| `explicit-id-ai-commit-matches.jsonl` | 2,262 commit/class hits | AI commit message names a CVE/GHSA | not a repo census |
| clone pools | 6,117 + 6,174 + scan v2 clones | `~/.cache/cve-analyzer/repos`, `~/.cache/ghsa200-sweep-fetch`, `.ai-slop/cache/cve-analyzer/repos` | reuse before cloning |

Overlap of **union any-repos (9,545)** with current-ai-scan:

| | count | status |
|---|---:|---|
| already scanned | 7,840 | computed |
| already complete | 7,391 | computed |
| already incomplete (ProvenanceError) | 449 | computed |
| not in the 8,909 at all | 1,705 | computed |
| **remaining vs complete (any)** | **2,154** | computed |
| precise union already complete | 5,739 / 6,150 | computed |
| **remaining vs complete (precise)** | **411** | computed |

Do not rescan the 7,391 complete identities. Re-try the 449 incomplete only if you need a closed NO_AI_COMMIT; they are currently UNSCANNABLE.

## 5. Pipeline (local clone + git log, no GitHub API)

### Queue

1. Start from `repos-union-precise.txt` (6,150) unless you explicitly want the noisier any-URL set (9,545).
2. Subtract `current-ai-scan/summary.json` `complete_repository_identities`.
3. Remaining scan queue:
   - **411** precise repos (recommended)
   - **2,154** if using any-URL identities
4. Classes with no repo: emit `UNSCANNABLE` / `NO_REPO` and stop. Do not call OSV.dev or api.github.com to invent one.

### Bounded clone (node 1 only)

Confirm free node-1 memory before a batch (`numactl -H`). `--membind=1` will swap onto disk if node 1 is exhausted; do not spill onto node 0.

```bash
# pin the worker
numactl --cpunodebind=1 --membind=1 bash

REPO=github.com/owner/name          # or host/group/name
KEY=${REPO//\//__}
DIR=/tmp/ai-repo-scan-pool/$KEY    # delete after verdict

# prefer an existing clone
#   ~/.cache/cve-analyzer/repos/*
#   /home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos/v2_*
#   ~/.cache/ghsa200-sweep-fetch/owner__name

git --no-optional-locks clone --filter=blob:none --bare \
    "https://${REPO}.git" "$DIR"
# non-github: use the host’s git URL (googlesource, gitlab, cgit, …)
# never api.github.com
```

After the verdict: `rm -rf "$DIR"` if it is a disposable pool clone (not a shared cache dir).

### Scan command

Production path (already implemented; reuse):

```bash
uv run --project cve-analyzer python scripts/cohort_scan_ai_commits.py \
    --repo "$REPO"
# internally: git log --all --since=2025-05-01 --grep=<Source v3 ERE> + --author=<bot ERE>
# then cve_analyzer.provenance.scan_repo_ai_commit_index / source_matcher
```

Lazy one-shot equivalent if you only need a routing prefilter (not a production HAS_AI):

```bash
git --no-optional-locks --git-dir="$DIR" log --all --since=2025-05-01 \
    --regexp-ignore-case --extended-regexp \
    --format='%H%x1f%an%x1f%ae%x1f%s%n%b%x1e' \
    --grep='co-authored-by:|assisted-by:|generated-by:|generated with|claude code|github copilot|cursor agent|openai.codex|noreply@anthropic\.com|noreply@openai\.com|users\.noreply\.github\.com'
```

Then run the **Source v3 matcher**, not the grep, for the verdict. Incremental.md is explicit: a human `Co-authored-by:` is not an AI marker.

### Marker list (production = `cve-analyzer/src/cve_analyzer/source_policy.py`)

**Vendor-exclusive emails** (display name ignored):
`noreply@anthropic.com`, `claude@anthropic.com`, `claude-bot@bun.sh`,
`cursoragent@cursor.com`, `codex@openai.com`, `noreply@openai.com`,
`copilot@github.com`, `aider@aider.dev`, `aider@aider.chat`,
`openhands@all-hands.dev`, `opencode@sst.dev`, `roomote@roocode.com`,
`agent@warp.dev`, `oz-agent@warp.dev`, `vibe@mistral.ai`,
`qwen-coder@alibabacloud.com`.

**GitHub bot logins** (any `<id>+<login>@users.noreply.github.com`):
`copilot`, `copilot-swe-agent`, `github-advanced-security`, `github-code-quality`,
`claude`, `anthropic-code-agent`, `cursor`, `devin-ai-integration`,
`gemini-code-assist`, `google-labs-jules`, `labs-code-app`, `roomote`,
`chatgpt-codex-connector`, `openai-code-agent`, `codex`, `openhands-agent`,
`qoderai`, `oz-by-warp`.

**Registered Co-authored-by name+email pairs:** Claude / anthropic-code-agent[bot],
Cursor / Cursor Agent, aider, Copilot, Codex / openai-code-agent[bot],
Mistral Vibe, Qwen-Coder / Qwen Code, OpenWork, Oz / Oz Agent
(see `COAUTHOR_IDENTITIES`; emails as in that table).

**Bare Co-authored-by name (no email):** `Atlassian Rovo Dev` only.

**Attribution verbs × tool aliases** (complete unquoted line):
verbs `Generated|Created|Written|Assisted`;
aliases `Claude Code`, `Claude`, `GitHub Copilot`, `Copilot`, `Cursor`,
`Aider`, `OpenAI Codex`, `Codex`, `Gemini CLI`, `OpenCode`, `Roo Code`,
`Mistral Vibe`, `Pi`, `Kilo Code`, `v0`, `Goose`.

**Exact footers:**
- `Generated with [Claude Code](https://claude.ai/code)`
- `🤖 Generated with [Claude Code](https://claude.ai/code)`
- `Changes auto-committed by Conductor`

**Model-qualified:** `Assisted-by: <harness>:<family>` where family ∈
claude/opus/sonnet/haiku, gpt/codex/o3/o4, gemini, qwen, mistral/devstral, kimi.

**Sweep-only loose regex** (`fetch_markers.py`, routing, high FP — do not use as HAS_AI):

```
co-authored-by:|assisted-by:|generated with (claude|codex|copilot|cursor)|claude code|claude opus|claude sonnet|github copilot|\bcursor\b|\bdevin\b|\bjules\b|\brovo\b|qwen code|openwork|\bqoder\b|coderabbit|\bkimi\b|\bgrok\b|\btrae\b|ai-assisted|ai-generated
```

`[AI]` / generic “AI-generated” prose is **not** in Source v3 production policy.

### Verdict

| verdict | rule |
|---|---|
| `HAS_AI_COMMIT` | Source v3 matcher hits ≥1 commit in `--all --since=2025-05-01` on a complete refs walk |
| `NO_AI_COMMIT` | clone+log complete, matcher hits 0. Never convert a failed clone or `ProvenanceError` into this |
| `UNSCANNABLE` | no repo on the class; clone/fetch/log failed; shallow/incomplete refs; 449 current-ai-scan incompletes until retried |

Reuse current-ai-scan: 2,992 already `HAS_AI_COMMIT`, 8,455−2,992 complete-with-zero are already `NO_AI_COMMIT` for this window, 454 `UNSCANNABLE`.

## Working files (gitignored, this research)

- `.ai-slop/state/census-research/repo-extract2.json`
- `.ai-slop/state/census-research/osv-extract.json`
- `.ai-slop/state/census-research/repos-union-precise.txt` (6,150)
- `.ai-slop/state/census-research/repos-union-any.txt` (9,545)
- `.ai-slop/state/census-research/queue-precise-not-complete.txt` (411)
- `.ai-slop/state/census-research/queue-union-not-complete.txt` (2,154)

