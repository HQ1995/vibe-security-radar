# Fresh A-M GHSA discovery (owners A-M)

Status: **PARTIAL / HOLD**. Proposed PASS = 0.  
This lane is **not exhaustive** and **not coverage-complete**.

Independence: first-party `github/advisory-database` + repository git/API only. Other worker directories, including fresh-nz and remediation, were not read and are not evidence. Worker PASS is a proposal only.

## Verdict

No case in the deep-reviewed sample closed all seven gates as an atomic AI-authored introduction or material new-surface contributor. This worker proposes **zero** admissions. Preserve 0 PASS.

## Four populations (current advisory-database HEAD)

Rebuild at `github/advisory-database` `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86` (`2026-08-13T18:29:41+00:00`), which is origin/main at rebuild time. Sparse paths: `advisories/github-reviewed/2025` and `2026`. Parsed file count: **12,805** JSON files (2025: 3,688; 2026: 9,117). That parse count is not causal coverage.

| Population | Artifact | Count |
|---|---|---:|
| Full denominator | `inventory-novel-am.jsonl` | **6,094** |
| Routed candidate pool | `routed-candidate-pool.jsonl` | **376** |
| Deep-reviewed sample | `cases.jsonl` | **25** |
| Unresolved coverage | `unresolved-coverage.jsonl` | **6,069** |

Denominator filter: unwithdrawn github-reviewed GHSA, published ≥ 2025-05-01, named GitHub owner/repo, owner initial A–M, not in the fp211/publication exclusion union (429 public IDs / 231 GHSA IDs). GitHub unreviewed advisories and github-reviewed years before 2025 are outside this denominator.

Stage counts at HEAD: unwithdrawn 12,387; published ≥ cutoff 11,240; owner A–M 6,858; excluded 71; novel any-date 6,787; novel since cutoff **6,094**.

## Routing rule (mechanically complete; recall-limited)

Rule file: `routing-rule.json`. Applied to **every** denominator row. Dispositions: `routing-dispositions.jsonl` (6,094).

- Match: case-insensitive substring
- Fields: `repository`, `summary` only
- Keywords: `mcp`, `agent`, `claude`, `cursor`, `copilot`, `gpt`, `llm`, `openai`, `gemini`, `codex`, `jules`, `devin`
- Result: 376 `ROUTE`, 5,718 `NOT_ROUTE`

A `ROUTE` hit is a candidate pointer, never causal proof, never a seven-gate verdict.

**Recall limitations (explicit):** the router does not inspect git history, trailers, bot authors, advisory details, references, or commit subjects. The English substring list misses AI-origin bugs whose repo name and summary omit those tokens, and it over-hits short tokens (`agent`, `gpt`). `NOT_ROUTE` is not negative proof. The deep-reviewed sample is **not** drawn only from `ROUTE` (9 of 25 are `ROUTE`; 16 were cloned outside this router). That second path is **not** mechanically complete.

Because seven-gate review of the denominator and of the 376-row routed pool is unfinished, lane status stays **PARTIAL / HOLD** even though the keyword router itself finished every denominator row.

## Deep-reviewed sample (n=25, non-exhaustive)

| Worker verdict | Rows |
|---|---:|
| PASS | 0 |
| REJECT | 24 |
| UNKNOWN | 1 |
| BLOCKED | 0 |

Unresolved coverage (6,069) is **UNREVIEWED**, not REJECT. 367 of those rows are routed and still unreviewed.

Cloned under `/tmp/ghsa200-worker-clones/fresh-am/clones/` and scored from the advisory JSON plus git:

| Case | Repository | Independent finding |
|---|---|---|
| `GHSA-RM43-82J9-R4MJ` | `dep0we/atomic-agents-stack` | Advisory names `dashboard/serve.py` unvalidated request-path read. Introducing hunk is unmarked root `151bd93d`. Claude trailer is on fix `ec474f45` and allowlisted tabs `08c5f6ab`. `v1.0.0` lacks the fix; `v1.1.0` contains it. `ai_hunk_gate` / `but_for_gate` FAIL. |
| `GHSA-CXGV-HP74-JJ7R` | `chofstede/ansible_jailexec` | Full history: zero AI markers. |
| `GHSA-FH2F-XFXC-Q9CC` | `bablilayoub/openhole` | Unmarked initial release owns the proxy. Cursor trailers are later landing-page commits after `v0.1.2`. |
| `GHSA-F7WF-V2VW-MPCX` | `mkreyman/mcp-memory-keeper` | Advisory: unvalidated `context_import` `filePath`. Claude trailer is on `fix(security): confine context_import` `e0ab521a`, not on 2025-06-17 origin commits. Origin-lane REJECT (AI-assisted fix). |
| `GHSA-8Q49-2H5H-434X` | `agentfront/frontmcp` | Advisory: OpenAPI spec poller SSRF. GitHub PR #266 members that added polling are unmarked `frontegg-david`. |
| `GHSA-6F5R-5672-72J7` | `andrea9293/mcp-documentation-server` | Advisory introduced 1.13.0 unauthenticated `0.0.0.0` bind. Unmarked `34aee75` added `web-server.ts`. |
| `GHSA-XRMJ-5G4G-8987` | `dynatrace-oss/dynatrace-mcp` | Advisory: `create_workflow_for_notification` template injection. Copilot commit **removes** the tool. |
| `GHSA-C5PX-58J2-7FQP` | `eLyiN/gemini-bridge` | Only AI hit is Copilot on Actions Node 24 migration. |
| `GHSA-6XX4-9WP6-65P7` | `manuelmauro/skilo` | 102 commits, zero AI markers. |
| `GHSA-HC4M-Q9JH-XW4J` | `always-further/nono` | Pack-verification fail-open fix is unmarked merge-from-fork. Separate Claude/Copilot commits are other surfaces. |

GitHub commit API plus frozen advisory JSON (no other-worker text):

| Case | First-party mismatch |
|---|---|
| `GHSA-647R-72HF-4VMH` | Advisory: `is_safe_regex_pattern`. Cursor commit files: Java parsing. |
| `GHSA-38C5-483C-4QQP` | Advisory: `Grid::expand_rows` overflow. Copilot commit: `delete_row`/`delete_col`. |
| `GHSA-2CWQ-PWFR-WCW3` | Advisory: DateTime `stackalloc`. Copilot commit: converter exception reporting. |
| `GHSA-XQV9-QR76-HFQ2` | Copilot subject is `fix: prevent command injection` — remediation, not origin. |
| `GHSA-JCQV-2G3V-GM88` | Copilot subject is MySQL handshake panic fix — remediation, not origin. |
| `GHSA-Q8MJ-M7CP-5Q26` | Advisory: `arrayFormat: comma` + `encodeValuesOnly` TypeError. Autofix commit: formatter/`strictNullHandling`. |
| `GHSA-X9VC-9FFQ-P3GJ` | Advisory: missing API key pass-through. Claude commit files: confirmation tokens/`safety.py`. |
| `GHSA-53G2-MVCC-Q9X3` | Advisory: HTMLParser paste XSS. Claude commit files: Karma → web-test-runner. |
| `GHSA-F5P9-J34Q-PWCC` | Advisory: unsynchronized maps. Copilot commit: preflight/C2 contact. |
| `GHSA-2JWF-F4XQ-F24H` | Claude on `harden:` temp-path fix, not an introducing hunk. |
| `GHSA-FJGC-3MJ7-8RG8` | Advisory: `x-proxy-path` XSS. Claude commit: pad history scrub. |
| `GHSA-WVPP-8HX9-P66J` / `GHSA-HMQ2-W58F-27JC` | `Co-authored-by: gpt` on the guard/validation **fixes**. |
| `GHSA-M8WH-29WM-52MV` | `google-labs-jules` authored `Security Fixes 3.12.3`. |

`GHSA-65XW-VW82-R86X` remains **UNKNOWN**: advisory names a `logicalQuery.Select` true-loop; the AI-marked commit is ancestor-axis predicates. No parent-delta was taken in this lane, so but-for is not closed. Subject-line overlap is ROUTE only.

## Hold reason

- Keyword routing finished every denominator row, with recall limitations recorded.
- Seven-gate review did not finish the 6,094-row denominator or the 376-row routed pool (367 routed rows remain UNREVIEWED).
- Status stays PARTIAL/HOLD. Do not treat this worker as coverage-complete.

## Claim boundary

- Countable PASS requires all seven gates on a first-party GHSA case.
- Proposed PASS: **0**.
- REJECT / UNKNOWN preserved in the sample; unresolved coverage is UNREVIEWED, not REJECT.
- Keyword, branding, OSV `introduced`, commit subjects, and ancestry alone are never causal proof.
- No tracked file or other worker directory was edited. Clones only under `/tmp/ghsa200-worker-clones/fresh-am/`.
