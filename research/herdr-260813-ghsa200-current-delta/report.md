# current-delta worker: 2026-07-23 -> 2026-08-13 first-party GHSA advisory delta

**Verdict first: 0 PASS proposals, 0 NARROW, 33 REJECT, 1 BLOCKED, 294 queue-only UNKNOWN. Status: PARTIAL.**
No completeness claim is made beyond the source enumeration itself. Worker PASS is a proposal only; this worker emits none.

## Contract binding

Terminal artifacts bind leader CONTRACT.md sha256
`cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3` (revised
2026-08-13: AI_INCOMPLETE_REMEDIATION patch-delta rule). This worker emits no
incomplete-remediation rows; the only AI-authored security-adjacent attempt
among adjudicated rows (commonmark 629da942ca, copilot-swe-agent regex anchor)
is audited per the patch-delta rule in its row: the residual quadratic paths
closed by the advisory fix are pre-existing sibling surfaces the AI patch never
touched, so it is not incomplete-remediation causality. Direct/contributor
but-for gating is unchanged.

## What was built

1. **Pagination-complete source delta.** Official `github/advisory-database` full clone
   (alternates read-only against the frozen local cache), tree-to-tree diff between the
   frozen snapshot `39d8887723797efc1804585dd06585c9fd751226` (2026-07-23T12:34:36Z) and
   current HEAD `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86` (2026-08-13T18:29:41Z).
   Independently recomputed github-reviewed delta: **731 added, 148 modified, 0 deleted** -
   exactly equal to the accepted freshness-qa 731-ID manifest (set equality asserted).
   Unreviewed-mirror churn (6085 A / 2511 M / 127 D in `advisories/unreviewed`) is kept
   as routing notes only, never mixed into the reviewed denominator.
2. **Live GraphQL cross-check with cursor conservation.** `securityAdvisories`
   publishedSince=2026-07-23T00:00:00Z (7 pages, 607 nodes) and updatedSince=2026-07-23T12:34:36Z
   (9 pages, 886 nodes), 100 nodes/page, ordered ASC. Every page's request `after` cursor,
   response sha256, `endCursor`, and `hasNextPage` are recorded in `api-manifest.json`;
   `endCursor(page N) == after(page N+1)` for every adjacent pair - conservation PROVEN.
   Raw API pages exist only under `/tmp/ghsa200-worker-clones/current-delta/raw/`; the repo
   holds only the hash manifest. The GraphQL `securityAdvisories` connection covers only
   github-reviewed advisories, consistent with the 731-scale delta.
3. **Deterministic 731-ID routing queue** (`routing-queue.jsonl`, sha256 in `result.json`):
   partition = last hex nibble of SHA256(uppercase GHSA ID); odd -> current-delta (338),
   even -> Grok lane (393); union == 731 exactly, intersection empty (asserted).
4. **Baseline exclusion and collision routing.** All 381 declared baseline public IDs
   (fp211 dispositions + public cases) excluded; 10 odd-partition IDs are baseline-declared
   and are routed out as REJECT/identity-collision rows, never double-counted. Sibling-lane
   ID declarations are recorded per row as routing notes only; the odd/even partition is
   the ownership rule. Intra-delta alias collisions are routed to the first GHSA.
5. **Bounded deep reviews (34 cases).** Each odd-partition case flagged as promising
   (AI keywords in advisory text, or explicit AI trailers within fix-commit +/-2 via recall
   sweep) was driven through vulnerable-repo git history: clone (blobless/shallow, new
   objects under `/home/hanqing/.cache/ghsa200-worker-clones/current-delta` per resource
   directive), fetch of advisory fix SHAs, per-hunk blame at the fix parent to locate the
   introducing commit, full message/trailer inspection, and fix-diff reversal comparison.
6. **Modified-148 review (separate).** 72 modified github-reviewed advisories changed
   aliases, ranges, or withdrawal state in the window; they are emitted as NOTE rows in
   `cases.jsonl` with `counted_as_new_id: false` - identity/alias/range change notes only.

## Outcome of the deep reviews

All 33 adjudicated REJECT rows fail `ai_hunk_gate`: the vulnerable hunk is human-authored.
Every explicit AI marker found sits on a **fix** commit or an unrelated hunk. Representative
counterevidence (full per-row detail in `cases.jsonl`):

| GHSA | Repo | Mechanism | AI marker found | Where it actually sits |
|---|---|---|---|---|
| GHSA-2Q4P-G7HV-5RGV | commonmark | quadratic Markdown DoS | copilot-swe-agent[bot] authored 629da942ca; fixes carry Claude Opus 4.8 trailers | copilot commit ADDED the `^` anchor (mitigation); vulnerable multibyte scan predates (introduced 0.6.0-era) |
| GHSA-PM5P-7W5H-JM5Q | easyappointments | CalDAV SSRF | a1b005161d `Co-Authored-By: Claude Opus 4.6` | XML namespace parsing refactor only; SSRF `get_http_client` introduced by maintainer in 2024 |
| GHSA-HFHX-W8P8-4HC7 | Budibase | uploadUrl SSRF | fix PR branch `codex/fix-vulns-73-ssrf-uploadurl` | Codex authored the FIX; bare fetch introduced by Adria Navarro (Apr 2025, human) |
| GHSA-XRMJ-5G4G-8987 | dynatrace-mcp | workflow template injection | Copilot authored `feat!: remove create_workflow_for_notification` | Copilot authored the REMOVAL; tool introduced by Christian Kreuzberger (Apr 2025) |
| GHSA-W6P7-2FXX-4F44 | pocket-id | refresh-token auth bypass | #1299 `Co-authored-by: Copilot` + `Claude Opus 4.6` | controller prompt-error hunk only; vulnerable service function predates, human-authored |
| GHSA-8XCM-R25X-G524 | undici | retry interceptor desync | `Assisted-by: openai:gpt-5.5` trailer | test-fixture regex parse only; retry-handler authored by Carlos Fuentes (Jul 2025) |
| GHSA-WVPP-8HX9-P66J | GitPython | option guard bypass | `Co-authored-by: GPT 5.6 <codex@openai.com>` | the two FIX commits; vulnerable parsing predates |
| GHSA-W4HW-QCX7-56PR | shescape | CMD paren injection | `Assisted-by: Claude Mythos` | the two FIX commits (#2649/#2651) |
| GHSA-HC4M-Q9JH-XW4J | nono | pack verification fail-open | `Co-Authored-By: Claude Opus 4.6` | line 18 struct touch only; verification authored by Luke Hinds |

**1 BLOCKED**: GHSA-7835-87Q9-RGVV (anthropics/claude-code sandbox escape). The advisory
references no fix commits; the public repo's tag history between v2.1.162 and v2.1.163
exposes only CHANGELOG/feed deltas, so the vulnerable-hunk introducing commit is not
reachable from first-party sources. Fixed released artifact v2.1.163 exists (release_gate
PASS on the fixed side only).

## Seven gates on REJECT rows

identity PASS (first-party GHSA names repo/mechanism/identity); ai_hunk FAIL (introducing
commit human-authored, no explicit AI marker); topology PASS (squash/carrier resolution
done, no authorship transfer); but_for FAIL (removing any AI hunk does not remove the
mechanism); fix_reversal PASS (minimum fix reverses the invariant); release PASS (advisory
carries fixed versions); uniqueness PASS (no baseline mechanism-fingerprint overlap).

## Counting discipline

- 731 = reviewed added identities, QA-agreed; 338 odd = this worker's coverage.
- 148 modified reviewed advisories are reviewed separately, never counted as new IDs.
- Baseline-declared and sibling-declared collisions are routed, not double-counted.
- Zero PASS rows emitted. The worker supports no claim beyond the enumerated delta.
