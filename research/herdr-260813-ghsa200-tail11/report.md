# Tail-11 official reviewed micro-delta

Status: **COMPLETE**. Proposed seven-gate `PASS` admissions: **0**.

This lane compared the official `github/advisory-database` github-reviewed identity set at accepted freshness HEAD `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86` against newer official HEAD `b5d749dd70bad2ed373a2524f3fdb34044512ea9`. Path-count delta was **derived**, not assumed: 34,377 reviewed JSON files at the accepted HEAD and 34,388 at the newer HEAD, so **+11**. Conservation holds: 11 added, 0 deleted, 2 modified, 0 renamed, 0 duplicate path IDs.

Every added reviewed GHSA identity has exactly one terminal `cases.jsonl` row. Leader-declared IDs and aliases (212 `case_id` values from fp211 `public_cases.jsonl`) do not overlap this added set. One added identity is withdrawn and is a duplicate of another added identity; it is excluded from counting. The remaining ten were deep-reviewed against first-party GitHub advisory objects where they exist, plus repository Git and tag history in lane-owned blobless clones.

Worker `PASS` is only a proposal. This shard proposes none. Fresh-nz artifacts were not read as evidence and were not modified. Sibling worker conclusions were not used as evidence. No canonical ledger, tracked publication file, or shared checkout was edited, committed, pushed, cleaned, or reset. No `/tmp` clones.

## Freeze

| Item | Value |
|------|--------|
| Official repository | https://github.com/github/advisory-database.git |
| Lane clone | `/home/hanqing/.cache/ghsa200-worker-clones/tail11/advisory-database` |
| Object reference (untouched) | `/home/hanqing/.cache/cve-analyzer/advisory-database` at `39d8887723797efc1804585dd06585c9fd751226` |
| Accepted freshness HEAD | `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86` 2026-08-13T18:29:41+00:00 `Publish Advisories` |
| Newer official HEAD | `b5d749dd70bad2ed373a2524f3fdb34044512ea9` 2026-08-13T20:54:24+00:00 `Publish Advisories` |
| Ancestry | accepted HEAD is an ancestor of the newer HEAD |
| Commits in range | 3 (`8a58b9bb` Advisory Database Sync; `af9f7068` and `b5d749dd` Publish Advisories) |
| Source heads bound | the two SHAs above only. Identity lists come from `git ls-tree` / `git diff` at those commits. |

Reviewed JSON files:

- Accepted: **34,377** unique GHSA path IDs (2025: 3,688; 2026: 9,117)
- Newer: **34,388** unique GHSA path IDs (2025: 3,688; 2026: 9,128)
- Added: **11**, deleted: **0**, modified: **2**, renamed: **0**
- 34,377 + 11 - 0 = 34,388 (path count conserved)
- Unique IDs: 34,377 retained + 11 added - 0 removed = 34,388 (identity conserved)

Added IDs:

`GHSA-463R-5M89-4XFR`, `GHSA-5HXG-R395-FQXX`, `GHSA-6XVF-9742-48W2`, `GHSA-87X5-VMC3-756J`, `GHSA-92M7-4FPW-2WXM`, `GHSA-G28P-6MCC-V4RV`, `GHSA-HJCP-JMPX-G3QM`, `GHSA-M42H-3232-VPV3`, `GHSA-M6WV-WH8G-64XC`, `GHSA-MW82-XCG6-GX79`, `GHSA-Q5H6-FCF5-49G9`

Modified IDs (not added identities; frozen only): `GHSA-X445-F3H2-J279`, `GHSA-XMF8-CVQR-RFGJ` (Auth.js reference/`database_specific`/`modified` updates; aliases and withdrawn unchanged).

Unreviewed JSON counts at the two HEADs: 323,274 to 323,296. Unreviewed files were not consumed for identity.

## Exclusions

- Leader-declared IDs/aliases: **0** of the 11 added IDs appear in the 212 fp211 `case_id` set or their aliases.
- Withdrawn: **GHSA-Q5H6-FCF5-49G9** (`withdrawn` 2026-08-13T20:44:55Z).
- Duplicates: the same withdrawn JSON states it is a duplicate of **GHSA-M42H-3232-VPV3** and points at `CVE-2026-12243`. It is excluded, not counted beside M42H.

## Verdicts

`PASS` 0, `REJECT` 11, `UNKNOWN` 0, `BLOCKED` 0, `NARROW` 0. Proposed admissions: **0**.

First-party GitHub repository advisories exist only for vLLM `GHSA-87X5-VMC3-756J` and NLTK `GHSA-M42H-3232-VPV3`. The other eight added IDs 404 on `repos/{owner}/{repo}/security-advisories/{ghsa}` and lack a `github.com/{owner}/{repo}/security/advisories/GHSA-*` reference.

### First-party identities (origin still fails)

**vLLM `GHSA-87X5-VMC3-756J` / `CVE-2026-73559`.** Identity closes: published first-party advisory on `vllm-project/vllm`. Mechanism: `/v1/completions` `prompt` as `list[str]` or `list[list[int]]` fans out one engine generator per element.

- First-party `vulnerable_version_range` is `>=0.19.0, <=0.26.0` while `patched_versions` is `>= 0.26.0`. Release containment fails: 0.26.0 is listed as both vulnerable and patched.
- Git independently shows fix squash `675f4295` is an ancestor of tag `v0.26.0` and is not an ancestor of `v0.25.0`. Tag `v0.26.0` contains `VLLM_MAX_COMPLETION_PROMPTS`; `v0.25.0` does not. That does not repair the first-party contradiction.
- `v0.18.0` already has `CompletionRequest.prompt` as `list[str] | list[list[int]] | str`, so the list surface is not introduced at 0.19.0. File split `4c1c501a` (Chauncey, PR `#32369`, 2026-01-15) has no AI trailer and is an ancestor of `v0.18.0`.
- Closer `675f4295` and PR `#47845` members have no AI trailer. `REJECT`.

**NLTK `GHSA-M42H-3232-VPV3` / `CVE-2026-12243`.** Identity closes. Mechanism: `url2pathname` decodes `%2e%2e` after a literal `../` regex.

- OSV `introduced` is `0`. Tag `3.9.3` already has `_UNSAFE_NO_PROTOCOL_RE` plus `url2pathname` after the check.
- Git tag `3.9.4` (tagger 2026-03-24) contains `pathsec.py` from merge `aec4fce` but still lacks `unquote` before that regex, so the percent-encoding hole remains. Tag `v3.10.0` adds `from urllib.parse import unquote` and checks the decoded name. That matches first-party `patched_versions >=3.10.0`.
- AI markers on PR `#3522` are fix-side (Claude Opus 4.6 on natgillin review commits; Copilot Autofix on ekaf `d065f9d4`; subject "Add more Copilot suggestions"). Merge `aec4fce` is Steven Bird, unmarked.
- Prior incomplete sandbox PR `#3480` (hyperps) has no AI marker. `REJECT` (old bug; AI is fixer/review).

### Excluded duplicate

**`GHSA-Q5H6-FCF5-49G9`.** Withdrawn duplicate of M42H / `CVE-2026-12243`. Terminal row only. Not counted.

### Not first-party (identity fails; git still reviewed)

**Home Assistant `GHSA-5HXG-R395-FQXX` / `CVE-2026-64825`.** Repo GHSA 404. OSV `introduced` 0. Claude Opus 4.7 trailers sit on closer squash `567fe858` and release-branch cherry `7e178efe` (`#172368`). Claude Opus 4.6 sits on prior `#167211` squash `2a855113`, which validated multipart filenames and did not cover inner `backup.json` `name`. Tag `2026.5.0` contains `#167211` and not `#172368`; tag `2026.6.0` contains cherry `7e178efe` (dev squash `567fe858` is not an ancestor of that tag). That is AI-as-fixer of a pre-existing second input, and identity is not first-party. `REJECT`.

**Jenkins (five GHSAs).** `GHSA-463R-5M89-4XFR`, `GHSA-92M7-4FPW-2WXM`, `GHSA-G28P-6MCC-V4RV`, `GHSA-M6WV-WH8G-64XC`, `GHSA-MW82-XCG6-GX79`. Repo GHSA 404. OSV `introduced` 0. Closers are unmarked `SECURITY-*` commits by Kevin-CB or Daniel Beck. Weekly SHAs are ancestors of `jenkins-2.568`; LTS SHAs are ancestors of `jenkins-2.555.3`. `REJECT`.

**migration-planner `GHSA-6XVF-9742-48W2` / `CVE-2026-53469`.** Repo GHSA 404. Bulk DELETE `/api/v1/sources` exists in 2024 Avishay Traeger API commits. Closer `db4c7857` (Aviel Segev, unmarked) is an ancestor of `v0.13.5`. `REJECT`.

**HttpComponents `GHSA-HJCP-JMPX-G3QM` / `CVE-2026-64607`.** Repo GHSA 404. OSV `introduced` `5.0-alpha1`. Closers are unmarked Oleg Kalnichevski commits. `rel/v5.6.3` contains `55733f4121f7` and does not contain parallel `ebac9512f555`. `REJECT`.

## What was not treated as origin evidence

PR branding, CodeRabbit review HTML, Copilot suggestion subjects on security closers, Claude trailers on fix/review members, OSV `introduced` alone, advisory keywords, and other workers' PASS/REJECT text. Unreviewed GitHub JSON was not an identity source.

## Contract revision (cbd04ef2)

Terminal artifacts bind to leader `CONTRACT.md` sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.

`AI_INCOMPLETE_REMEDIATION` uses the patch-delta rule: rollback may reopen a broader old vulnerability and that is not, by itself, a failure. The row counts only if an AI security attempt adds or rewrites a boundary, a released residual bypass in that same boundary is covered by a first-party advisory, and a later same-mechanism closure directly amends that AI boundary. Unrelated untouched sibling holes do not count. Direct/contributor but-for is unchanged.

Applied only to incomplete-remediation candidates:

- `GHSA-5HXG-R395-FQXX`: #167211 is an AI filename-guard attempt released in `2026.5.0`. The advisory residual is inner `backup.json` name, a pre-existing sibling input. Later #172368 does not amend the filename guard. Patch-delta not countable. Origin/fixer but-for on the closer is unchanged. Identity still fails.
- `GHSA-M42H-3232-VPV3`: Claude/Copilot markers rewrite pathsec sandbox members; the first-party advisory names percent-encoded `../` via `url2pathname` in `data.py`, which already exists at `3.9.3` without those trailers. `v3.10.0` unquote amends that older regex, not the AI pathsec boundary. Patch-delta not countable. Origin/fixer but-for is unchanged.

No other added identity is an incomplete-remediation row. No row is labeled countable `AI_INCOMPLETE_REMEDIATION`. Proposed admissions remain 0.

## Final claim boundary

- Derived path-count delta: **+11**. Conservation holds.
- Proposed seven-gate admissions: **0**.
- CVE aliases are not extra cases.
- Withdrawn duplicate Q5H6 is excluded.
- Leader verification is required before any later admission. This worker does not mutate the canonical ledger.

## Out of this denominator: next_tail_head

Observed clone `HEAD` `a42c436870111aa3f221257c9d56126a93173ccc` (`2026-08-13T20:57:17+00:00`, `Publish GHSA-p28v-f755-9qrg`) is recorded only as `next_tail_head`. It is not a source head for this freeze, not in the +11/0/2 identity lists, and not a case in `cases.jsonl`. This artifact does not silently move the source head to that commit.

After this tail's terminal validation (`6e8a7ca9..b5d749dd` = +11/0/2), a separate follow-up audited `b5d749dd..a42c436` in `autoresearch/herdr-260813-ghsa200-tail11/next_tail/`. That range adds one reviewed identity, `GHSA-P28V-F755-9QRG` (`CVE-2026-73654`). The follow-up verdict is `REJECT` (first-party identity closes; introducing `JSONHeroPath.set` hunk is unmarked). That identity remains outside this denominator.
