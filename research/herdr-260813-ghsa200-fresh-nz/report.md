# Fresh official GHSA discovery (N-Z and digit/other owners)

Status: **COMPLETE**. Proposed seven-gate `PASS` admissions: **0**.

Leader checkpoint: this shard froze the current official `github/advisory-database` revision and the full N-Z first-party denominator from that revision. Keyword and AI-marker co-occurrence is routing only. No `PASS` without an exact mechanism-creating AI hunk, but-for/material contribution, same-mechanism reversal, and released vulnerable/fixed artifacts. Fresh-am and remediation in-progress proposals were not read and are not evidence.

Lane: current first-party GitHub repository advisories whose owner initial is N-Z or a digit/other character. Identities must be absent from the fp211 declared-ID freeze and the effective publication corpus. Security-remediation and reintroduction contribution cases are excluded. Worker `PASS` is only a proposal; this shard proposes none.

Owned output: `autoresearch/herdr-260813-ghsa200-fresh-nz/`. Mixed clone paths: existing active data remains at `/tmp/ghsa200-worker-clones/fresh-nz/` and was not moved. All new clones and large objects go under `/home/hanqing/.cache/ghsa200-worker-clones/fresh-nz/`. The shared checkout was left dirty. No tracked file, ledger, script, doc, or `web/data` path was edited. Nothing was committed, pushed, cleaned, or reset.

## Verdict

No novel first-party GHSA in this owner slice closed all seven gates with an exact AI marker on the mechanism-creating atomic hunk, but-for/material contribution, same-mechanism minimum fix reversal, vulnerable and fixed released artifacts, and uniqueness.

The 624 novel N-Z first-party advisories whose official JSON contains AI-product keywords were **not** promoted. Keywords and referenced-commit AI markers are a routing queue. They are not identity, origin, topology, but-for, reversal, or release proof.

The strongest origin near-miss remains Pydantic AI `GHSA-H7P7-W5GC-XJ3W` / `CVE-2026-54249`. Identity, uniqueness, same-mechanism reversal, and released containment close. The landed squash `272c92ac35b2ad81b6c9eddbda425b27de4b0762` carries `Co-authored-by: Claude Opus 4.6`, but that trailer belongs to a later review-feedback member that does not touch the Vercel adapter. The adapter hunk that reconstructs `UploadedFile` from client `providerMetadata` is unmarked member `b6866b45bc42a63c29b5051640588c408e88f211` (`fixing vercel`, author mattbrandman). Treating the squash trailer as origin would transfer authorship across commits. `REJECT`.

CVE aliases are not counted separately.

## Frozen advisory-database revision

Independent fetch of `origin/main` into `/tmp/ghsa200-worker-clones/fresh-nz/advisory-database` (blobless clone; object reference to the untouched cache at `39d8887723797efc1804585dd06585c9fd751226` only). That clone stays on `/tmp`. Root `/tmp` is tight, so later clones and large objects use `/home/hanqing/.cache/ghsa200-worker-clones/fresh-nz`. The `/tmp` tree was not relocated.

| Field | Value |
|---|---|
| Repository | `https://github.com/github/advisory-database.git` |
| Frozen HEAD | `b5d749dd70bad2ed373a2524f3fdb34044512ea9` |
| Committer date | `2026-08-13T20:54:24+00:00` |
| Subject | Publish Advisories |
| Equals origin/main at fetch | yes |
| github-reviewed JSON (all years, ls-tree) | 34,388 |
| github-reviewed 2025 JSON | 3,688 |
| github-reviewed 2026 JSON | 9,128 |

Sparse worktree is 2025 and 2026 reviewed JSON only. Unreviewed JSON was not consumed.

First-party rule: a reviewed advisory is first-party if and only if a `references` URL matches `https://github.com/{owner}/{repo}/security/advisories/GHSA-*`. Owner lane: first character of that owner is a digit, a non-letter, or in N-Z.

## Full N-Z denominator (campaign window published on or after 2025-05-01)

Manifests (SHA-256 in `advisory_db_revision.json`):

- `nz-denominator.jsonl`: 4,482 N-Z first-party window rows (active and withdrawn)
- `nz-denominator-ids.txt`: the same 4,482 GHSA IDs, sorted
- `nz-denominator-novel-ids.txt`: 4,190 novel active IDs
- `nz-keyword-routing.jsonl`: 624 novel keyword hits, labeled routing-only

| Slice | Count |
|---:|---:|
| Campaign-window reviewed JSON | 11,635 |
| Campaign-window first-party | 9,025 |
| N-Z first-party window | 4,482 |
| Of those, withdrawn | 212 |
| N-Z first-party window active | 4,270 |
| Already in the ID freeze | 80 |
| Novel active N-Z first-party | 4,190 |
| Of those, OpenClaw | 537 |
| Novel non-OpenClaw | 3,653 |
| Novel with AI-keyword routing | 624 |
| Keyword hits promoted to PASS | 0 |

The ID freeze remains `freeze.json` SHA-256 `4260206f309c6cba55eef8369e3e84d5b86813f1c81d4fabc4c2fac91fa7824d` (476 unique public IDs, 104 repositories). Every reviewed case ID below is absent from that freeze.

## Gate outcomes for reviewed identities

Reviewed machine-readable rows: 29. `PASS` 0, `REJECT` 27, `UNKNOWN` 1, `BLOCKED` 1, `NARROW` 0.

### Near-miss (identity and releases close; origin fails)

**Pydantic AI `GHSA-H7P7-W5GC-XJ3W` / `CVE-2026-54249`.** First-party repository advisory, published, not withdrawn. Mechanism: `VercelAIAdapter` rebuilds `UploadedFile` from client-controlled `providerMetadata` and the provider fetches that reference with server credentials. OSV and the advisory give affected `>=1.65.0,<1.106.0` (and the 2.x beta pair `>=2.0.0b1,<2.0.0b6`).

- PR `#3942` lands as single-parent squash `272c92ac35b2ad81b6c9eddbda425b27de4b0762` (parent `0b0ec325b651ece0f0087f8a059a91a262a5efdc`) with trailers for Douwe Maan, David, and Claude Opus 4.6.
- The squash delta adds `UploadedFile` and the adapter reconstruction named by the advisory.
- Tag `v1.65.0` (`9af531667fc2b5f87b8f61145f8b14f97217a62a`) is ahead of the squash by 2 commits, merge-base equal to the squash. Tag `v1.106.0` (`1b42945de65b2816fed3cffa371671a2ac759241`) is ahead of fix merge `ed31bdd64e11ce1475916a398ee3312791ed2d38` by 3. Tag `v1.105.0` does not contain the fix.
- Minimum semantic fix member `d2cb3ae524578f795a90e2ef543b8b46b05efcc6` (PR `#5772`) drops client `UploadedFile` unless `preserve_file_data=True`. That is the same invariant.

Origin fails: 72 PR members. Adapter hunk is unmarked `b6866b45bc42a63c29b5051640588c408e88f211`. The only non-merge Claude member, `12508f1550e73b6ae78764212e51390c065b5025`, edits `messages.py` only. `ai_hunk_gate` FAIL, `topology_gate` FAIL, `but_for_gate` FAIL. `REJECT`.

### Revision-new identity (old bug)

**NLTK `GHSA-M42H-3232-VPV3` / `CVE-2026-12243`.** Present in frozen HEAD and not in the earlier GitHub API crawl. Official JSON: ECOSYSTEM introduced `0`, fixed `3.10.0`. Mechanism is percent-encoded `..` bypassing `nltk.data` path checks via `url2pathname` after validation. Fix merge `aec4fce1b84ad725b8975f7365b23a4f626572a9` (PR `#3522`) is contained in tag `v3.10.0`. One PR member subject mentions Copilot suggestions; that is fix-side review. `REJECT`.

### Human origins with later AI fixes

- **lara-mcp `GHSA-XJ5P-8H7G-76M7` / `CVE-2025-53832`.** Human origin `20957f40b3cae4a3f37206eb874b686c285ebaa5` adds `import_tmx` `exec`/`curl`. Copilot-marked `e534ef690adf390e4ac862a200b2a83f6cf45944` is not an ancestor of vulnerable tag `v0.0.11` and is an ancestor of patched `v0.0.12`. `REJECT`.
- **stata-mcp `GHSA-49M4-VP58-WGC9` / `CVE-2026-55071`.** Unmarked SongTan origin `0001cec1135824bc77dca6fe116ac6b06a2c8c4d`; unmarked fix `1641e93a71e7d1600adb2c7ab1041370d43347d4`. `REJECT`.
- **stata-mcp `GHSA-4P62-HQP5-G644` / `CVE-2026-47708`.** Unmarked origin `0b5dbfda0cb0843090d9b3bc193a771b1544c275`; unmarked fix `e6f945941ae0c7cf5e74a428e0b3dc82b396382f`. `REJECT`.

### Fix-side AI (not origin)

Referenced-commit scan hits whose subjects are security fixes or permission-gate backports, all `REJECT` for origin:

SIPSorcery `GHSA-JWJP-4649-V8JP` and `GHSA-28GM-JRMW-XX93`; Smarty `GHSA-F6WF-28G6-769X`; league/commonmark `GHSA-2Q4P-G7HV-5RGV` and `GHSA-29PJ-957V-52MC`; pyca/cryptography `GHSA-G6CJ-PR64-35W5`; FastMCP `GHSA-VV7Q-7JX5-F767`; Vitest `GHSA-5XRQ-8626-4RWP` (Codex `allowWrite`/`allowExec` backport); vLLM pooling hardening `GHSA-Q8GQ-377P-JQ3R`; vm2 `GHSA-248R-7H7Q-CR24`; NLTK `GHSA-GFWX-W7GR-FVH7`; RustFS `GHSA-FC6G-2GCP-2QRQ` and `GHSA-GW2X-Q739-QHCR`; n8n Chat Trigger `GHSA-MVH4-2CM2-6HPG`.

n8n `GHSA-JH8H-6C9Q-7GMW`, `GHSA-2P9H-RQJW-GM92`, `GHSA-VPCF-GVG4-6QWR`, and `GHSA-75G8-RV7V-32F7` reference Claude-coauthored weekly bundle/backport carriers. Bundles are not atomic origin hunks. `REJECT`.

### Remediation / residual (delegated out of this lane)

Preserved as `REJECT` here, not counted, and not taken from the remediation worker:

- Pimcore `GHSA-2MHJ-FHVG-V428` / `CVE-2026-55072`: advisory text is an incomplete regex fix after `dbe1d131e4`. Copilot is on the follow-up.
- zeptoclaw `GHSA-HHJV-JQ77-CMVX`: Claude-marked blocklist-bypass patch on a freeze repository.
- ouroboros `GHSA-JV2H-4P9V-WF5W` / `CVE-2026-66065`: first-party summary is an incomplete fix of `CVE-2026-47211`.
- Vitest `GHSA-P63J-VCC4-9VMV` / `CVE-2026-73653`: Browser Mode commands bypass the later `allowWrite` gate.

### UNKNOWN and BLOCKED

- **vLLM `GHSA-87X5-VMC3-756J` / `CVE-2026-73559`.** First-party identity exists. No recovered AI origin for prompt-list fan-out. `patched_versions` `>= 0.26.0` contradicts `vulnerable_version_range` `>=0.19.0, <=0.26.0`. `release_gate` FAIL, origin `UNKNOWN`.
- **OpenClaw coverage `BLOCKED`.** 537 novel first-party OpenClaw GHSAs are in the frozen denominator. The repository is already in the ID freeze. This origin-discovery lane did not re-adjudicate that mass. Representative row: `GHSA-P73F-W79W-JQR5`. Product-name keyword hits are routing only.

## What was not treated as origin evidence

PR branding, AI product names in advisory prose, MCP/agent repository names, Devin or Copilot review comments, GitHub Actions auto-review, weekly bundle coauthors, fix-side Claude/Copilot/Codex trailers, and keyword/AI-marker co-occurrence. Unreleased commits were not counted. Old-bug refactors, import carriers, and introduced-0 bugs were rejected when recovered. Other workers' proposals were not used.

## Coverage boundary

Official reviewed coverage is the frozen advisory-database HEAD above. The full N-Z first-party window list is the denominator. Origin replay remains a priority slice plus the revision-new NLTK identity. Remaining novel non-OpenClaw N-Z first-party GHSAs were not individually blamed. The unreviewed GitHub stream is out of scope for first-party identity.

## Final claim boundary

- Proposed seven-gate admissions: **0**.
- CVE aliases are not extra cases.
- Incomplete remediations were preserved and not converted into origin `PASS`.
- Leader verification is required before any later admission. This worker does not mutate the canonical ledger.
