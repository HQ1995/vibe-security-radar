# Fresh-strict net-new screen (canonical84 exclusion)

Verdict first: **1 PASS proposal** (`GHSA-FRVJ-C5QP-XJ4W`). **10 REJECT**. **1 NARROW**. **1 UNKNOWN**. Assigned **13**, reviewed **13**, unreviewed **0**. Did not pad to 20. Conservation `13=13+0`. Packet delta **0**. Canonical84 stays **84**. Publication and more-than-200 remain **HOLD**. Worker PASS is a proposal only and does not admit FRVJ.

Live `github/advisory-database` HEAD `39e9e0242ac84dcd010f9fcc23f9e81a448ddc89` is 16 commits ahead of frozen `a42c436870111aa3f221257c9d56126a93173ccc`. GitHub compare: **1** added github-reviewed JSON (`GHSA-29RF-F4VV-PVQ6`), 10 modified reviewed files, 0 removed. Morning `f2c6ab3` to live: same 1 added identity.

## Sources (read-only except owned extracts)

- Contract sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- Canonical84 ledger sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`
- Canonical84 summary sha256 `6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a`
- Frozen advisory HEAD `a42c436870111aa3f221257c9d56126a93173ccc` (2026-08-13T20:57:17Z)
- Live advisory HEAD `39e9e0242ac84dcd010f9fcc23f9e81a448ddc89` via ls-remote plus compare API
- Incomplete-fix screen: 219 first-party 2025-2026 github-reviewed GHSAs not in canonical84; 12 with an AI marker on a listed commit
- Local queues (canvas wave2, directroot batches 1-28, residual-security20 leftover4, additive-guard96) were treated as already mined. This packet did not rubber-stamp other workers' NARROW all-7-PASS rows
- Shared caches were read-only. Owned authorizer clone and 150MB wheels were deleted after hashing

## Method

Freeze up to 20 strong candidates without padding. Selection: the only post-freeze new reviewed identity, plus the 12 incomplete-fix GHSAs whose listed commits carry an explicit AI marker. Eligible classes: AI root, necessary contributor, AI-created surface, or AI incomplete rem under the exact residual path. KEEP requires all seven gates PASS. AI on a closer is not origin. Sibling-path residuals fail patch-delta. Unclosed gates stay UNKNOWN. failing_gates lists FAIL only.

## PASS proposal

Worker PASS is a proposal. Leader plus independent hostile red-team must accept before the count moves.

### GHSA-FRVJ-C5QP-XJ4W (open-webui/open-webui)

All seven gates plus patch-delta PASS at incomplete-remediation scope.

- Identity: github-reviewed GHSA-frvj-c5qp-xj4w, CVE-2026-59221, not withdrawn. PyPI open-webui introduced 0.9.6, fixed 0.10.0. First-party repo advisory exists.
- AI hunk: 0354775917 single-parent (parent d4030a8a). Co-authored-by Claude Opus 4.7. First-parent replaces a single `unquote(path)` with a `range(8)` decode-until-stable loop in `_sanitize_proxy_path`.
- Topology: atomic. 0354775917 is an ancestor of closer 05098d25. No member-to-carrier transfer.
- But-for / patch-delta: the AI commit is an explicit rewrite of the terminal-proxy path guard. GHSA-FRVJ names 9x encoding that exits the cap still encoded. Residual is inside that cap, not an untouched sibling route.
- Fix reversal: 05098d25 inserts `if unquote(decoded) != decoded: return None` on the same loop.
- Release: PyPI open-webui 0.9.6 wheel sha256 `ce5fdd1b8acf2b823c87417242dea4e6686d6130a98e766954ec6f04e5e146ed`, uploaded 2026-06-01, not yanked; `_sanitize_proxy_path` equals `git show 0354775917`; no fail-closed. PyPI 0.10.0 wheel sha256 `4bd16d93dc86e955939bb1b40409a7013108708bf4cba61871e0ff5112802460`, uploaded 2026-06-29, not yanked; function equals `git show 05098d25`. GitHub releases v0.9.6 (2026-06-01T21:57:03Z) and v0.10.0 (2026-06-29T19:17:48Z) are not draft and not prerelease.
- Uniqueness: absent from canonical84. Distinct from uncounted GHSA-R2WG (original missing/single-decode sanitizer). Directroot batch24 REJECT used an unrelated ranked SVG commit and is not this scope.

## Non-KEEP (12)

| ID | Verdict | Class | Minimal counterexample |
| --- | --- | --- | --- |
| GHSA-29RF-F4VV-PVQ6 | REJECT | human + RC only | Lakhan OAuth linking; tags are 2.4.0-rc.* |
| GHSA-RHFG-J8JQ-7V2H | REJECT | sibling path | Human fetchWithSsrFGuard; closer wires other channels |
| GHSA-CVQ5-HHX3-F99P | REJECT | Copilot test | Copilot on configmap_test.go; listed SHA is the closer |
| GHSA-3775-99MW-8RP4 | REJECT | human original | 534f4ff Ville podSpecPatch closer; AI is later |
| GHSA-7VF8-2CR6-54MF | REJECT | AI closer | Claude merge-from-fork removes driver log field |
| GHSA-8WCJ-MFRC-JX5Q | REJECT | AI closer | Claude drop builder SA token; sibling of counted QF5V |
| GHSA-F4VV-55C2-5789 | REJECT | AI closer | Claude stop guest JWT; body names this GHSA |
| GHSA-FP43-VJ7G-PG92 | REJECT | AI closer | Claude harden names GHSA-fp43; VP6R is a different EL/CDN bug |
| GHSA-P5RM-JG5C-8C77 | NARROW | same-first-tag | v1.34.0 first contains both percent-decode and NUL closer |
| GHSA-XW57-23P8-9WC5 | REJECT | allowlist expansion | PT-008 expands localhost permit-list; zero tags |
| GHSA-48P8-G2FX-3WWM | UNKNOWN | merge-from-fork | Claude squash trailer; private-fork members unrecovered |
| GHSA-WVPP-8HX9-P66J | REJECT | uniqueness | Residual of counted GHSA-R9MR |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. Only leader-reviewed rows with all seven gates PASS enter that bound after independent hostile red-team. This packet did not edit canonical84 and does not support a greater-than-200 claim.

Owned temporary clones, fetched advisory pages, wheel JSON, and terminals snippets were removed. Canonical ledger was not edited. No commit or push.
