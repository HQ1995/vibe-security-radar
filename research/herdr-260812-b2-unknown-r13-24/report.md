# Batch 2 unknown recovery: ranks 13–24

## Outcome

This is a bounded recommendation audit of exactly the twelve frozen inventory rows whose `resolvability_rank` is 13 through 24 inclusive. It is not a new systems-candidate search. The audit found no publication-grade AI-authorship PASS. Ranks 13–18 remain UNKNOWN because each has a real public security fix and released containment, but the observed AI signals do not bind to the exact vulnerable origin and same security mechanism. Ranks 19–24 are rejected from the current publication corpus on affirmative hard-gate failures, without turning residual authorship uncertainty into a human-only claim.

The operative claim rule is conjunctive: a PASS needs (1) affirmative public AI-authorship/assistance evidence bound to the candidate, (2) exact vulnerable-origin/fix lineage, (3) the same security mechanism, (4) first-party advisory identity, and (5) released containment. Routing, ancestry, shared files, tests, source recovery, and release carriers are diagnostic only. Absence of an AI marker is not proof of human-only authorship.

## Scope and snapshot boundary

- Started: `2026-08-12T12:47:51-04:00`.
- Checkout snapshot: branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`, 405 `git status --short` entries. The checkout was intentionally dirty; no existing path was changed.
- Sole inventory: `autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl`, SHA-256 `5167b86efb2d6e3d218c41da120c7302f99049b9c588e8fd00896051d50355ca`.
- Canonical compact serialization of only ranks 13–24: SHA-256 `0c9bc82fc9178a0ad050d0438c1df3d58b3749a3132f6a81053e95f855c92266`.
- Frozen supporting inputs:
  - `snapshot/audit-adjudications.jsonl`: `47536f4e426b51ff2fa012cb9a250ea49ed21d51a7cb1a1f369ecd2c13d1ba9a`.
  - `snapshot/refresh-exact-adjudications.jsonl`: `ca026877faf923625df0c88afb9fa97b482123c0f7a1d37b966350cc9513dff8`.
  - `snapshot/audit-handoff.md`: `da93dbc191996505ea79fc2a71f8892c9c7e6cdf14a6053530d73f13f750969c`.
  - `audit-review/official-records.jsonl`: `19fcd3298046962919cd25afb332f8c54093922f1a3b3f3e3991ea0cd49f1090`.
  - `audit-review/prioritized-ai-edges.jsonl`: `a3f57b7be768a039ba2a9d7d6f5b1de49affff3d7bbe90f45be4f7bc1932a50e`.
  - Selected frozen adjudication records for ranks 13–18: SHA-256 `43ad1e41bdf483449c22c8f538817a400e4a31720c196346ab31e955caa92a32`.
- Read-only local repository snapshots used for ranks 13–18:
  - `openclaw/openclaw` HEAD `86075ed73811b8f4fcd6acd7869b191e17188873`.
  - `open-webui/open-webui` HEAD `1ac3dd4a893e13803e7b889611303c4a7a5cc470`.
  - `ash-project/ash` HEAD `3856ff201eec4dafc2283ba60f93d4bafdd49899`.
- Rank 19–24 supporting snapshot: `background-r19-24.md`, SHA-256 `670c5b380427cae66de57fa37fb445e8831c67c1fa5c2b514d6b06cdb697d23e`; its frozen CVEList revision is `e07ca6f300c9ca36f9120b0d5149a5edf6227b1f` and its observed repository HEADs are LosslessCut `3b9a59c288bf6e11076b583c932cfa48ddab3b02`, Badaso `1ee86e4c5eed33c23b46163a0359e41f3fa357b7`, mall `d9501e97a78eb2bb0ae8eaa273eeb1cfc7c5d386`, Perl `e6dfa909e10757e7906b67c06533058d0f40cb1c`, and GStreamer `598383c413681b426e0f2c93a2813f1a6b40565e`.
- First-party advisory API reads for ranks 13–18 succeeded at approximately `2026-08-12T12:51–12:53-04:00`. A later attempt to hash the GitHub responses hit unauthenticated HTTP 403 rate limiting; no empty-response digest is treated as evidence. The frozen official-record hashes above, commit-object snapshots, exact URLs, and returned advisory fields define the reproducible boundary.
- Explicit exclusions: ranks 1–12 and 25+, every ledger component outside these twelve inventory rows, product-name-only signals, and any broad candidate rediscovery.

## Status vocabulary

- `RESOLVED_PASS`: all five publication gates close.
- `RESOLVED_REJECT`: affirmative evidence disproves or fatally breaks the proposed AI-to-vulnerability causal edge; it does not mean “no public AI marker found.”
- `STILL_BLOCKED`: a required source object, exact fix/history, or first-party identity could not be recovered.
- `STILL_UNKNOWN`: the security fix/lineage may be known, but AI causality remains neither proven nor disproven.
- `NARROW` is retained as a mechanism/severity qualifier, not silently promoted to PASS or REJECT.

## Recommendation ledger

| Rank | Public identity | Component | Recommendation | Causal attribution | Decisive boundary |
|---:|---|---|---|---|---|
| 13 | CVE-2026-32050 / GHSA-792q-qw95-f446 | OpenClaw Signal | **STILL_UNKNOWN** | UNKNOWN | Exact reaction-access fix/release, but routed AI change is mention gating and origin is unattributed. |
| 14 | CVE-2026-56399 / GHSA-v376-5ppg-xp5v | Open WebUI retrieval | **STILL_UNKNOWN** | UNKNOWN | Seven AI routes miss redirect/fetch validation; exact vulnerable boundary lacks affirmative attribution. |
| 15 | CVE-2026-34511 / GHSA-9jpj-g8vv-j5mf | OpenClaw Gemini OAuth | **STILL_UNKNOWN** | UNKNOWN | Exact PKCE origin/fix/release; neither origin nor preserving refactor is affirmatively AI-bound. |
| 16 | CVE-2026-41408 / GHSA-4g5x-2jfc-xm98 | OpenClaw Tlon media | **STILL_UNKNOWN** | UNKNOWN; **NARROW** availability scope | Exact unbounded origin and released cap; all 80 AI routes miss `media.ts`. |
| 17 | CVE-2026-35660 / GHSA-wq58-2pvg-5h4f | OpenClaw Gateway | **STILL_UNKNOWN** | UNKNOWN | All 69 P0 routes bind a release carrier, not the exact admin-scope fix. |
| 18 | CVE-2026-70395 / GHSA-vvp6-3wv6-833j | Ash relationships | **STILL_UNKNOWN** | UNKNOWN | Three Claude ancestors are wrong-mechanism; exact 2022 origin is unattributed. |
| 19 | CVE-2026-19352 / GHSA-rq3v-mj3j-qv4c | LosslessCut HTTP API | **RESOLVED_REJECT** | UNKNOWN retained | Exact fix has no containing release; two Claude ancestors are workflow-only. |
| 20 | CVE-2026-19387 / GHSA-32fh-qx9x-qfwj | GStreamer IMA ADPCM | **RESOLVED_REJECT** | REJECT | Exact 2009 human origin and human fix; release 1.28.6, no same-mechanism AI edge. |
| 21 | CVE-2026-19376 / GHSA-86p9-mgrp-3g8m | Badaso file API | **RESOLVED_REJECT** | UNKNOWN retained | Vendor report remains open, vulnerable routes remain, and no fix/release exists. |
| 22 | CVE-2026-19361 / GHSA-4j4g-jhqh-8v4w | macrozheng/mall reset | **RESOLVED_REJECT** | UNKNOWN retained | Vendor issue deleted; vulnerable flow remains with no fix/release. |
| 23 | CVE-2026-15534 / GHSA-2cxw-qmfc-3vx3 | Perl regex cache | **RESOLVED_REJECT** | UNKNOWN retained | Exact human patches exist only on unreleased `blead`; older origin not fully recovered. |
| 24 | CVE-2026-19389 / GHSA-p44h-f9j6-g9ff | GStreamer ASF demuxer | **RESOLVED_REJECT** | REJECT | Exact 2006–2008 human origins and human fix; release 1.28.6, no AI edge. |

## Row-level adjudication

### Rank 13 — CVE-2026-32050 / GHSA-792q-qw95-f446 — STILL_UNKNOWN

- First party: [OpenClaw advisory GHSA-792q-qw95-f446](https://github.com/openclaw/openclaw/security/advisories/GHSA-792q-qw95-f446) says reaction-only Signal events could call `enqueueSystemEvent` before DM/group authorization; affected `<=2026.2.24`, fixed `>=2026.2.25`.
- Exact containment: [fix `2aa7842adeedef423be7ce283a9144b9f1a0a669`](https://github.com/openclaw/openclaw/commit/2aa7842adeedef423be7ce283a9144b9f1a0a669) moves a shared access decision ahead of reaction notification enqueue. Local ancestry check confirms `bcbfb357…` is an ancestor of the fix.
- Candidate/lineage: local blame and the frozen audit retain refactor `bcbfb357bec72500b304936fd2d37e1acd49edbb` as the vulnerable boundary. The only routed AI commit directly editing `event-handler.ts`, `1d46ca3a95c7ff2669cc9c2a231fc460a2a3cbbb`, adds group mention gating after the reaction-only early-return branch; it does not add or remove the missing sender-access check.
- Decision: that routed edge is wrong-mechanism, but `bcbfb357…` has no affirmative public AI binding. No negative authorship proof exists, so the row remains UNKNOWN rather than REJECT.

### Rank 14 — CVE-2026-56399 / GHSA-v376-5ppg-xp5v — STILL_UNKNOWN

- First party: Open WebUI’s [duplicate advisory GHSA-82r6-c5jm-f3mw](https://github.com/open-webui/open-webui/security/advisories/GHSA-82r6-c5jm-f3mw) explicitly identifies the same `/api/v1/retrieval/process/web` SSRF and the same patch as the [canonical advisory GHSA-c6xv-rcvw-v685](https://github.com/open-webui/open-webui/security/advisories/GHSA-c6xv-rcvw-v685).
- Exact containment: [fix `02238d3113e966c353fce18f1b65117380896774`](https://github.com/open-webui/open-webui/commit/02238d3113e966c353fce18f1b65117380896774) adds scheme checks, hostname/IP filtering, and blocked-result handling in `backend/open_webui/retrieval/web/{main,utils}.py`. The duplicate’s structured field says `0.6.27`, but its own narrative says the canonical range supersedes it; the canonical first-party record says affected `<=0.6.36`, patched `>=0.6.37`. This report uses `0.6.37` and preserves the discrepancy.
- Candidate/lineage: `af57a2c1538f46b8f480deeff10942cf463acc5b` is the oldest blamed boundary for the vulnerable initial-target validation in the fix parent. None of the seven routed AI edges edits the redirect/fetch validation mechanism. Examples: Jules bot `41e4e739…` changes notes permissions/config; Jules bot `70333c4d…` changes `Chat.svelte`; `f4d54c51…` adds SCIM; `918f507d…` is only a merge/release carrier.
- Decision: every observed AI route is wrong-edge or carrier-only, but the exact vulnerable boundary lacks affirmative authorship evidence in either direction. STILL_UNKNOWN.

### Rank 15 — CVE-2026-34511 / GHSA-9jpj-g8vv-j5mf — STILL_UNKNOWN

- First party: [OpenClaw advisory GHSA-9jpj-g8vv-j5mf](https://github.com/openclaw/openclaw/security/advisories/GHSA-9jpj-g8vv-j5mf) says the Gemini OAuth flow exposed the PKCE verifier by reusing it as `state`; affected `<=2026.4.1`, fixed `>=2026.4.2`.
- Exact lineage/containment: `a6deb0d9d57629c9511ecd490de870149359fb07` introduces the bundled provider with both `state: verifier` and `code_verifier: verifier`; it is an ancestor of [fix `a26f4d0f3ef0757db6c6c40277cc06a5de76c52f`](https://github.com/openclaw/openclaw/commit/a26f4d0f3ef0757db6c6c40277cc06a5de76c52f), which generates an independent OAuth state and ships in `2026.4.2`.
- Candidate: `92e765cdee15c445af94e0b2c2ac6d03f907f56f` refactors the OAuth modules while preserving `state: verifier`; the retained routing evidence does not affirmatively bind it or the introducing commit to AI. The origin’s human co-author trailer is not an AI signal.
- Decision: same-mechanism ancestry is exact, but the required affirmative AI-authorship gate remains open. STILL_UNKNOWN.

### Rank 16 — CVE-2026-41408 / GHSA-4g5x-2jfc-xm98 — STILL_UNKNOWN (NARROW)

- First party: [OpenClaw advisory GHSA-4g5x-2jfc-xm98](https://github.com/openclaw/openclaw/security/advisories/GHSA-4g5x-2jfc-xm98) classifies the issue as narrow, low-severity availability-only exhaustion: Tlon media bypassed core count/size/cleanup limits. Affected `<=2026.3.28`; fixed `>=2026.3.31`; first stable fixed tag `v2026.3.31`.
- Exact lineage/containment: `f4682742d9d16a58058492d5cb6d2d6e372b9cef` introduces unlimited image enumeration and direct response-to-file streaming; it is an ancestor of [fix `2194587d70d2aef863508b945319c5a7c88b12ce`](https://github.com/openclaw/openclaw/commit/2194587d70d2aef863508b945319c5a7c88b12ce), which caps images and bytes and uses the core media runtime.
- Candidate: none of 80 routed AI edges edits `extensions/tlon/src/monitor/media.ts`. `213a704b71f4996dc82a583288ee53785215f627` is a package-only release-preflight change, not the mechanism. The origin has only a human co-author trailer, not affirmative AI evidence.
- Decision: retain NARROW and released containment, but AI causality remains UNKNOWN.

### Rank 17 — CVE-2026-35660 / GHSA-wq58-2pvg-5h4f — STILL_UNKNOWN

- First party: [OpenClaw advisory GHSA-wq58-2pvg-5h4f](https://github.com/openclaw/openclaw/security/advisories/GHSA-wq58-2pvg-5h4f) says `/reset` and `/new` in the Gateway `agent` RPC allowed `operator.write` callers to reach session reset without the `operator.admin` guard. Affected `<2026.3.23`, fixed `>=2026.3.23`.
- Exact lineage/containment: `616658d4b0883a0e162d2100b990754cf71ee056` introduces that routing and is an ancestor of [fix `50f6a2f136fed85b58548a38f7a3dbb98d2cd1a0`](https://github.com/openclaw/openclaw/commit/50f6a2f136fed85b58548a38f7a3dbb98d2cd1a0), which checks admin scope before reset. The vendor states the fix is in released tags `v2026.3.23` and `v2026.3.23-2`.
- Candidate: all 69 P0 routes bind to broad carrier `630f1479c44f78484dfa21bb407cbe6f171dac87`, a release-preparation commit, not the exact patch. No affirmative AI binding exists for the introducing commit.
- Decision: reject the carrier edge, not the entire authorship hypothesis. STILL_UNKNOWN.

### Rank 18 — CVE-2026-70395 / GHSA-vvp6-3wv6-833j — STILL_UNKNOWN

- First party: [Ash advisory GHSA-vvp6-3wv6-833j](https://github.com/ash-project/ash/security/advisories/GHSA-vvp6-3wv6-833j) and the [CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-70395) identify the exact origin and patch. A nested map could reach `Ash.Query.filter/2` as a predicate, and missing `limit(1)` produced a lookup oracle. Affected `>=1.52.0-rc.11,<3.31.1`; fixed `>=3.31.1`.
- Exact lineage/containment: [origin `571c138140e71cea24005189f45d7a63c8d2ed20`](https://github.com/ash-project/ash/commit/571c138140e71cea24005189f45d7a63c8d2ed20) replaces typed `Ash.Filter.get_filter` casting with a raw key map passed to `Ash.Query.filter`; it is an ancestor of [fix `09f42593035bceb0f6153dd7ee45cc49d108300a`](https://github.com/ash-project/ash/commit/09f42593035bceb0f6153dd7ee45cc49d108300a), which restores casting and adds `limit(1)`.
- Negative controls: all three observed Claude-bound ancestors are causally unrelated: `08b65244…` redacts pagination keysets, `737288cc…` handles calculation filters on restrictive data layers, and `93335a22…` fixes documentation typos. The 2022 origin itself has no affirmative public AI binding.
- Decision: exact security lineage and release containment close, but AI authorship does not. Absence is not negative evidence; STILL_UNKNOWN.

### Rank 19 — CVE-2026-19352 / GHSA-rq3v-mj3j-qv4c — RESOLVED_REJECT

- First party: the frozen [CVEList record](https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/19xxx/CVE-2026-19352.json) identifies affected LosslessCut through 3.69.0 and [patch `260802348955231442c4bae6c2d9d8ede947af0a`](https://github.com/mifi/lossless-cut/commit/260802348955231442c4bae6c2d9d8ede947af0a), which adds Host/Origin validation to `src/main/httpServer.ts` for the DNS-rebinding/CSRF mechanism.
- Exact lineage: `a3cbce61901651d526d9575f3c4bb2aafc21c40f` is the 2023 first vulnerable HTTP API implementation. Claude-bound ancestors `7da03ebdad9d836241e9d33fe1fe3a11c2e49fd2` and `b0eb2b980e3d3a4ce3e14c31375ce8c40ea8f905` edit only `.github/workflows/build.yml`; they are exact negative controls for same-mechanism causality.
- Release boundary: no tag contains the fix, while the vulnerable origin is contained through `v3.69.0`.
- Decision: reject from the publication corpus because released containment fails. AI attribution of the origin remains UNKNOWN; the decision is not a human-only claim.

### Rank 20 — CVE-2026-19387 / GHSA-32fh-qx9x-qfwj — RESOLVED_REJECT

- Identity recovery: `ima/dvi` was a codec token, not an owning repository. The exact first-party object is GStreamer [MR 12235](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/12235), with human commits `5448745c4c892be67ff710e928c69cfd9ef8a2e8` and [`5903987091bb25e4f549331032cd2e3494cf8dae`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/5903987091bb25e4f549331032cd2e3494cf8dae).
- Same mechanism: `5903987…` changes the validation modulus from `8` to `8 * dec->channels`, directly repairing multi-channel sample-count under-validation. First-party blame attributes the vulnerable check to human commit `29c3542dd5ed0471245f02c13e9e2a63399f1ad8` from 2009.
- Released containment: project advisory [GST-SA-2026-0077](https://gstreamer.freedesktop.org/security/sa-2026-0077.html) says `gst-plugins-bad <1.28.6` is affected and 1.28.6 fixes it.
- Decision: exact origin, patch, mechanism, and release are closed, but there is no same-mechanism public AI edge. RESOLVED_REJECT.

### Rank 21 — CVE-2026-19376 / GHSA-86p9-mgrp-3g8m — RESOLVED_REJECT

- First party: [Badaso issue 1100](https://github.com/uasoft-indonesia/badaso/issues/1100) remained open at the boundary; the frozen [CVEList record](https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/19xxx/CVE-2026-19376.json) says the maintainer did not respond and links no patch.
- Repository evidence: at observed HEAD `1ee86e4c5eed33c23b46163a0359e41f3fa357b7`, file view/download/delete routes still lack authentication/permission middleware. Blame places the route group in human commit `fcae4ee21cd416754ca9ecf13e1a370874cb1332` (2022); no post-disclosure route fix or containing release was present.
- Decision: source identity is recovered, so the former source block is closed; absence of a public fix and released containment is an affirmative eligibility failure. RESOLVED_REJECT, with private AI use not inferred either way.

### Rank 22 — CVE-2026-19361 / GHSA-4j4g-jhqh-8v4w — RESOLVED_REJECT

- First party: the frozen [CVEList record](https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/19xxx/CVE-2026-19361.json) says the vendor deleted issue 979 and did not respond. The vendor issue URL now resolves to the repository page; the surviving [disclosure issue](https://github.com/wr0ld/macrozheng-mall-Commit-0504e86-Broken-Authentication/issues/1) remained open.
- Repository evidence: observed vendor HEAD `d9501e97a78eb2bb0ae8eaa273eeb1cfc7c5d386` still returns an authentication code from `/sso/getAuthCode` and accepts it at `/sso/updatePassword`. Blame attributes the flow to human commit `663e2d706a287b53dd95abfd0da80e40062f51a6` (2022). No public fix or released containment exists.
- Decision: the row is no longer source-blocked, but it fails the mandatory public-fix and release gates. RESOLVED_REJECT; no private-authorship inference.

### Rank 23 — CVE-2026-15534 / GHSA-2cxw-qmfc-3vx3 — RESOLVED_REJECT

- First party: the frozen [CVEList record](https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/15xxx/CVE-2026-15534.json) names exact human patches [`568e6fd238867bb9e99fa3f47cba3169009239e0`](https://github.com/Perl/perl5/commit/568e6fd238867bb9e99fa3f47cba3169009239e0) and [`54cf3d44cbbedd17d774e9a37921963e8fd5d0cb`](https://github.com/Perl/perl5/commit/54cf3d44cbbedd17d774e9a37921963e8fd5d0cb).
- Same mechanism: the patches make the countdown unsigned-compatible, widen `I32` cache counters to `STRLEN`, and bound `(len + 1) * n`, exactly matching the undersized regex-cache overflow.
- Release boundary: tags through `v5.45.1` retain the vulnerable `I32` counters; no `v5.45.2` or `v5.44.1` exists at the snapshot, and only `blead` contains the fix.
- Decision: exact source patches exist but released containment fails, so the row is RESOLVED_REJECT for corpus eligibility. The older causal origin was not fully re-established; causal authorship remains UNKNOWN.

### Rank 24 — CVE-2026-19389 / GHSA-p44h-f9j6-g9ff — RESOLVED_REJECT

- Identity recovery: `overflow/underflow` was mechanism text, not an owning repository. GStreamer [MR 12233](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/12233) contains exact human [fix `cc36734ceed745216ea481e2f67901680e4f6304`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/cc36734ceed745216ea481e2f67901680e4f6304).
- Same mechanism: the patch widens skip lengths to `guint64` and adds lower-bound checks before the vulnerable subtractions. First-party blame locates those expressions in human commits `366b006b7d2e198b3cf072281d336e8968f7a125`, `f8d7045fc8f17aeeaae260a700becc13eb0a1497`, `d0483656b3d07fbe6f963f959e1d87316c0d9807`, and `49cdce158d49631d65a9539885a47abcc030cb55` from 2006–2008.
- Released containment: project advisory [GST-SA-2026-0075](https://gstreamer.freedesktop.org/security/sa-2026-0075.html) says `gst-plugins-ugly <1.28.6` is affected and 1.28.6 addresses it.
- Decision: exact old human lineage, same-mechanism fix, and released containment close; there is no public AI causal edge. RESOLVED_REJECT.

## Negative, blocked, and unknown controls

- No product or repository branding was used as an authorship signal.
- No row passed merely because an AI-attributed commit was an ancestor, shared a file, appeared near a fix, added a test, or was carried by a release merge.
- Wrong-edge findings are preserved at candidate-edge level; they do not become categorical human-authorship claims.
- The rank-14 first-party version discrepancy is preserved rather than silently reconciled.
- The later unauthenticated GitHub API 403 is preserved as a source-snapshot limitation. Earlier successful advisory reads and frozen first-party records remain usable; the 403 itself supplies no evidence.
- Ranks 19 and 23 retain causal UNKNOWN despite a corpus-level REJECT because their independent mandatory release gate fails. Ranks 21 and 22 are eligibility negatives (no public fix/release), not negative proof about private AI use.
- During the supporting rank 19–24 replay, one initial maintenance-disabled `git tag --contains` read of a shared GStreamer promisor clone occurred before `GIT_NO_LAZY_FETCH=1` was set and may have populated missing objects. No ref, index, tag, branch, or worktree file changed; subsequent reads disabled lazy fetch or used first-party HTTP.

## Exact commands and sources

All local Git reads used maintenance-disabled configuration. The salient commands were:

```sh
jq -c 'select(.resolvability_rank>=13 and .resolvability_rank<=24)' autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl
sha256sum autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl autoresearch/herdr-260812-unknown-recovery/snapshot/audit-adjudications.jsonl autoresearch/herdr-260812-unknown-recovery/snapshot/refresh-exact-adjudications.jsonl autoresearch/herdr-260812-unknown-recovery/snapshot/audit-handoff.md autoresearch/orchestrator-260810-0613/audit-review/official-records.jsonl autoresearch/orchestrator-260810-0613/audit-review/prioritized-ai-edges.jsonl
git -c gc.auto=0 -c maintenance.auto=false -C REPO show -s --format='%H%x09%P%x09%aI%x09%an <%ae>%x09%s' SHA
git -c gc.auto=0 -c maintenance.auto=false -C REPO show --format= --name-only SHA
git -c gc.auto=0 -c maintenance.auto=false -C REPO show --format= --unified=6 SHA -- PATH
git -c gc.auto=0 -c maintenance.auto=false -C REPO blame -L 46,95 02238d3113e966c353fce18f1b65117380896774^ -- backend/open_webui/retrieval/web/utils.py
git -c gc.auto=0 -c maintenance.auto=false -C REPO merge-base --is-ancestor ORIGIN FIX
curl -fsS --max-time 20 https://api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID
curl -fsS --max-time 20 https://cveawg.mitre.org/api/cve/CVE-2026-70395
```

The exact first-party source URLs appear in each row. No build or test suite was run: tests are diagnostic and unnecessary to establish the report’s authorship boundary.

## Claim boundary

This ledger recommends what the frozen evidence supports; it does not prove that unattributed commits were human-only, and it does not claim that a security fix was AI-authored merely because some AI-attributed commit exists in its ancestry. Only a `RESOLVED_PASS` row would be publication-grade evidence of a genuine AI-authored/assisted vulnerable candidate with exact same-mechanism lineage and released containment. `STILL_UNKNOWN` and `STILL_BLOCKED` are terminal findings for this bounded batch, not invitations to infer a positive result.

## Artifact map

- `report.md`: narrative, sources, commands, evidence, negative controls, and claim boundary.
- `recommendation-ledger.jsonl`: twelve machine-readable row dispositions.
- `result.json`: terminal status, counts, blockers, claim boundary, and artifact map.
- `background-r19-24.md`: bounded supporting first-party replay for ranks 19–24.
