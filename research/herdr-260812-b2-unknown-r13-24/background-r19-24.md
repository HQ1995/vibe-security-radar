# Batch 2 primary-source adjudication: unresolved ranks 19–24

## Result

Frozen recommendation at `2026-08-12T16:55:57Z`: **0 RESOLVED_PASS, 6 RESOLVED_REJECT, 0 STILL_BLOCKED, 0 STILL_UNKNOWN**.

`RESOLVED_REJECT` here means only that the row cannot enter the current publication corpus under the required gates. For ranks 19 and 23, causal AI attribution remains unknown, but a separately verified hard gate—released containment—fails. This is not a claim that private AI assistance was impossible.

| Rank | Advisory | Recommendation | Decisive boundary |
|---:|---|---|---|
| 19 | CVE-2026-19352 / GHSA-rq3v-mj3j-qv4c | **RESOLVED_REJECT** | Two public Claude commits are exact ancestors but touch only the Windows build workflow. The vulnerable HTTP API origin is human-authored and unattributed for AI purposes; the exact human fix has no containing release tag. |
| 20 | CVE-2026-19387 / GHSA-32fh-qx9x-qfwj | **RESOLVED_REJECT** | `ima/dvi` is a codec token, not the owning repository. GStreamer MR 12235 is the exact fix and 1.28.6 is released containment; the vulnerable validation line originated in a human 2009 commit, so there is no same-mechanism public AI edge. |
| 21 | CVE-2026-19376 / GHSA-86p9-mgrp-3g8m | **RESOLVED_REJECT** | The only first-party report remains open and the CNA says the maintainer did not respond. The vulnerable routes remain in the observed repository HEAD; no public fix or released containment exists. |
| 22 | CVE-2026-19361 / GHSA-4j4g-jhqh-8v4w | **RESOLVED_REJECT** | The vendor issue was deleted, the surviving disclosure issue remains open, and the vulnerable password-reset flow remains at observed HEAD. No public fix or released containment exists. |
| 23 | CVE-2026-15534 / GHSA-2cxw-qmfc-3vx3 | **RESOLVED_REJECT** | The two exact Perl patches are human-authored and same-mechanism, but no release tag contains them at the boundary; released tags through v5.45.1 retain the vulnerable `I32` cache counters. |
| 24 | CVE-2026-19389 / GHSA-p44h-f9j6-g9ff | **RESOLVED_REJECT** | `overflow/underflow` is a mechanism token, not the owning repository. GStreamer MR 12233 is the exact human fix, released in 1.28.6; blamed vulnerable expressions originate in human commits from 2006–2008. |

## Snapshot and inputs

Only inventory lines/ranks 19–24 were read. No other rank was adjudicated or discussed.

- `autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl`: SHA-256 `5167b86efb2d6e3d218c41da120c7302f99049b9c588e8fd00896051d50355ca`.
- `snapshot/refresh-exact-adjudications.jsonl`: `ca026877faf923625df0c88afb9fa97b482123c0f7a1d37b966350cc9513dff8`.
- `snapshot/refresh-overlay.jsonl`: `bfafa3e5ae570eb01be61dfb9aeb0adbcfdfe19f1a453ba494e3a13743aaa4e8`.
- `snapshot/audit-handoff.md`: `da93dbc191996505ea79fc2a71f8892c9c7e6cdf14a6053530d73f13f750969c`.
- `snapshot/refresh-handoff.md`: `eba2d5d1593f5edfec639f2580fd2149af18c519c9a7442777d895be151cdeb2`.
- CVEList snapshot revision: `e07ca6f300c9ca36f9120b0d5149a5edf6227b1f`. Inventory-bound record hashes: rank 19 `c31390387007b22422989fee458cdfdc52f28eb1bc850d92d11903885d263855`; rank 20 `17692ec241334dd03bce92aa112226830da7e44de38f0bb4776fc2a67ce4d708`; rank 21 `55bcfc42ef23d71559ff5df3b9a8cbdf66fb82bf1c00674ac245e8ab55420fd7`; rank 22 `aa78571a9b39e0f13a6d7d01886358ded43acd98b1b5b320c4eebf4799856dac`; rank 23 `aed8b7f555a13f50e6513299e72aa4f3c565b23531e06cc1afaf07d5b69a947a`; rank 24 `490912131c47f1c3b49878c952ce23aafef50b728741c2d8f781890ddfe18625`.
- Read-only repository HEADs observed: LosslessCut `3b9a59c288bf6e11076b583c932cfa48ddab3b02`; Badaso `1ee86e4c5eed33c23b46163a0359e41f3fa357b7`; mall `d9501e97a78eb2bb0ae8eaa273eeb1cfc7c5d386`; Perl `e6dfa909e10757e7906b67c06533058d0f40cb1c`; GStreamer `598383c413681b426e0f2c93a2813f1a6b40565e`.

Operational disclosure: an initial GStreamer `git tag --contains` read was run with `-c gc.auto=0 -c maintenance.auto=false` but before `GIT_NO_LAZY_FETCH=1`; it emitted a remote redirect from the promisor clone and may have populated missing objects in that shared clone. No ref, index, branch, tag, or worktree file changed. All subsequent shared-repository reads set `GIT_NO_LAZY_FETCH=1`, or used first-party HTTP APIs/raw files.

## Row-level evidence

### Rank 19 — LosslessCut — RESOLVED_REJECT

The VulDB CNA record names [`260802348955231442c4bae6c2d9d8ede947af0a`](https://github.com/mifi/lossless-cut/commit/260802348955231442c4bae6c2d9d8ede947af0a) as the patch and affected versions through 3.69.0. The patch adds Host/Origin validation to `src/main/httpServer.ts` and tests, matching the DNS-rebinding/CSRF mechanism.

The first vulnerable implementation is human commit [`a3cbce61901651d526d9575f3c4bb2aafc21c40f`](https://github.com/mifi/lossless-cut/commit/a3cbce61901651d526d9575f3c4bb2aafc21c40f), dated 2023-10-15. Public Claude commits [`7da03ebdad9d836241e9d33fe1fe3a11c2e49fd2`](https://github.com/mifi/lossless-cut/commit/7da03ebdad9d836241e9d33fe1fe3a11c2e49fd2) and [`b0eb2b980e3d3a4ce3e14c31375ce8c40ea8f905`](https://github.com/mifi/lossless-cut/commit/b0eb2b980e3d3a4ce3e14c31375ce8c40ea8f905) carry explicit Claude Fable 5 co-author/session metadata and are ancestors of the fix, but modify only `.github/workflows/build.yml`. They are wrong-mechanism controls. `git tag --contains` returned no tag for either candidate or the fix; the vulnerable origin is contained through `v3.69.0`. Thus exact causality remains unattributed and released containment is absent.

Primary sources: [CVEList record](https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/19xxx/CVE-2026-19352.json), [GHSA identity](https://github.com/advisories/GHSA-rq3v-mj3j-qv4c), and the linked repository commits above.

### Rank 20 — GStreamer IMA ADPCM — RESOLVED_REJECT

The Red Hat CNA record and GHSA point to GStreamer, not a repository named `ima/dvi`. First-party [MR 12235](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/12235) is merged and contains human commits [`5448745c4c892be67ff710e928c69cfd9ef8a2e8`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/5448745c4c892be67ff710e928c69cfd9ef8a2e8) and [`5903987091bb25e4f549331032cd2e3494cf8dae`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/5903987091bb25e4f549331032cd2e3494cf8dae). The latter changes the vulnerable check from `% 8` to `% (8 * dec->channels)`, exactly matching multi-channel sample-count under-validation. GitLab blame attributes that check to human commit [`29c3542dd5ed0471245f02c13e9e2a63399f1ad8`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/29c3542dd5ed0471245f02c13e9e2a63399f1ad8), “adpcmdec: complete ima adpcm support,” dated 2009-07-23.

The project-owned [GST-SA-2026-0077](https://gstreamer.freedesktop.org/security/sa-2026-0077.html) states `gst-plugins-bad < 1.28.6` is affected and that 1.28.6 addresses the issue. This closes exact fix, mechanism, and released containment, but not an AI causal edge.

### Rank 21 — Badaso file API — RESOLVED_REJECT

The first-party [issue 1100](https://github.com/uasoft-indonesia/badaso/issues/1100) remained `OPEN`, created/last updated 2026-06-23. The VulDB CNA record says the project was informed but had not responded and links no patch. At observed HEAD `1ee86e4c...` (2025-04-21), `src/Routes/api.php` still exposes file `view`, `download`, and `delete` routes without authentication/permission middleware. Blame assigns the route group to human commit `fcae4ee21cd416754ca9ecf13e1a370874cb1332` (2022). No post-disclosure route commit, advisory-linked patch, or release tag was present. This rejects the row for absence of a public security fix and released containment; it does not assert a universal negative about private AI use.

Primary sources: [CVEList record](https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/19xxx/CVE-2026-19376.json), [GHSA](https://github.com/advisories/GHSA-86p9-mgrp-3g8m), and issue 1100.

### Rank 22 — macrozheng/mall password reset — RESOLVED_REJECT

The CNA says the vendor deleted issue 979 and did not respond. The original [issue URL](https://github.com/macrozheng/mall/issues/979) now resolves to the repository page; the surviving [disclosure issue](https://github.com/wr0ld/macrozheng-mall-Commit-0504e86-Broken-Authentication/issues/1) remained `OPEN`, created/last updated 2026-06-23. Observed vendor HEAD `d9501e97...` (2026-03-06, before disclosure) still returns the generated authentication code from `/sso/getAuthCode` and accepts it at `/sso/updatePassword`. Blame attributes both controller flow and verification service to human commit `663e2d706a287b53dd95abfd0da80e40062f51a6` (2022). No post-disclosure relevant commit, public fix, or release containment exists.

Primary sources: [CVEList record](https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/19xxx/CVE-2026-19361.json), [GHSA](https://github.com/advisories/GHSA-4j4g-jhqh-8v4w), and the two issue URLs above.

### Rank 23 — Perl regex superlinear cache — RESOLVED_REJECT

The CPANSec CNA record names exactly two patches. Human commit [`568e6fd238867bb9e99fa3f47cba3169009239e0`](https://github.com/Perl/perl5/commit/568e6fd238867bb9e99fa3f47cba3169009239e0) makes the countdown unsigned-compatible; human commit [`54cf3d44cbbedd17d774e9a37921963e8fd5d0cb`](https://github.com/Perl/perl5/commit/54cf3d44cbbedd17d774e9a37921963e8fd5d0cb) changes the `I32` counters to `STRLEN` and bounds the `(len + 1) * n` calculation. Both are authored by David Mitchell and exactly match the advisory's undersized-cache overflow mechanism; neither patch metadata contains public AI attribution.

Released containment fails at the boundary. Remote tags include v5.45.1 but no v5.45.2 or v5.44.1. First-party raw files for v5.42.0–v5.42.3, v5.44.0, v5.45.0, and v5.45.1 all retain `I32 poscache_maxiter`/`poscache_iter`; only `blead` contains the `STRLEN` fix. Therefore the exact source fix exists but is unreleased. The older causal origin was not fully re-established, so no broader negative AI-causality claim is made.

Primary sources: [CVEList record](https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/15xxx/CVE-2026-15534.json), [patch 1](https://github.com/Perl/perl5/commit/568e6fd238867bb9e99fa3f47cba3169009239e0.patch), [patch 2](https://github.com/Perl/perl5/commit/54cf3d44cbbedd17d774e9a37921963e8fd5d0cb.patch), and [v5.45.1 `regexp.h`](https://raw.githubusercontent.com/Perl/perl5/v5.45.1/regexp.h).

### Rank 24 — GStreamer ASF demuxer — RESOLVED_REJECT

The Red Hat CNA record points to GStreamer; `overflow/underflow` is advisory mechanism text, not a repository. First-party [MR 12233](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/12233) is merged with exact human fix [`cc36734ceed745216ea481e2f67901680e4f6304`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/cc36734ceed745216ea481e2f67901680e4f6304). It widens skip lengths to `guint64` and adds lower-bound checks before the exact vulnerable subtractions, matching the integer overflow/underflow advisory mechanism.

GitLab blame assigns vulnerable expressions to human commits `366b006b7d2e198b3cf072281d336e8968f7a125` (2006), `f8d7045fc8f17aeeaae260a700becc13eb0a1497` (2007), `d0483656b3d07fbe6f963f959e1d87316c0d9807` (2007), and `49cdce158d49631d65a9539885a47abcc030cb55` (2008). Project-owned [GST-SA-2026-0075](https://gstreamer.freedesktop.org/security/sa-2026-0075.html) states `gst-plugins-ugly < 1.28.6` is affected and 1.28.6 addresses it. Exact lineage, same mechanism, and released containment are closed; there is no public AI causal edge.

## Exact command/source record

Inventory isolation and hashes:

```sh
sha256sum autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl
sed -n '19,24p' autoresearch/herdr-260812-unknown-recovery/unresolved-inventory.jsonl
sha256sum autoresearch/herdr-260812-unknown-recovery/snapshot/{refresh-exact-adjudications.jsonl,refresh-overlay.jsonl,audit-handoff.md,refresh-handoff.md}
```

CVE records were read from exact revision `e07ca6f3...`:

```sh
curl -fsSL --max-time 15 \
  https://raw.githubusercontent.com/CVEProject/cvelistV5/e07ca6f300c9ca36f9120b0d5149a5edf6227b1f/cves/2026/19xxx/CVE-2026-19387.json
```

The same command shape was used only for the other five in-scope IDs. GitHub advisory identity was queried with `curl -fsSL -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' https://api.github.com/advisories/<GHSA>`; the unauthenticated API rate-limited the final two, so their CVEList records and first-party repository sources, not a missing API response, support the conclusions.

GStreamer exact MRs, commits, blame, and releases:

```sh
curl -fsSL 'https://gitlab.freedesktop.org/api/v4/projects/gstreamer%2Fgstreamer/merge_requests/12235'
curl -fsSL 'https://gitlab.freedesktop.org/api/v4/projects/gstreamer%2Fgstreamer/merge_requests/12235/commits'
curl -fsSL 'https://gitlab.freedesktop.org/api/v4/projects/gstreamer%2Fgstreamer/merge_requests/12233/commits'
curl -fsSL 'https://gitlab.freedesktop.org/api/v4/projects/gstreamer%2Fgstreamer/repository/files/subprojects%2Fgst-plugins-bad%2Fgst%2Fadpcmdec%2Fadpcmdec.c/blame?ref=5448745c4c892be67ff710e928c69cfd9ef8a2e8'
curl -fsSL 'https://gitlab.freedesktop.org/api/v4/projects/gstreamer%2Fgstreamer/repository/files/subprojects%2Fgst-plugins-ugly%2Fgst%2Fasfdemux%2Fgstasfdemux.c/blame?ref=a75bd8187bb716cf543ea2c545002fa38b31e3c7'
curl -fsSL https://gstreamer.freedesktop.org/security/sa-2026-0077.html
curl -fsSL https://gstreamer.freedesktop.org/security/sa-2026-0075.html
```

Repository reads used this form after the disclosed initial GStreamer read:

```sh
GIT_NO_LAZY_FETCH=1 git -c gc.auto=0 -c maintenance.auto=false -C "$repo" show "$sha"
GIT_NO_LAZY_FETCH=1 git -c gc.auto=0 -c maintenance.auto=false -C "$repo" blame -L "$start,$end" --line-porcelain HEAD -- "$path"
GIT_NO_LAZY_FETCH=1 git -c gc.auto=0 -c maintenance.auto=false -C "$repo" log --all --since='2026-06-23T00:00:00Z' -- "$path"
```

Perl release boundary:

```sh
curl -fsSL https://github.com/Perl/perl5/commit/568e6fd238867bb9e99fa3f47cba3169009239e0.patch
curl -fsSL https://github.com/Perl/perl5/commit/54cf3d44cbbedd17d774e9a37921963e8fd5d0cb.patch
git -c gc.auto=0 -c maintenance.auto=false ls-remote --tags https://github.com/Perl/perl5.git \
  'refs/tags/v5.45.*' 'refs/tags/v5.44.*' 'refs/tags/v5.42.*'
curl -fsSL https://raw.githubusercontent.com/Perl/perl5/v5.45.1/regexp.h
curl -fsSL https://raw.githubusercontent.com/Perl/perl5/blead/regexp.h
```

## Claim boundary and negative controls

- No row passes all of public AI binding, but-for causality, exact advisory/fix lineage, same mechanism, and released containment.
- Ranks 20 and 24 are strong causal negatives: exact vulnerable code predates contemporary coding agents by many years, while exact project fixes and releases are first-party verified.
- Ranks 21 and 22 are rejection-by-eligibility controls: no public fix/release exists. This does not prove anything about private AI use.
- Ranks 19 and 23 retain causal attribution uncertainty. They are rejected only because released containment is independently absent (and rank 19's observed Claude commits are also wrong-mechanism).
- A public source commit is not treated as a release. Product/mechanism token carriers (`ima/dvi`, `overflow/underflow`) are not treated as repository identities.
