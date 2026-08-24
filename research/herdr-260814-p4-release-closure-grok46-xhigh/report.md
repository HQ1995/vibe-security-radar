# P4 release/fix closure of 11 hostile UNKNOWN rows

Verdict first: **KEEP 0. PASS_PROPOSAL 0. REJECT 11. UNKNOWN 0. NARROW row 0.** Packet delta 0. Current leader-accepted count remains **85**.

Independent closure of only the 11 UNKNOWN rows in `autoresearch/herdr-260814-w3-p4-hostile-redteam-grok46-xhigh/cases.jsonl`. The 3 hostile REJECT rows (GHSA-87X5, GHSA-XC48, GHSA-26GQ) were not reopened. Original P4 `herdr-260814-w3-p4-grok46-high` release PASS values were not copied. Missing/404 artifacts would have stayed UNKNOWN; after first-party tag, npm, PyPI, crates.io, Maven, and goproxy replay none of these 11 were 404. Same first tag without a vulnerable interval is NARROW, not PASS. A PASS_PROPOSAL requires all seven gates exactly PASS and a distinct first-party GHSA mechanism absent from canonical85. None of these rows meet that bar.

Conservation: assigned=11, reviewed=11, unreviewed=0.

## Verdict table

| Case | Kind | Hostile | This review | Release | Closed FAILs |
|---|---|---|---|---|---|
| GHSA-4F78-QHMW-8J8M | 1 | UNKNOWN | REJECT | PASS (v41.0.0 / v41.2.0) | ai_hunk, topology, but-for |
| GHSA-F2R8-JV7C-XQMP | 1 | UNKNOWN | REJECT | PASS (v42.0.0-alpha.1 / v42.0.0-beta.3) | ai_hunk, topology, but-for |
| GHSA-C4C3-PG64-4M4V | 1 | UNKNOWN | REJECT | PASS (mermaid@11.16.0 / 11.16.1) | ai_hunk, but-for |
| GHSA-JR45-8VMC-QM54 | 1 | UNKNOWN | REJECT | PASS (undici 7.24.5 / 7.29.0 and 8.0.0 / 8.9.0) | ai_hunk, but-for |
| GHSA-W62W-66V9-VVGV | 1 | UNKNOWN | REJECT | PASS (4.29 / 4.30 plus goproxy pseudo) | ai_hunk, but-for |
| GHSA-RQ84-P6RR-VF89 | 1 | UNKNOWN | REJECT | PASS (v0.8.0 / v0.11.0 plus PyPI) | ai_hunk, topology, but-for |
| GHSA-QHJ8-Q5R6-8Q6J | 2 | UNKNOWN | REJECT | NARROW | ai_hunk, but-for, fix_reversal |
| GHSA-JQ43-27X9-3V86 | 2 | UNKNOWN | REJECT | NARROW | ai_hunk, but-for |
| GHSA-4HX9-48XH-5MXR | 2 | UNKNOWN | REJECT | NARROW | ai_hunk, but-for |
| GHSA-RJ4J-2JPH-GG43 | 2 | UNKNOWN | REJECT | NARROW | ai_hunk, but-for |
| GHSA-7C4H-VH2M-743M | 2 | UNKNOWN | REJECT | NARROW | ai_hunk, but-for |

## Kind-1 peels (release PASS as containment, not a save)

### GHSA-4F78-QHMW-8J8M -- REJECT

Identity PASS. Origin FAIL: parent `bab6bd3d` already concatenates `dock_state_` into DevTools JS. Candidate `fe477ce3` is an electron-roller Chromium bump.

Release independently peeled on the 41.x line. Git `v41.0.0` and npm `electron@41.0.0` contain the candidate and do not contain listed closer `969741f9`; the file still concatenates unsanitized `dock_state_`. Git `v41.2.0` and npm `electron@41.2.0` contain `969741f9` and `kValidDockStates`. Hostile was correct that `v41.2.0` contains both the candidate and that closer; that is the fixed artifact, not proof that no vulnerable artifact exists. Original P4 PASS that paired `v41.0.0` with 42.x closer `04614eed` was not used.

### GHSA-F2R8-JV7C-XQMP -- REJECT

Same candidate SHA, distinct GHSA. Parent already uses `platform_util::OpenPath` on the DevTools embedder reveal path.

Exact listed closer `10fb5b39`: `v42.0.0-alpha.1` contains the candidate and OpenPath and does not contain `10fb5b39`. `v42.0.0-beta.3` / npm `electron@42.0.0-beta.3` contains `10fb5b39`. Stable `v41.0.0` also contains the candidate without that listed SHA. `v41.2.1` removes OpenPath via unlisted trop `1b8a298d62` (#50937); that SHA is recorded and was not substituted for the listed closer.

### GHSA-C4C3-PG64-4M4V -- REJECT

Cursor coauthor on beta-policy tests. Candidate does not touch `assignWithDepth.ts`.

Hostile gn clone lacked `mermaid@11.16.0` / `mermaid@11.16.1`. The cve-analyzer clone has both tags. `mermaid@11.16.0` contains `dea05724` and not `2cd6dcf7`. `mermaid@11.16.1` contains `2cd6dcf7`. npm `mermaid@11.16.0` and `mermaid@11.16.1` are HTTP 200. Not same-first-tag. Original P4 PASS was not copied.

### GHSA-JR45-8VMC-QM54 -- REJECT

Claude TTL change in `cache-handler.js` is not `parseCacheControlHeader` OWS trimming.

npm `undici@7.24.5` gitHead `51fd6617` contains `90775009` and not `85a24055`. npm/git `v7.28.0` already contains `85a24055`. Advisory-named npm/git `v7.29.0` `9e38fc12` also contains `85a24055`. 8.x: `v8.0.0` contains the candidate and not `cb105d7c`; `v8.5.0` and advisory-named `v8.9.0` contain `cb105d7c`. Those npm versions are HTTP 200. Local cache lacked `v7.29.0` / `v8.9.0`; they were fetched by tag, not GitHub REST.

### GHSA-W62W-66V9-VVGV -- REJECT

GetObjectAttributes is a new route on a pre-existing SkipClean router. Parent already has GetObject and Iceberg SkipClean.

Git `4.29` is the parent of `dd1b4287` and contains `10a30a83` without the closer. Git `4.30` contains `dd1b4287`. `proxy.golang.org` pseudo-version `v0.0.0-20260526080459-dd1b4287899e` is HTTP 200 with Origin.Hash equal to `dd1b4287`. Hostile left UNKNOWN because the exact pseudo-version was not a git tag name. First-party git tags and the named module artifact peel. Original P4 PASS was not copied.

### GHSA-RQ84-P6RR-VF89 -- REJECT

Log-env squash is not OAuth token-exchange audience checking. Independent replay of `b190dcf3` adds `OAUTH_TOKEN_EXCHANGE_TRUSTED_CLIENT_IDS` and introspection. Original P4 fix_reversal FAIL was not inherited.

Local cache stopped at `v0.8.12`. `git ls-remote` plus fetch of first-party `v0.11.0` (`f9590b80`) shows it contains `b190dcf3` and `c4332be7`. `v0.8.0` and `v0.10.0` contain `823b9a6d` and not those closers. PyPI `open-webui` 0.8.0 and 0.11.0 are HTTP 200 and not yanked.

## Kind-2 (assigned SHA is the listed fix)

Same-first-tag rule: the first first-party tag that contains the assigned SHA also contains the closer, because they are the same SHA. That is NARROW, not PASS. Origin still FAILs, so the row is REJECT, not NARROW.

### GHSA-QHJ8-Q5R6-8Q6J -- REJECT

Changelog-only. No AI marker. Fix-reversal FAIL with positive evidence: name-only is `bindings/matrix-sdk-ffi/CHANGELOG.md`. The panic closer in `matrix-sdk-base-0.14.1` is `476fe5f9d`, present there and absent from `0.14.0`. crates.io 0.14.0 and 0.14.1 are HTTP 200. Assigned SHA is not in 0.14.1. First tags that contain it are the 0.16.0 family. Release NARROW.

### GHSA-JQ43-27X9-3V86 -- REJECT

Human merge-from-fork SMTP sanitizer. Maven `netty-codec-smtp` 4.2.6.Final and 4.2.7.Final HTTP 200. Git `netty-4.2.6.Final` lacks `1782e8c2`. Git `netty-4.2.7.Final` first contains that SHA, which is the closer. NARROW.

### GHSA-4HX9-48XH-5MXR -- REJECT

Human LDAP URL restriction. Maven `keycloak-ldap-federation` 26.4.5 and 26.4.6 HTTP 200. Git `26.4.5` lacks `754c070c`. Git `26.4.6` first contains it. NARROW.

### GHSA-RJ4J-2JPH-GG43 -- REJECT

Human path-validation fix. Advisory names 2.3.0. goproxy `v2.3.0` HTTP 200 Origin.Hash=`bda2bbcc` equals git `v2.3.0` and does not contain `58362b08`. First containing tag is `v2.4.0-alpha.2` (goproxy Origin.Hash=`56193238`). NARROW. Named 2.3.0 is not a 404.

### GHSA-7C4H-VH2M-743M -- REJECT

Human community-package version validation. npm `n8n@1.120.2` and `n8n@1.120.3` HTTP 200. Git `n8n@1.120.2` lacks `ae0669a7`. Git `n8n@1.120.3` first contains it. NARROW.

## Uniqueness and claim boundary

All eleven identities are absent from canonical85 counted 85, including appended `GHSA-8359-H9FX-J6V9`. GHSA-4F78 and GHSA-F2R8 share candidate `fe477ce3` and remain distinct failed edges.

No PASS_PROPOSAL. Canonical85 was not edited. Publication and more-than-200 stay HOLD.

## Replay

`zsh replay.zsh` must print `REPLAY_OK reviewed=11 KEEP=0 REJECT=11 UNKNOWN=0 PASS_PROPOSAL=0 packet_delta=0 current_leader_accepted_count=85`. No GitHub API. No ledger edits. No commit or push. Owned clones and pages deleted after replay.

## Input hashes (SHA-256)

- hostile cases.jsonl `100ce5c5b7c9f6561a5bba0619ce9936c26b105ae94221a32ba92102f906a7bb`
- adjudication-4.jsonl `3264d02737cfef400e3e70cd45a6e88c852b46f6d98f3a5320c85af1ca9b563f`
- CONTRACT.md `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- canonical85 ledger.jsonl `2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568`
