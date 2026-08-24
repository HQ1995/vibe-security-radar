# OpenClaw tail: primary-source notes

Research time: 2026-08-12 12:18–12:30 EDT

Repository: `openclaw/openclaw`

Outcome: **no new publication-grade positive**. Nine residual routed edges and one high-vote routing control were replayed; all fail the same-mechanism/but-for gate. Seven additional exact-blame routes remain `UNKNOWN` and are listed below rather than silently discarded.

## Scope and immutable snapshot boundary

I read the shared checkout and the existing read-only OpenClaw clone. I did not fetch, build, test, or mutate either one. The shared tree is volatile; all statements below are bound only to these byte hashes and Git refs:

| Input | Frozen value |
|---|---|
| `docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md` | SHA-256 `f0e9655bc724b1aac4bfc075ec1441400c3b2e8fa672e70a474977a983acd6f6` |
| `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` | SHA-256 `7c41296f815b2022b61c18460e9525a0867d05a20482093d5f9daf8e4a11db0a` |
| `docs/SOK-AI-CONTRIBUTED-VULNERABILITIES-2025-2026.md` | SHA-256 `39aadfe41a9a9b5f514b3a384ea2bd505b0898606c5c8f140ebcf8af85408f20` |
| `strict-ledger-union-v2/ledger.jsonl` | SHA-256 `282d2975d0ee24e9949cc4d108ad5a1ffd9b045ad8548cc6b1661aaf2c18392e` |
| `strict-200-v3/ledger.jsonl` | SHA-256 `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81` |
| `strict-audit-20260811/class_adjudications_v4.json` | SHA-256 `af8ac38d9f879130b5067afa63a4ee208c9571fbe9c8ddb937699e51c77a5abe` |
| `openclaw-blame-screen-v3/exact-direct-candidates.jsonl` | SHA-256 `a65921693400bb29fef202cfeb34944dbb85981bb11aca1d29f23c43c2fd2576` |
| `openclaw-exact-review-deepseek-v2/results.jsonl` | SHA-256 `553c2c3edf383041508878b8edb306e561dd67d12bc03df643358e65379b003b` |
| first-party advisory API snapshot `current-advisories.json` | SHA-256 `7512d9eb04a6533188fc23a33f39651b97885225902aac26348ab65589a3a35b` |
| first-party advisory paginated response `current-advisories-pages.json` | SHA-256 `8435983cb7b4954dd5bb0427bc553feb9691de6813c1622cf8340815088fc8e0` |
| read-only Git clone | `/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`; `origin/main=fb9a62e9956883c1b0aed5fa742d6e527cb9e86d` |

The advisory snapshot contains 647 records, all `state=published`, all `withdrawn_at=null`; publication dates span `2026-01-31T08:52:50Z` through `2026-06-30T01:11:32Z`.

## Frozen exclusions before discovery

The closure document freezes 15 GHSA identities, its nine accepted components, its three rejected edges, every full candidate/member/carrier/fix SHA printed there, and the described mechanism fingerprints. I did not re-adjudicate them.

Intersecting the 647 first-party advisory identities with the frozen `strict-200-v3` ledger yields **37 existing OpenClaw rows / 74 public IDs / 25 distinct candidate SHAs / 10 carrier SHAs / 36 fix SHAs**. Those exact ledger edges and their mechanisms were excluded by content hash, not by a hand-maintained partial list. The existing 156-row strict audit was also excluded by `class_id` regardless of verdict. This retains its FAIL and NEEDS_REVIEW rows as prior adjudications rather than recycling them.

After those exclusions, the exact-blame routing artifact has 17 rows in 15 classes. Exact blame remains discovery evidence only. Nine are replayed below. A tenth, separately high-voted routing result, is included as a negative control because it demonstrates a public-advisory/fix identity mismatch.

## Primary sources and exact read-only commands

Primary sources were the first-party repository advisory API, first-party pull API, and the frozen first-party Git object/tag database. Model results and blame packets were used only to find routes.

```zsh
# Advisory snapshot census and row lookup
jq '{total:length,states:(group_by(.state)|map({key:.[0].state,value:length})|from_entries),withdrawn:([.[]|select(.withdrawn_at!=null)]|length)}' \
  autoresearch/herdr-260812-openclaw-tail/current-advisories.json
jq '.[] | select((.ghsa_id|ascii_downcase)=="ghsa-2ww6-868g-2c56")' \
  autoresearch/herdr-260812-openclaw-tail/current-advisories.json

# Public advisory's referenced PR and its only member
gh api repos/openclaw/openclaw/pulls/24140 --jq \
  '{state,merged_at,merge_commit_sha,title,html_url}'
gh api --paginate 'repos/openclaw/openclaw/pulls/24140/commits?per_page=100' \
  --jq '.[] | [.sha,.commit.author.date,.commit.author.name,.commit.message] | @tsv'

# Atomic attribution/delta, reversal, paths, and release entry
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  show --format=fuller <candidate>^..<candidate>
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  show --format=fuller <fix>
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  show --format='%H %s' --name-only --no-renames <candidate> <fix>
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  tag --contains <sha> --sort=version:refname 'v2026.*'

# Locate the actual MIME-type fix set for GHSA-2WW6, rather than the routed gallery fix
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  log origin/main -S'sanitizeImageMimeType' \
  --format='%H %ad %s' --date=iso-strict -- \
  src/auto-reply/reply/export-html/template.js
```

## Row-level adjudication

`First tag` means the first stable `v2026.X.Y`/hotfix tag containing that SHA. It proves release entry only. It is not treated as the first vulnerable version unless the same first-party advisory and mechanism establish that lower bound.

| # | Public identity and routed edge | Topology / release evidence | Same-mechanism and but-for result | Verdict |
|---:|---|---|---|---|
| 1 | [GHSA-354R-7MFH-7RH2](https://github.com/openclaw/openclaw/security/advisories/GHSA-354r-7mfh-7rh2), routed [`5aed38ee`](https://github.com/openclaw/openclaw/commit/5aed38eebc09cd370d1529554a2eaf0e2d53111d) -> [`aedf62ac`](https://github.com/openclaw/openclaw/commit/aedf62ac7e669a89c7b299201bf6537dc6b12e0e) | Both are direct mainline commits; first tags `v2026.1.20` and `v2026.2.25`. Advisory range is `<=2026.2.24`, patched `>=2026.2.25`; first vulnerable release is not stated, so remains `UNKNOWN`. | Candidate hardens guild/thread reaction allowlisting and still executes `if (!data.guild_id) return`; it therefore excludes Discord DMs entirely. The later fix newly admits/checks DM and group-DM reactions with `dmPolicy`, pairing store, and `allowFrom`. Candidate cannot create the missing-DM-auth path. | **FAIL `NO_BUT_FOR`; no positive.** This is not incomplete hardening of the affected DM path because that path is absent in candidate delta. |
| 2 | [GHSA-53VX-PMQW-863C](https://github.com/openclaw/openclaw/security/advisories/GHSA-53vx-pmqw-863c), routed [`f9c220e2`](https://github.com/openclaw/openclaw/commit/f9c220e2613134c3fad6907dc11746cc6a791ef6) -> [`7eecfa41`](https://github.com/openclaw/openclaw/commit/7eecfa411df3d12e6b810e6ca5df47254fc3db3f) | Direct commits; first tags `v2026.3.8` and `v2026.4.14`. Advisory says `<2026.4.14`, fixed `>=2026.4.14`; lower bound `UNKNOWN`. | Candidate changes only browser documentation and tests. It adds no production SSRF-policy default or navigation path. It is also adjacent to the already-frozen Browserbase/DNS-split mechanism, so it is excluded at both production-delta and known-mechanism gates. | **FAIL `TEST_DOC_ONLY` / known mechanism.** |
| 3 | [GHSA-R54R-WMMQ-MH84](https://github.com/openclaw/openclaw/security/advisories/GHSA-r54r-wmmq-mh84), routed [`f5c2be19`](https://github.com/openclaw/openclaw/commit/f5c2be19105d2dd2429ce073dfb07c1a8806e03c) -> [`7dac9b05`](https://github.com/openclaw/openclaw/commit/7dac9b05dd9d38dd3929637f26fa356fd8bdd107) | Direct commits; first tags `v2026.3.1`, `v2026.3.2`. Advisory says `<=2026.3.1`, fixed `>=2026.3.2`; it does not establish the first vulnerable release. | Candidate only gives existing root-containment failures a distinct `outside-workspace` error code and maps that error for callers. It does not add archive extraction, a validate/write gap, or a symlink-rebind window. The fix changes `archive.ts` and race-safe write mechanics; shared `fs-safe` tests are routing noise. | **FAIL `DIFFERENT_PREDICATE`.** |
| 4 | [GHSA-RM59-992W-X2MV](https://github.com/openclaw/openclaw/security/advisories/GHSA-rm59-992w-x2mv), routed [`e707c97c`](https://github.com/openclaw/openclaw/commit/e707c97ca6cc6873511c695ecbb94b7eba96f5a2) -> [`651dc745`](https://github.com/openclaw/openclaw/commit/651dc7450b68a5396a009db78ef9382633707ead) | Direct commits; first tags `v2026.3.2`, `v2026.3.22`. Advisory says `<2026.3.22`, fixed `>=2026.3.22`; first vulnerable release `UNKNOWN`. | Candidate adds idempotent webhook-server lifecycle and cleanup after startup failures to prevent `EADDRINUSE`. It does not alter request-body buffering, signature-check order, body budgets, or pre-auth concurrency. The later fix adds those pre-auth guards. Shared `webhook.ts`/test paths do not bridge the mechanisms. | **FAIL `DIFFERENT_PREDICATE`.** |
| 5 | [GHSA-G86V-F9QV-RH6M](https://github.com/openclaw/openclaw/security/advisories/GHSA-g86v-f9qv-rh6m), routed [`dd9ba974`](https://github.com/openclaw/openclaw/commit/dd9ba974d0353adb5d35722d936a35724f0bb5a5) -> [`d61f8e56`](https://github.com/openclaw/openclaw/commit/d61f8e56723e03573b847422468d99c44c26e34f) | Direct commits; first tags `v2026.2.24`, `v2026.3.28`. Advisory says `<=2026.3.24`, fixed `>=2026.3.28`; lower bound `UNKNOWN`. | Candidate sorts already-approved DNS answers IPv4-first to improve reachability on IPv6-broken hosts. It does not classify any address public/private and neither adds nor removes the missing special-use ranges. Fix adds the actual IPv6 range blocks. | **FAIL `NO_CLASSIFIER_DELTA`.** Same file is insufficient. |
| 6 | [GHSA-39MP-545Q-W789](https://github.com/openclaw/openclaw/security/advisories/GHSA-39mp-545q-w789), routed [`29c5ed54`](https://github.com/openclaw/openclaw/commit/29c5ed54b276e8e65e2e894d0d29cc5ccbbadddd) -> purported fix [`ea018a68`](https://github.com/openclaw/openclaw/commit/ea018a68ccb92dbc735bc1df9880d5c95c63ca35) | Candidate first tag `v2026.1.8`; `ea018a68` first tag `v2026.1.14-1`. The first-party advisory explicitly identifies `ea018a68` as the earliest released vulnerable handler/history point, not containment, and says actual containment is release `2026.3.24`. | Candidate only keeps a typing indicator alive on tool-start events. It does not touch `/send`, `senderIsOwner`, general command authorization, or `sendPolicy`. The routed “fix” is directionally reversed: it is vulnerable-code introduction/refactor evidence. | **FAIL `WRONG_FIX_IDENTITY` + `UNRELATED_CANDIDATE`.** |
| 7 | [GHSA-4RQQ-W8V4-7P47](https://github.com/openclaw/openclaw/security/advisories/GHSA-4rqq-w8v4-7p47), routed [`ebfeb7a6`](https://github.com/openclaw/openclaw/commit/ebfeb7a6bf533b733d2a08a527dc77f4ae793900) -> [`333fbb86`](https://github.com/openclaw/openclaw/commit/333fbb86347998526dd514290adfd5f727caa6d9) | Direct commits; first tags `v2026.1.20`, `v2026.2.22`. Advisory says `<=2026.2.21-2`, fixed `>=2026.2.22`; first vulnerable release `UNKNOWN`. | Candidate adds the vector-memory plugin and hook infrastructure. Its only intersection with the net refactor is `pnpm-lock.yaml`; it does not change `isPrivateIpv4`, special-use ranges, or web-fetch SSRF. | **FAIL `LOCKFILE_ONLY`.** |
| 8 | [GHSA-Q3JJ-46PQ-826R](https://github.com/openclaw/openclaw/security/advisories/GHSA-q3jj-46pq-826r), routed [`5a3a448b`](https://github.com/openclaw/openclaw/commit/5a3a448bc48dc9e72530b46195476a48845bb8da) -> [`31160dc0`](https://github.com/openclaw/openclaw/commit/31160dc069b7cc5d833b39c53736a41ad3befda2) | Direct commits; first tags `v2026.2.17`, `v2026.4.22`. Advisory says `<=2026.4.21`, fixed `2026.4.22`; lower bound `UNKNOWN`. No squash carrier is involved. | Candidate extracts already-existing `sessions_spawn` logic into `subagent-spawn.ts` and adds an owner command caller. It does not add `acp-spawn.ts` or an ACP child-session path. The fix adds the ACP envelope propagation and capability model; a four-line shared-file overlap does not make the earlier extraction a but-for cause. | **FAIL `COMPOSITION_NOT_BUT_FOR`.** This is the explicit compositional negative control. |
| 9 | [GHSA-MR34-9552-QR95](https://github.com/openclaw/openclaw/security/advisories/GHSA-mr34-9552-qr95), routed [`83825933`](https://github.com/openclaw/openclaw/commit/838259331f84237e2b538fae2473d2d88782d587) -> [`52ef4230`](https://github.com/openclaw/openclaw/commit/52ef42302ead9e183e6c8810e0a04ee4ef8ae9fc) | Direct commits; first tags `v2026.2.17`, `v2026.4.15`. Advisory explicitly starts at `>=2026.4.7` and is fixed in `2026.4.15`; candidate predates the vulnerable lower bound by many releases. | Candidate adds Discord messaging-tool media de-duplication and associated tracking types. It does not add client tool definitions, normalized-name collision handling, or the trusted local `MEDIA:` raw-name decision fixed later. Its ancestry/type blame cannot explain a vulnerability whose first-party affected range begins at 4.7. | **FAIL `PREDATES_AFFECTED_SURFACE` / known media-containment family.** |
| 10 | [GHSA-2WW6-868G-2C56](https://github.com/openclaw/openclaw/security/advisories/GHSA-2ww6-868g-2c56), diagnostic route [`6ac1c1d6`](https://github.com/openclaw/openclaw/commit/6ac1c1d6ea0359069cf8d4c6e73ea20c0dad54e2) -> [`f3adf142`](https://github.com/openclaw/openclaw/commit/f3adf142c195000cbde31200626a1d8c8b716df9) | Both direct commits; first tags `v2026.1.15`, `v2026.2.23`. The advisory is published/non-withdrawn and says patched `>=2026.2.23`. Its referenced PR [#24140](https://github.com/openclaw/openclaw/pull/24140) is closed/unmerged; member `d93d22fc…` did not land. Mainline containment is [`f8524ec7`](https://github.com/openclaw/openclaw/commit/f8524ec77a3999d573e6c6b8a5055bf35c49a2e6) plus [`e578521e`](https://github.com/openclaw/openclaw/commit/e578521ef4930d02c573fa2d9ef72c4317a34dd6), both first in `v2026.2.23`. | Advisory mechanism is unvalidated `img.mimeType` in `src/auto-reply/reply/export-html/template.js`. Candidate and routed fix affect only `skills/openai-image-gen/scripts/gen.py`: user-selected filename extension reaching an unescaped gallery attribute, then gallery escaping. That may be a separate real hardening, but no first-party advisory in the 647-record snapshot identifies it; it cannot borrow GHSA-2WW6 identity. | **FAIL `PUBLIC_ID/FIX_MECHANISM_MISMATCH`.** This is a negative control against promoting an 8-vote model route. |

## Preserved UNKNOWN routes

The following exact-blame rows survived the ledger/closure/manual-adjudication exclusion but were not independently replayed within this shard. They remain diagnostic `UNKNOWN`, not negatives or positives:

```text
CVE-2026-28446 / GHSA-4RJ2-GPMH-QQ5X  8b4696c0 -> f8dfd034
CVE-2026-32899 / GHSA-RM2P-J3R7-4X4J  5aed38ee -> aedf62ac
CVE-2026-32062 / GHSA-MFG5-7Q5G-F37J  8b4696c0 -> 1d8968c8
CVE-2026-28465 / GHSA-3M3Q-X3GJ-F79X  8b4696c0 -> a749db98
CVE-2026-28465 / GHSA-3M3Q-X3GJ-F79X  b9643ad6 -> a749db98
CVE-2026-26319 / GHSA-4HG8-92X6-H2F3  8b4696c0 -> 29b587e7
CVE-2026-27670 / GHSA-2G8C-6QFQ-528M  f5c2be19 -> 7dac9b05
CVE-2026-26326 / GHSA-8MH7-PHF8-XGFM  5af322f7 -> d3428053
```

Some share a candidate/fix with a replayed negative, but their public identities and predicates were not assumed aliases. They need their own first-party identity/mechanism check before any final label.

## Claim boundary

- **New positives: 0.** No row here may increase the strict component count.
- Tags establish shipped topology, not causality. For rows whose advisory gives only an upper bound, `first released vulnerable version` stays `UNKNOWN`; candidate first-tag was not substituted.
- Direct commit trailers establish first-party commit-level AI attribution only. They do not prove line-level generation.
- Blame hits, shared paths, model votes, ancestor relations, and matching patched-version dates were used only to route work.
- The closed/unmerged PR #24140 member is negative topology evidence. Its mechanism entered main via a different two-commit fix set; the erased/unlanded member is not a released fix.
- Incomplete or adjacent hardening was not promoted. Same-file security work (DNS ordering versus range classification; lifecycle cleanup versus pre-auth body guards) remains negative unless candidate delta and reversal share the exact predicate.
- The source API itself currently exposes `cve_id=null` for most rows above even where routing artifacts carry a CVE. GHSA identity is therefore the first-party repository-advisory anchor used here; routing CVE strings were not treated as authoritative aliases.
