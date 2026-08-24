# Shard 03 adversarial FP audit (ordinals 73–108)

Coverage: exactly 36 canonical COMPONENT_ROW records, ordinals **73–108**.
Verdicts: CONFIRM=3, NARROW=27, FALSE_POSITIVE=5, UNKNOWN=1, BLOCKED=0.
Public cases are counted by verified advisory identity, not by row or mechanism count: prefer a first-party `GHSA-*` as `case_id`; retain a CVE only as a formal alias of that GHSA; merge two GHSAs only with first-party identifier evidence. This shard’s 36 rows are therefore not 36 public cases.
Only CONFIRM/HIGH is claim-grade without another review. Baseline PASS/NARROW/REJECT/UNKNOWN, OSV `introduced`, prior votes, and carrier AI labels were treated as hypotheses.

Owned outputs: `shards/shard-03.jsonl`, `reports/shard-03.md`. Raw clones/pages under `/tmp/fp211-shard-03`. MISP reads used `~/.cache/cve-analyzer/repos/misp_misp` read-only.

## CONFIRM
- **73** AI_DIRECT_ROOT HIGH: A brand-new importer file that documents 'auth is the caller's responsibility' is still AI-direct-root when the CNA names that overwrite path and the atomic fix is the missing org check.
- **76** AI_DIRECT_ROOT HIGH: A Claude commit whose subject is unrelated (logs viewer) can still be the first introduction of the named XSS sink; match the hunk, not the subject.
- **81** AI_DIRECT_ROOT HIGH: When the advisory text quotes the exact token-presence predicate, that sibling of a shared SHA can CONFIRM even if other siblings stay NARROW.

## FALSE_POSITIVE counterexamples
### 75 `not_origin_of_named_mechanism`

- git show c736f11a: +enforceBrowserOriginForAnyClient = hasBrowserOriginHeader && !hasProxyHeaders
- git show 20523b91: trustedProxyAuthOk only; no Origin predicate
- git show ebed3bbd: removes hasProxyHeaders exemption from origin check

Replay:
```
git -C /tmp/fp211-shard-03/clones/openclaw show c736f11a16d6bc27ea62a0fe40fffae4cb071fdb | rg -n hasProxyHeaders
git -C /tmp/fp211-shard-03/clones/openclaw show 20523b918adff4feae378ac9965e204c56b6e3d8 | rg -n trustedProxyAuthOk
git -C /tmp/fp211-shard-03/clones/openclaw show ebed3bbde1a72a1aaa9b87b63b91e7c04a50036b | rg -n hasProxyHeaders
```

### 83 `not_origin_of_named_mechanism`

- routes/api.php parent: Route::post('/projects'...) and Route::post('/servers'...) already api.ability:read
- named GHSA endpoints therefore pre-exist the candidate; deleting 62c394d3 leaves CVE-2026-32718 intact
- no independent git-tag peel for this row's claimed Coolify versions was closed in-shard

Replay:
```
git -C /tmp/fp211-shard-03/clones/coolify grep -n "post('/projects'\|post('/servers'\|servers/{uuid}/validate" 62c394d3a1dba6aa6d4ab1456b7a7911f6b72639^ -- routes/api.php
git -C /tmp/fp211-shard-03/clones/coolify show c15bcd56347fc8c535755791e92e4f6c2af17e3a -- routes/api.php
```

### 89 `unreleased_dangerous_revert`

- git merge-base --is-ancestor 9400eaa9 v2.33.2 -> not ancestor; same tags contain 57b11d40 whenever they contain 9400eaa9

Replay:
```
git -C /tmp/fp211-shard-03/clones/coder log -1 --format='%H %P %ci %s' 9400eaa957fb019b0084bd1c8599ec0f671f17cb
git -C /tmp/fp211-shard-03/clones/coder log -1 --format='%H %P %ci %s' 57b11d405f17492aa789d4b9ff33366f961a37f8
comm -23 <(git -C /tmp/fp211-shard-03/clones/coder tag --contains 9400eaa957fb019b0084bd1c8599ec0f671f17cb | sort) <(git -C /tmp/fp211-shard-03/clones/coder tag --contains 57b11d405f17492aa789d4b9ff33366f961a37f8 | sort)
```

### 90 `not_origin_of_named_mechanism`

- deleting the webhook-retire candidate does not add RelativeURL/Prefix checks; the named CEL/Validate gap pre-existed

Replay:
```
git -C /tmp/fp211-shard-03/clones/fission show c6cd334f008676963c68fc7be7924aa02731e061^:pkg/webhook/httptrigger.go | sed -n '30,40p'
git -C /tmp/fp211-shard-03/clones/fission show 0deed6bf3f26bc0f10e9130cd0d479b0b9f5f609 | sed -n '1,40p'
```

### 94 `old_bug_preserving_refactor`

- Public case_id is only first-party `GHSA-7JM2-G593-4QRC`. `GHSA-9FC9`+`CVE-2026-45001` are an unreviewed wrapper pair, not a first-party alias of 7JM2; they are in `public_ids_remove`.
- GitHub GHSA-7jm2 identifiers contain no CVE and no GHSA-9fc9; merging them would treat same-mechanism/same-fix as alias.
- removing 29f20624 from main leaves parent exec-only PROTECTED_GATEWAY_CONFIG_PATHS; advisory residual (sandbox, plugins, gateway auth/TLS, hooks, MCP, SSRF, fs) remains
- tests deleted in 53764bbb show the member is a simplification of a richer branch-local guard that was never the released mainline denylist

Replay:
```
python3 -c "import json;from pathlib import Path;d=json.loads(Path('/tmp/fp211-shard-03/notes/ghsa_api_identity.json').read_text());
[print(x['ghsa'], x['cve_id'], x['type']) for x in d if x['ghsa'] in ('GHSA-7jm2-g593-4qrc','GHSA-9fc9-8v4x-f5cp')]"
git -C /tmp/fp211-shard-03/clones/openclaw show 29f206243b2d636e10ebf794a27d937d63f04b49^:src/agents/tools/gateway-tool.ts | sed -n '24,32p'
cat /tmp/fp211-shard-03/pages/94-member.json
git -C /tmp/fp211-shard-03/clones/openclaw merge-base --is-ancestor fe30b31a97a917ecc6e92f6c85378b6b20352422 v2026.4.14
```

## NARROW counterexamples (identity/scope/topology/fix-set/release)
### 74 AI_DIRECT_ROOT

CNA-accepted realpath+mode patches can still leave the named arbitrary-file-read invariant open; narrow fix_reversal rather than CONFIRM.

- fix 234d9aad realpathSync-canonicalizes and sets cache 0o600 but does not constrain the path to an allowed root; absolute /etc/passwd still resolves

### 77 AI_NEW_SURFACE_CONTRIBUTOR

When CNA cites two patches, the minimum fix set is the helper that closes UNC/remote file:// plus any caller seams; a new AI caller of a pre-existing loader is contributor-not-origin.

- deleting 8d74578c leaves the shared Windows media loader; candidate is a new caller not the origin of file:// UNC acceptance

### 78 AI_NEW_SURFACE_CONTRIBUTOR

A real AI new surface can still be NARROW when the CNA describes the sibling HTTP discovery hop that the one-line fix never touches.

- reviewed GHSA-F7FH / CVE-2026-43576 impact wording emphasizes /json/version second-hop, which is the unpatched HTTP discovery path; the landed fix is the direct-WS branch

### 79 AI_NEW_SURFACE_CONTRIBUTOR

Same-parent patch-equivalent member/carrier is topology NARROW, not two origins; a new API on a pre-existing unvalidated fragment is contributor-not-origin.

- deleting PrefixSearch leaves the older unvalidated fragment APIs; named SQL-fragment sink is pre-existing

### 80 AI_NEW_SURFACE_CONTRIBUTOR

One AI device-skip commit can feed several later advisories; count the scopes row as a new surface of that skip, not as the origin of scope binding.

- 079af0d0 does not introduce self-declared scopes; it expands who may connect device-less, after which later scope-binding logic is residual

### 82 AI_DIRECT_ROOT

A new AI file can still be direct-root when the unused channel parameter is the named invariant; missing fix blobs and missing fixed tags keep the row NARROW.

- 9b4aff0f exists as a commit but blob 924c1cb0 is missing locally (GIT_NO_LAZY_FETCH); reversal of channel-scoping is from commit message/API, not a fully readable parent blob
- 94e14d9d is a mega v0.3.0 dump (ChannelBridge plus many unrelated files)

### 85 AI_NEW_SURFACE_CONTRIBUTOR

A sticker-only omitted maxBytes argument is a new fetch site, not origin of a multi-channel byte-cap advisory.

- deleting the sticker commit does not close named multi-channel unbounded fetches
- no in-shard git-tag peel for the claimed openclaw media-limit versions

### 86 AI_GUARD_WEAKENING

Nashorn --no-java to GraalJS HostAccess.ALL is guard weakening; keep both deny-list and js.load commits in the minimum fix set.

- parent Python allowAllAccess is out of scope; listed single fix c691e35e is the second hop after 87a7d96a

### 87 AI_NEW_SURFACE_CONTRIBUTOR

A new token API that inherits an old FormRequest is contributor-not-origin of the role-allowlist hole; annotated tags that do not peel to the fix commit leave release UNKNOWN.

- new token Users controllers are a new surface on a shared unvalidated FormRequest; deleting them leaves the session API residual
- git tag peel on the clone failed; GitHub annotated-tag SHAs were not merge-base proven to contain/exclude the fix

### 88 AI_NEW_SURFACE_CONTRIBUTOR

When the fix commit's own message quotes a parent-path PoC, the AI temp/ route is a new startswith surface, not origin of that CVE wording.

- named /music sibling-prefix PoC is the parent path; temp_base is a distinct new surface patched in the same commit

### 91 AI_NEW_SURFACE_CONTRIBUTOR

Adding TypeSymlink without containment is a new extract surface on an already unbounded Join; without local tag objects release stays UNKNOWN.

- parent TypeReg already lacked dest prefix checks; Unzip ZipSlip is not introduced by the symlink member
- fix is multi-purpose (Untar symlink target + Unzip + TypeReg prefix)

### 92 AI_DIRECT_ROOT

When origin/ does not store the PR member, GitHub commit API can still prove AI on the nickname matcher, but topology stays NARROW until the blob is in git.

- member blob not in the local openclaw clone; topology depends on GitHub commit API rather than git cat-file

### 93 AI_DIRECT_ROOT

Thread-root injection without a sender allowlist is a real AI origin; CONFIRM still needs member-vs-carrier blob equality.

- squash carrier vs member blobs were not byte-compared in-shard; topology remains NARROW

### 95 AI_NEW_SURFACE_CONTRIBUTOR

A new exec-event prompt special-case is a contributor on a parent that already scheduled exec-event heartbeats.

- exec-event as a heartbeat reason pre-exists the special-case prompt; this row is the owner-auth inheritance seam on that reason

### 96 AI_NEW_SURFACE_CONTRIBUTOR

Same Synology intro commit can origin an empty-allowlist row and a webhook-path row; they stay distinct iff fixes and invariants differ. Do not treat replaceExistingScope as HTTP replaceExisting.

- member HTTP registerPluginHttpRoute snippet did not pass replaceExisting:true; that token appears in the fix diff and in unrelated supervisor replaceExistingScope
- input release_evidence was null; no in-shard tag peel for CVE-2026-35635 versions

### 97 AI_NEW_SURFACE_CONTRIBUTOR

Do not trust REJECT missing_published_artifact: list tags that contain the carrier without the fix. A new OAuth callback matcher that inherits parent unbound state is contributor-not-origin.

- baseline REJECT missing_published_artifact is false for the carrier: 1.6.0/1.6.1 exist without the cookie fix
- deleting only the generic matcher leaves /callback/:id on the same unbound-nonce helper

### 98 AI_DIRECT_ROOT

Delimiter-free tuple concat is AI-direct-root of the collision; a mega-squash carrier and a still-truncated digest keep the row NARROW.

- mega-squash carrier is not the origin member; official patch still truncates the hash

### 99 AI_DIRECT_ROOT

A Claude-authored new CSV emitter is direct-root of formula injection; missing npm gitHead still blocks CONFIRM on release containment.

- npm packuments 26.5.2 and 26.6.0 have gitHead=null; local actual clone has no 26.5/26.6 tags; artifact-to-commit peel not closed

### 100 AI_NEW_SURFACE_CONTRIBUTOR

An AI env override is a new execution-affecting surface even when sibling selectors and dotenv loading are later; unfetched tags keep release UNKNOWN.

- project-local .env loading is a later independent surface; this row is only the env override selector

### 101 AI_NEW_SURFACE_CONTRIBUTOR

A new PDF force_download branch on a parent that already downloaded ImageUrl is contributor-not-origin of the named SSRF helper.

- public IDs name the shared download_item SSRF helper, not only the new PDF branch

### 102 AI_NEW_SURFACE_CONTRIBUTOR

Enabling a new Compose service without log rotation is a new surface of a parent pattern, not origin of the whole unbounded-logs advisory.

- unbounded docker logs already existed on sibling platform services

### 103 AI_NEW_SURFACE_CONTRIBUTOR

Registering one more unvalidated RPC is a distinct surface; public IDs that name 'the trace APIs' plus a whole-module auth fix stay NARROW.

- row mechanism already says not origin of CVE-2026-8147; deleting BatchGetTraceInfos leaves other unvalidated trace APIs

### 104 AI_NEW_SURFACE_CONTRIBUTOR

One Copilot TS v2 commit can origin three distinct mechanisms; file-resolver is contributor relative to the Python parent.

- Python parent already resolved ${file:...} unbounded; TS runtime is a newly published copy of that sink

### 105 AI_NEW_SURFACE_CONTRIBUTOR

Keep GHSA-W28W and CVE-2026-73299 together but NARROW identity: GitHub reviewed object has cve_id=null while OSV aliases the CVE.

- CNA/OSV extra commits besides 047756f4; GHSA vulnerability ranges also mention <=0.1.4 patched 0.1.5 which this v2 commit does not explain

### 106 AI_DIRECT_ROOT

A v2 loader that newly depends on gray-matter can be direct-root of JS-engine frontmatter even when the engines map is library-default; still NARROW until the default is quoted from the parent blob and a packument peels.

- in-shard grep of loader.ts did not show an explicit engines:{js:...} map; gray-matter default engines are inferred from the fix message rather than a cited default-engine line
- no npm gitHead peel closed for c27402da vs a published @prompty/core version in this shard

### 107 AI_GUARD_WEAKENING

A listed squash carrier that is a later independent Claude PR is topology NARROW, not proof the member reached the tag.

- input origin_kind squash_member is wrong: member is not ancestor of carrier

### 108 AI_DIRECT_ROOT

Always print merge parents of the listed carrier: a 'Merge commit from fork' that includes the fix SHA is not the origin carrier.

- input origin_kind merge_member with carrier=f74174a5 inverts topology: that merge carries the fix, not the origin

## UNKNOWN / BLOCKED
- **84** release_gate=UNKNOWN: claimed artifacts 8.1.2/8.1.3 were not recovered: local taylored tags do not include 8.1.x; ls-remote showed no 8.1 refs

## Ordinal 94 public IDs (identity_relation, keep/remove)

This row is one mechanism-level evidence unit and **one** public case. Two GHSAs are not merged, and the CVE is not attached to 7JM2.

| Public ID | identity_relation | GitHub primary evidence | Disposition |
|---|---|---|---|
| `GHSA-7JM2-G593-4QRC` | `FIRST_PARTY_GHSA_NO_CVE` | reviewed; `identifiers=[{GHSA}]`; `cve_id=null`; `repository_advisory_url` is `openclaw/openclaw`; `nvd_published_at=null` | **keep** — public `case_id` |
| `GHSA-9FC9-8V4X-F5CP` | `UNREVIEWED_CVE_WRAPPER_NOT_FIRST_PARTY_ALIAS` | unreviewed; `repository_advisory_url=null`; `github_reviewed_at=null`; `identifiers` include GHSA-9fc9 **and** CVE-2026-45001; 7JM2 appears only in `references[]`, not in `identifiers` | **remove** — not a proven formal alias or first-party duplicate of 7JM2 |
| `CVE-2026-45001` | `FORMAL_ALIAS_OF_GHSA-9FC9_ONLY` | GitHub `cve_id` on 9FC9; absent from 7JM2 `identifiers` | **remove** — would silently attach a CVE to 7JM2 |

`public_ids_keep=["GHSA-7JM2-G593-4QRC"]`. `public_ids_remove=["CVE-2026-45001","GHSA-9FC9-8V4X-F5CP"]`. Same repository, same fix `fe30b31a`, and similar wording are **not** merge proof. Identity_gate remains **NARROW**. Causal verdict remains **FALSE_POSITIVE** (but-for FAIL: main parent of carrier `29f20624` already had exec-only `PROTECTED_GATEWAY_CONFIG_PATHS`). Member `53764bbb` (missing locally; GitHub API) deletes a richer branch-local fingerprinting guard that v2026.4.12 main did not ship.

Replay for identity objects: `/tmp/fp211-shard-03/pages/GHSA-7jm2-g593-4qrc.api.json` (`identifiers`, `cve_id`) and `/tmp/fp211-shard-03/pages/GHSA-9fc9-8v4x-f5cp.api.json` (`identifiers`, `references`).

## Uniqueness (shared SHAs, distinct mechanisms)

| SHA | Ords | Decision |
|---|---|---|
| `cc048a29` / `03586e3d` | 6 vs **96** | Distinct: empty-allowlist vs inherited webhookPath. |
| `506bed5a` | 9 vs **85** | Distinct: token-in-URL vs omitted maxBytes. |
| `079af0d0` | 15/33/54/**80**/**81** | Distinct fixes/invariants; 81 is direct token-presence, 80 is scopes residual. |
| `57b76343` | 56 vs **84** | Opposite roles: PayPal-body FIX vs token-replay CANDIDATE. |
| `8d74578c` | 60 vs **77** | Distinct: image-tool workspaceOnly vs native media UNC caller. |
| `a0e61088` | **104/105/106** | Distinct TS v2 sinks: file resolver, Nunjucks, gray-matter. |

## Representative replay commands

```bash
# identity
python3 -c "import json;from pathlib import Path;print(Path('/tmp/fp211-shard-03/notes/ghsa_api_identity.json').read_text()[:200])"
git -C /home/hanqing/.cache/cve-analyzer/repos/misp_misp merge-base --is-ancestor 41450bdb5d31ab017e147ccc921951ee6a70e134 v2.5.37
git -C /tmp/fp211-shard-03/clones/openclaw show c736f11a16d6bc27ea62a0fe40fffae4cb071fdb | rg hasProxyHeaders
git -C /tmp/fp211-shard-03/clones/coolify grep -n "post('/projects'" 62c394d3a1dba6aa6d4ab1456b7a7911f6b72639^ -- routes/api.php
comm -23 <(git -C /tmp/fp211-shard-03/clones/coder tag --contains 9400eaa957fb019b0084bd1c8599ec0f671f17cb | sort) <(git -C /tmp/fp211-shard-03/clones/coder tag --contains 57b11d405f17492aa789d4b9ff33366f961a37f8 | sort)
```

## Limitations

- Did not checkout/fetch/modify `~/.cache/cve-analyzer/repos/*`.
- OpenClaw members `ce12b909` and `53764bbb` are absent from the local clone; GitHub commit API pages under `/tmp/fp211-shard-03/pages/` were used.
- Mysti fix blob `924c1cb0` missing locally; ChannelBridge reversal is NARROW.
- Fission, ddev, ouroboros, ironclaw, garminconnect, rconfig: GitHub tag refs exist but several clones lack tag objects, so those release gates stay UNKNOWN rather than inferred PASS.
- `@actual-app/cli` 26.5.2/26.6.0 packuments have `gitHead=null`.
- Row 96 `replaceExisting` HTTP flag was not found on the member register call; uniqueness vs ord 6 still holds via a different fix SHA.
- No BLOCKED row: every missing prerequisite had a safe alternative (GitHub API page, first-party advisory, or explicit UNKNOWN).

## Reusable lessons

1. **Hunk over subject / carrier label.** Logs-viewer commits can introduce XSS; pairing commits can sit next to a human Origin skip.
2. **Named endpoints on the parent are fatal.** Coolify GHSA-f47p lists routes already `ability:read` before the Hetzner commit.
3. **Same SHA ≠ duplicate.** Require distinct source/sink/invariant/fix; 079af0d0 feeds five rows.
4. **Fix commit messages can confess pre-existence.** Fission 0deed6bf says Validate() never checked RelativeURL/Prefix.
5. **Same-day revert+restore on every tag is unreleased.** Coder 9400eaa9 parent of 57b11d40; empty tag delta.
6. **Do not trust REJECT missing_published_artifact.** better-auth 1.6.0/1.6.1 contain the carrier without the cookie fix.
7. **Listed carrier may be the fix merge or a later independent PR.** Garminconnect f74174a5; ironclaw b58b4215.
8. **Public cases follow first-party GHSA identity, not mechanism count.** Two GHSAs merge only when identifiers prove alias/duplicate publication. For 94, keep `GHSA-7JM2` (no CVE); remove unreviewed `GHSA-9FC9`+`CVE-2026-45001` rather than counting a second case or forging an alias.
9. **realpath is not a root jail.** Claude-hud 234d9aa addresses cache mode more than arbitrary read.
10. **Minimum fix set is the helper that closes the invariant**, not the listed candidate_fix_edge (openclaw 4fd7feb0 vs 93880717).
