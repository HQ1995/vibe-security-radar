# Provisional closure audit — shard 03

Scope: `GHSA-V52W-28XH-V562`, `GHSA-W9RM-VVQP-QQ3H`,
`CVE-2026-45582`, `GHSA-WXW3-Q3M9-C3JR`, `CVE-2026-46383`,
`GHSA-64VR-4GR2-M642`, `CVE-2026-2393`, and `CVE-2026-42278`.
This is a replay report only; it does not modify the ledger, generated data, or
publisher inputs.

## Decision rule

I read `docs/AUDIT-PROTOCOL.md` in full and applied its vulnerability-first,
smallest-BIC rule. A PR member that first wrote the vulnerable lines takes
precedence over a squash or later move; an AI marker must be on that BIC. The
gate order below is always:

`identity, ai_hunk, topology, but_for, fix_reversal, release, uniqueness`.

`NARROW` is deliberate where the complete code interval is known but no
vulnerable tagged release, or no same-line patched release, exists. It must not
be widened to `PASS` merely to remove a provisional label.

## Result summary

| Case | Recommended gates | Decision |
|---|---|---|
| `GHSA-V52W-28XH-V562` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` |
| `GHSA-W9RM-VVQP-QQ3H` | `PASS, PASS, PASS, PASS, PASS, NARROW, PASS` | `READY_TO_BACKFILL` — development-only interval |
| `CVE-2026-45582` | `PASS, FAIL, PASS, PASS, PASS, PASS, PASS` | `NOT_AI_REVIEW` |
| `GHSA-WXW3-Q3M9-C3JR` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` |
| `CVE-2026-46383` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` |
| `GHSA-64VR-4GR2-M642` | `PASS, PASS, PASS, PASS, PASS, NARROW, PASS` | `READY_TO_BACKFILL` — affected v2 line is unpatched; v3 removes the surface |
| `CVE-2026-2393` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` after release correction |
| `CVE-2026-42278` | `PASS, PASS, PASS, PASS, PASS, NARROW, PASS` | `READY_TO_BACKFILL` — commit interval, no vulnerable tag |

Seven rows can be backfilled with the bounded fields below. `CVE-2026-45582`
must leave the AI catalog through the normal `NOT_AI` ledger transaction; its
real, human-authored vulnerability lifecycle is fully closed.

## Case findings

### GHSA-V52W-28XH-V562 — complete, narrowly scoped bundled advisory

Recommended objects:

- candidate `4f86724bd112b07e68033098562c1c4ddc37d93b`, parent
  `c84c70c7088f70718a5411d4ef20fabbfe3a429c`;
- main-line carrier `bc9dc69d62aaa567a2ccefee12d28a58b96d96c4`;
- minimum fix `7c3ae2e3b7c996571acc07c96222b6dc2de01a3e`;
- vulnerable release `1.8.0`, fixed release `1.8.1`.

The one-member PR #20 commit has a Claude Opus 4.7 trailer and adds the MCP
HTTP server from an absent parent: no `Host`/`Origin` validation and an
unbounded body accumulator. The squash carrier preserves the same file blob.
The fix adds both guards, and git plus npm artifacts witness the unguarded
1.8.0 and guarded 1.8.1 boundary.

Required fields: add the real GHSA to `advisory_ids`, add `carrier_set`, set
`fixed_release=1.8.1`, and add a `scope_statement` that counts only advisory
issues 1 and 2 on the MCP HTTP surface. Explicitly exclude issue 3 (read-only
transactions), issue 4 (compose/network exposure), and the separate REST body
cap.

Primary sources: [reviewed advisory](https://github.com/advisories/GHSA-v52w-28xh-v562),
[atomic member](https://github.com/kozou-dev/kozou/commit/4f86724bd112b07e68033098562c1c4ddc37d93b),
[carrier](https://github.com/kozou-dev/kozou/commit/bc9dc69d62aaa567a2ccefee12d28a58b96d96c4),
and [fix](https://github.com/kozou-dev/kozou/commit/7c3ae2e3b7c996571acc07c96222b6dc2de01a3e).

### GHSA-W9RM-VVQP-QQ3H — complete development-only XSS interval

Recommended objects:

- candidate `5a4344884f93337a52d0abee1014edade3ed96e6`, parent
  `4bf6b9b90e20fbf9d9c3ebf4d7bcfb9534171858`;
- fix `cf42409badc27b13d9bb644b9175aa7f27e11259`, parent
  `898f8a1e56ee90afcc64fc17b8cdc2f019915c55`;
- no vulnerable released version.

The Claude Sonnet 4.6-marked BIC writes notification messages through
`innerHTML`; the fix rebuilds nodes and assigns the message with
`textContent`. The CVE record is `PUBLISHED` and explicitly says the flaw was
only on a development branch. Git confirms `v1.2` contains neither commit,
while the first later tag, `v1.3` (`ecd04d494b0fda2ab39fb56472785388c2d5872e`),
contains both. `v1.4` is therefore not the first fixed release and `v1.3` was
never a vulnerable released artifact.

Required fields: delete the false `<=1.3` / fixed `1.4` pair. Encode a
development commit interval from the BIC through `cf42409^`, set
`vulnerable_release=null`, and record `v1.3` only as
`first_release_containing_fix`, not as an affected-to-fixed transition. Add
`GHSA-W9RM-VVQP-QQ3H` and `CVE-2026-9806` to `advisory_ids`.

Primary sources: [published advisory](https://github.com/advisories/GHSA-w9rm-vvqp-qq3h),
[BIC](https://github.com/MISP/cti-transmute/commit/5a4344884f93337a52d0abee1014edade3ed96e6),
and [fix](https://github.com/MISP/cti-transmute/commit/cf42409badc27b13d9bb644b9175aa7f27e11259).

### CVE-2026-45582 — closed human origin; remove AI attribution

Recommended objects:

- human introducer `5960d2826eb23e87ed142b3a88cf5d8ac0eddc42`, parent
  `78abda601ab0c34fb60cb760ed18a2fa5ae3c232`;
- fix `6cf6fef653fcd6d598f2f356aac4754931c7329f`;
- vulnerable `<2.51.3`, fixed `2.51.3`.

The real BIC adds `src/telemetry/workflow-sanitizer.ts` and the partial
URL-field redaction. It is authored by the maintainer and has no AI marker.
The currently attributed Claude-marked `47510ef6...` changes Tool variants
and does not touch the sanitizer. The direct fix fully redacts URL-like fields.
Thus `ai_hunk=FAIL`; after replacing the stale candidate, the factual topology,
but-for, fix, release, and uniqueness gates are closed rather than unknown.

Required fields: set the ledger disposition to `NOT_AI`, clear AI
`candidate_set`/marker fields, record `introducer_sha=5960d282...` and its
parent, retain the existing fix/release boundary, and add both
`CVE-2026-45582` and `GHSA-F3RG-XQJJ-CJ9W`. Remove the case from AI publication
only through that ledger transaction.

Primary sources: [reviewed advisory](https://github.com/advisories/GHSA-f3rg-xqjj-cj9w),
[human BIC](https://github.com/czlonkowski/n8n-mcp/commit/5960d2826eb23e87ed142b3a88cf5d8ac0eddc42),
and [fix](https://github.com/czlonkowski/n8n-mcp/commit/6cf6fef653fcd6d598f2f356aac4754931c7329f).

### GHSA-WXW3-Q3M9-C3JR — complete direct OAuth-state origin

Recommended objects:

- candidate `b5f3bad633d8ae79fd5ffbb35ec2a39afdfc2f5e`, parent
  `3a3434b403187ddace8cf35a1ee6ae88aeb11377`;
- fix `9deb7936aba7931f2db4b460141f476508f11bfd`;
- vulnerable `<1.6.2`, fixed `1.6.2`.

The Copilot-marked BIC creates cookie-backed OAuth state storage but does not
bind the callback's `state` to a stored nonce. The fix stores `oauthState` and
compares it during parsing. The advisory's necessary conditions remain part of
the claim: cookie state storage plus a provider path without effective PKCE
verification.

Required fields: change `contribution_class` from
`AI_NEW_SURFACE_CONTRIBUTOR` to `AI_DIRECT_ROOT`, add the real GHSA ID, retain
the candidate/fix and release range, and remove any stale Cursor/move-origin
narrative.

Primary sources: [first-party advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-wxw3-q3m9-c3jr),
[BIC](https://github.com/better-auth/better-auth/commit/b5f3bad633d8ae79fd5ffbb35ec2a39afdfc2f5e),
and [fix](https://github.com/better-auth/better-auth/commit/9deb7936aba7931f2db4b460141f476508f11bfd).

### CVE-2026-46383 — original Copilot member recovered

Recommended objects:

- atomic candidate `d6f919476feab3ddbf6ad76c9cf0afb0c5ea8248`, parent
  `c17b1ac1a4a969b8147ff85d9a1e88a5bb9d21a2`;
- same-tree main-line carrier `1162240afafb0c9af8f0c5cf0ad8c5cb467e9e98`,
  parent `6c99c5b0b19bf74d85bad2d97185a62b6b199050`;
- fix `77d1dda8303c8d7ccb6148788a6274fdece98499`;
- vulnerable `<=0.12.4`, fixed `0.13.0`.

PR #1099's last member is authored and committed by
`Copilot <copilot-rework@github.com>`. It adds
`_looks_like_legacy_apm_bundle()` with raw `tar.extractall(tmp)` on Python
3.10/3.11 after checking only links. The carrier's tree exactly equals that PR
head. The fix adds Windows-drive/absolute-path and normalized traversal checks.
Tag ancestry confirms carrier-without-fix at `v0.12.4` and both at `v0.13.0`.

Required fields: replace unrelated later candidate `491c9da0...` with
`d6f919...`, add `116224...` as carrier, retain `77d1dda...`, add
`GHSA-MQ5J-PW29-JCV3`, and keep `AI_DIRECT_ROOT`. Do not fall back to the
earlier generic unpacker or to the main-line squash as the BIC.

Primary sources: [reviewed advisory](https://github.com/advisories/GHSA-mq5j-pw29-jcv3),
[Copilot-authored PR member](https://github.com/microsoft/apm/commit/d6f919476feab3ddbf6ad76c9cf0afb0c5ea8248),
[carrier](https://github.com/microsoft/apm/commit/1162240afafb0c9af8f0c5cf0ad8c5cb467e9e98),
and [fix](https://github.com/microsoft/apm/commit/77d1dda8303c8d7ccb6148788a6274fdece98499).

### GHSA-64VR-4GR2-M642 — original member and successor closure recovered

Recommended objects:

- atomic PR #462 member `5f71e9ece07d9a85655f18fb8b4aa92b9d217408`,
  parent `28d808469cfb6d6bd7d52ccaa7761d4b44042e84`;
- main-line carrier `32230bc7acff055a089eaf682d6717ca945b6c7d`;
- closure `21de369a5819931d2ad4e88fb71c3baa7524066f` against first parent
  `32bab6ae1a82981d40fe01905398117de18d8a39`;
- vulnerable release `2.5.27`; no patched v2 release; first successor tag
  containing the removal is `v3.260302.2`.

The Automagik Genie-coauthored member first adds
`readTranscriptFromCommit()` and interpolates externally influenced `gitDir`
and `commitSha` into `execSync`. Its parent lacks the function, and the exact
hunk survives in the squash carrier and `v2.5.27`. Current alleged fix
`066b31ef...` changes README/agent material only. The v3 promotion merge
removes the v2 MCP module entirely: its first parent contains the function and
the merge result does not.

Required fields: move `32230bc...` from candidate to carrier; set the atomic
candidate to `5f71e9...`; replace `066b31...` with closure `21de369...`.
Preserve the advisory truth `patched_versions=None`: set
`fixed_release=null` for the affected v2 line and record a separate
`successor_closure_release=v3.260302.2`. Never display `2.5.27` as both
vulnerable and fixed.

Primary sources: [reviewed advisory](https://github.com/advisories/GHSA-64vr-4gr2-m642),
[atomic member](https://github.com/automagik-dev/genie/commit/5f71e9ece07d9a85655f18fb8b4aa92b9d217408),
[carrier](https://github.com/automagik-dev/genie/commit/32230bc7acff055a089eaf682d6717ca945b6c7d),
and [successor closure](https://github.com/automagik-dev/genie/commit/21de369a5819931d2ad4e88fb71c3baa7524066f).

### CVE-2026-2393 — atomic Claude member plus corrected package boundary

Recommended objects:

- atomic PR #16583 member `42a1acb091e737e457fbafb21c4abbe2214f01fe`,
  parent `781f9608bd5d074568c477a324adf604b79ae72c`;
- main-line squash carrier `3094ab608b1d91bff5830d5a89aa042ccd3c9acc`,
  parent `4a724addefd1950a43b62eb4c89894b4e75e01c6`;
- release-branch fix `fec1670e7edbd5e7f97087a5299feb3c634826e4`
  and main-line equivalent `64aa0ab7207f9c649b59ba1a5f40d82196817389`;
- verified stable affected window `>=3.8.0,<3.10.0`, fixed `3.10.0`.

The Claude-coauthored member—not the later `delivery.py` rename and not the
current `2e0adc...` aggregate—first adds
`requests.post(webhook.url, ...)` without destination validation. The two fix
commits produce the same `delivery.py` blob and add `_validate_webhook_url`
before the request.

The reviewed advisory's `<3.9.0` / fixed `3.9.0` metadata contradicts the
released artifacts. The PyPI 3.9.0 sdist (SHA-256
`47a41fa22107b0ceee1f91e2184759ebfaffa31d7913b70318b78fb5369e52ec`)
still posts directly and contains no validator. The 3.10.0 sdist (SHA-256
`54a6e18100623855d5d2a5b22fdec4a929543088adee49ca164d72439fdce2e3`)
imports and calls the validator. Git tags agree: v3.8.0/v3.8.1/v3.9.0 are
unguarded; v3.10.0 contains the backport.

Required fields: replace `2e0adc...` with atomic candidate `42a1ac...`, add
carrier `3094ab...`, record both equivalent fix edges, and override the stale
advisory range with the artifact-proven `>=3.8.0,<3.10.0` / `3.10.0`. Add
`GHSA-65H7-C7C4-MGHX` to the identifiers and retain a note about the upstream
metadata discrepancy.

Primary sources: [reviewed advisory](https://github.com/advisories/GHSA-65h7-c7c4-mghx),
[atomic member](https://github.com/mlflow/mlflow/commit/42a1acb091e737e457fbafb21c4abbe2214f01fe),
[carrier](https://github.com/mlflow/mlflow/commit/3094ab608b1d91bff5830d5a89aa042ccd3c9acc),
[release backport](https://github.com/mlflow/mlflow/commit/fec1670e7edbd5e7f97087a5299feb3c634826e4),
[main fix](https://github.com/mlflow/mlflow/commit/64aa0ab7207f9c649b59ba1a5f40d82196817389),
[PyPI 3.9.0](https://pypi.org/project/mlflow/3.9.0/), and
[PyPI 3.10.0](https://pypi.org/project/mlflow/3.10.0/).

### CVE-2026-42278 — complete compositional chain, deleted upstream

Recommended objects:

- AI contributor `8f000e9403a33c693eeb630771bc3d4846473991`, parent
  `6462f64ec2af07129bdd6aade7a3653eb133b39f`;
- human exploit-completing contributor
  `c21e8dcd5281cb4b0fda21529ed74ba46e62d873`, parent
  `07be2e9a89fa8927164dbc64dc0579b86e232a82`;
- fix `fb6ef59d6c1385400e7acea7ae31fc6a473c3051`, parent
  `3a270467fa8d99cbe7f700d661147ce4d11552f8`;
- vulnerable commit interval from `c21e8d...` through `fb6ef59^`; no tagged
  vulnerable release.

The Claude Opus 4.6-marked SmartAccount commit creates
`check_spending_policy()` with a no-config fallthrough. The later human pocket
commit makes pocket addresses authenticate through a parent but continues to
look up policy by the raw pocket address, completing the bypass. The fix
resolves pocket to parent before policy and per-key-limit accounting. This is
`AI_CODE_FLAWED`, not an AI-sole-root claim.

Required fields: retain candidate `8f000e...`, explicitly record human causal
contributor `c21e8d...`, and retain fix `fb6ef59...`. Replace the meaningless
`>=0` release range with the exact git interval and `no_vulnerable_tag=true`.
Set the clone source to
`.ai-slop/state/legacy87/clones/UltraDAGcom_core`. All repository and code
evidence URLs must name `UltraDAGcom/core`; do not substitute the reporter's
fork. Because the upstream repository is now deleted, set a code-source
availability note, not an `original_sha` unresolved reason—the three objects
are present and verified in the local Git object store.

Primary sources: [published CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-42278),
[first-party advisory URL](https://github.com/UltraDAGcom/core/security/advisories/GHSA-9chc-gjfr-6hrq),
[AI contributor](https://github.com/UltraDAGcom/core/commit/8f000e9403a33c693eeb630771bc3d4846473991),
[human contributor](https://github.com/UltraDAGcom/core/commit/c21e8dcd5281cb4b0fda21529ed74ba46e62d873),
and [fix](https://github.com/UltraDAGcom/core/commit/fb6ef59d6c1385400e7acea7ae31fc6a473c3051).

## Backfill boundary

- Backfill the seven `READY_TO_BACKFILL` rows only with the exact candidates,
  carriers, fixes, ranges, and bounded `NARROW` release statements above.
- Route `CVE-2026-45582` through `NOT_AI_REVIEW`; do not merely hide its
  uncertainty banner while retaining the false AI candidate.
- Preserve the upstream contradictions for W9, 64VR, and 2393 as explicit
  structured notes. They are resolved evidence boundaries, not reasons to
  invent a vulnerable release or a nonexistent patch.
