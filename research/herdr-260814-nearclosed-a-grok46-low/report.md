# Near-closed released wave A (fp211 ordinals 10, 21, 25)

Verdict first: **1 PASS proposal** (ordinal 21). Two NARROW (ordinals 10 and 25). 0 REJECT. 0 UNKNOWN. 0 BLOCKED.

Assigned 3, reviewed 3, unreviewed 0. Conservation 3=2+1. Worker PASS is a proposal only. Canonical88 remains 88 HOLD. Packet delta 0 until leader admission. Publication and greater-than-200 stay HOLD. This packet does not rebuild the strict-released ledger.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical88 summary SHA-256 `81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921`. Ledger SHA-256 `35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074`. fp211 public_cases.jsonl SHA-256 `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`. Shared tracked files and canonical ledgers were not edited. No commit, push, or credential output.

## Assignment

Exactly three first-party identities, fp211 ordinals 10, 21, 25. Leader challenge reopened only ordinal 21. Ordinals 10 and 25 are unchanged NARROW. Overlay routing is not truth. All seven contract gates were rebuilt from Git objects, first-party advisories, tags, and NuGet artifacts.

Scoped-contributor rule: PASS when deleting the exact atomic AI change eliminates or materially shrinks a precisely named advisory mechanism, even when an older sibling path remains, and the later minimum fix reverses that exact new surface.

Clones used read-only: `/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/{hermes-webui,sharpcompress,titra}`. NuGet nupkgs were fetched into a replay mktemp and discarded. No owned extras.

## Per case

1. GHSA-5WQV-FHMR-PJGH NARROW identity_gate, but_for_gate, fix_reversal_gate. Unchanged. Unreviewed global GHSA. Claude ee672df46 adds profile= on state.db. Parent already served GET /api/session sidecar IDOR. Closer 2a3baa71 scopes sidecar by-id. Contained in v0.51.442 / fixed v0.51.443.

2. GHSA-6C8G-7P36-R338 PASS_PROPOSAL. All seven gates PASS at the narrowed async scope. Reviewed repo GHSA-6c8g-7p36-r338 names WriteToDirectoryInternal (sync) and WriteToDirectoryAsyncInternal (async). PoC reports both APIs escape on SharpCompress 0.47.4. Parent 3f9986c13 IArchiveExtensions has ExtractToDirectory directory-entry Path.Combine and no archive-level WriteToDirectoryAsync. Parent entry-level WriteToDirectoryAsync already uses ExtractionMethods guards. Copilot 8b95e0a76 first adds archive-level WriteToDirectoryAsync with the uncontained directory-entry combine. Human b501bac54 later moves that branch into IAsyncArchiveExtensions.cs; authorship is not transferred. Closer 2021a066 adds GetFullPath/StartsWith on WriteToDirectoryAsyncInternal. NuGet 0.47.4 nupkg sha256 987d11f9... nuspec commit 5758b082 equals tag 0.47.4; net8.0 dll contains WriteToDirectoryAsyncInternal; git tree at that commit still Path.Combines directory entries. NuGet 0.48.0 nupkg sha256 d8c5da8a... nuspec commit 6e59c7d7 equals tag 0.48.0 and contains the fix. Older sync sibling remaining is allowed.

3. GHSA-PQGX-6WG3-GMVR NARROW but_for_gate. Unchanged. Count squash 67c7b766. Member 40331e610 is not a tag ancestor. Parent already executed unsanitized vm2 NodeVM timeEntryRule. Sandbox replacement without a sanitizer delta. Contained in 0.99.48 / fixed 0.99.49.

## Uniqueness

None of the three IDs is in canonical88 strict_released_case_ids (88). None is GHSA-8RW6-P7M8-63JP. CVE aliases are stored and not counted. Replay uniqueness reads only the pinned canonical88 summary.

## Claim boundary

Countable PASS requires all seven gates PASS plus leader admission. Proposed PASS: 1 (GHSA-6C8G-7P36-R338). Publication remains HOLD. Greater-than-200 remains HOLD. Canonical88 was not rebuilt. Expansion stopped. Did not pad. Did not change ordinals 10 or 25.
