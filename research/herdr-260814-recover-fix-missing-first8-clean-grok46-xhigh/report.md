# Recover fix_object_missing ranks 1-8 (clean)

REJECT 8. PASS=0. packet_delta=0. Worker PASS is proposal-only; this packet emits none.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.

## Selection

Pinned authoritative 38-ID routing list from `autoresearch/herdr-260814-recover-fix-missing-ranks17-24-grok46-low/result.json` SHA256 `04206ea707bec13f0ec351dc34d95f97b43ec5ce9bf969c71226506f351886e8`. Leader replay of that packet passed. This worker did not inherit any case verdict or causal gate from it.
Source routing packet `herdr-260814-nextqueue-v2-grok46-low` result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` strict 94.
Frozen first-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` committer 2026-08-14T03:33:36+00:00.
Pinned source `fix_object_missing` count is 38. Subtract canonical94, nextqueue queued 20 plus leftover 11, and newer terminal verdicts: overlaps empty, remaining 38. Deterministic uppercase GHSA ID sort. Frozen ranks 1-8 only. Ranks 9-16 are owned by another worker; disjointness is by rank (`remaining[0:8]` vs `remaining[8:16]`), not by reading that worker's files. Ranks 17-24 are `remaining[16:24]`.

Temporary public clones recovered the advisory fix objects anonymously with credential helpers disabled. Shared caches were not mutated. Those objects are routing. All seven exact PASS are mandatory. Prefer zero PASS over one false positive.

## Frozen ranks 1-8

1. GHSA-264V-M8FM-76JM nimiq/core-rs-albatross REJECT ai_hunk FAIL. Closer `6ff0800e8e03` n_parents=1 Jose Daniel Hernandez replaces `assert_eq!(history.len(), positions.len())` with a None return in `history_proof.rs`. No matcher hit. Advisory sha256 `cbb080ce575f6c44c669d51b586c76bee6515082f78e197e91befbd1f6257289`.
2. GHSA-27W2-87XV-37C6 nimiq/core-rs-albatross REJECT ai_hunk FAIL. Closer `807ee8e99a7c` n_parents=1 Jose Daniel Hernandez on `keys/src/tagged_signing.rs`. No matcher hit. Advisory sha256 `71ad1ca13c48f548d3a6d8b5876ba5c4307801ab385132b8d3a16a6acc3b8527`.
3. GHSA-2VQ4-854F-5C72 go-vikunja/vikunja REJECT ai_hunk FAIL and fix_reversal FAIL. Named SHA `c03d682f48af` is test-only `project_test.go` ParadeDB fixture expectation by kolaente, not the `CanUpdate` reparent Admin check. Advisory sha256 `3974b2aa19c16aa8b6c0d69d90acda1f21ce4b3023cec903240a072b3ac34283`.
4. GHSA-36XV-JGW5-4Q75 nestjs/nest REJECT ai_hunk FAIL and topology FAIL. Named closer `83558ae774a9` is a two-parent merge of PR 16686. Atomic patch `0f962c75a474` is human Kamil Mysliwiec sanitizing SSE `message.type`/`id` newlines. Path-limited pre-fix scan of `sse-stream.ts` is empty. Unrelated Claude trailer on injector hang is a sibling field. Advisory sha256 `b36ac94f3e0c91b260df4fcd9e5d8aa8ac27341658a73dbe6cf817b6d5567174`.
5. GHSA-3763-QP59-59VF nimiq/core-rs-albatross REJECT ai_hunk FAIL. Closer `a530b2434ebc` n_parents=1 viquezclaudio on validity-store replay window. No matcher hit. Advisory sha256 `23bc5fecfb72dcda4e871b7421e791e15f3a7748431d36e2a21895ab3544d7cb`.
6. GHSA-44QC-PGVP-WX7V go-gitea/gitea REJECT ai_hunk FAIL. Closer `9e84deb969af` n_parents=1 bircni, human Co-authored-by Lunny Xiao. Bundled feed-PAT and clone-redirect sibling edits. notification.go redaction is not AI authorship. Advisory sha256 `1d9aa9fc687718428551411887da58a6f115f5c18d1ffec933496c87fda76a1d`.
7. GHSA-46WQ-28CX-MHW4 nimiq/core-rs-albatross REJECT ai_hunk FAIL. Closer `41d35acee1b5` n_parents=1 Pascal Berrang rejects equal-length keys in `TrieProofNode::child_index`. No matcher hit. Advisory sha256 `df5607466aaefc93841d59db9149072c73409749cf621dd02a735611ea0289f0`.
8. GHSA-48CH-P4GQ-X46X go-vikunja/vikunja REJECT ai_hunk FAIL and fix_reversal FAIL. Closer `879462d71735` n_parents=1 kolaente adds GetResourcesByList URL-project match. GetResource and unused Auth on GetTasksByUIDs remain incomplete reversal. Advisory sha256 `a114c156f68da9e75dc61d4f09d6d8f9effd087105cc9a3f3b9f7905435ba0b4`.

Routing, recovered SHA, same repo, shared SHA, AI-on-fix, carrier trailer transfer, old-bug preservation, sibling fields, and hardening are not proof. Release artifacts were not hashed; release_gate is UNKNOWN. None is countable.

## Conservation

assigned 8 = reviewed 8 + unreviewed 0. Equation 8=8+0. Holds. Did not pad.
PASS_PROPOSAL 0. countable_pass 0.
Temp clones were deleted after evidence capture.

Stop. No ledger, site, or other-directory edits. No commit or push.
