# CF3 two-gate seven (proposal only)

Verdict: **0 PASS_PROPOSAL / 0 REJECT / 7 NARROW / TERMINAL**. Canonical87 stays 87. Accepted-pending GHSA-8RW6 is not overlapped. Countable pass 0. Greater-than-200 remains unsupported. Worker PASS is proposal only. Prior fp211-unseen-twogate8/nearpass packets are routing hypotheses only.

Conservation: 7 = 7 + 0. Exact identities, no padding.

## Per-case (actual unresolved gate)

### GHSA-5GVR-V6QV-H5MM NARROW - unresolved `topology_gate`

Reviewed GHSA names delimiter-free observation hash collision, closer `f32fda8b`, npm `12.0.0`. Identity PASSes. Atomic Claude `924a11ee` authors `computeObservationContentHash` concat then `slice(0,16)`. Parent lacks that function. But-for PASSes. Member is not an ancestor of mega-squash `c6f93298` or `v11.0.0`. `store.ts` blob `20727332` equals member/carrier/`v11.0.0`; blob equality is not SHA ancestry. Closer is a two-parent merge that still truncates. Uniqueness PASSes versus canonical87 and GHSA-8RW6.

### GHSA-7X5Q-8F6H-RJRC NARROW - unresolved `identity_gate`

Global GHSA is unreviewed with empty `affected[]`. Atomic Claude `840ec19c` replaces Nashorn `--no-java` with GraalJS `HostAccess.ALL`. That hunk PASSes but-for. Member is any-ancestor of `v3.21.21`, not first-parent. Unmarked merge `d874e6e5` is first-parent. Do not transfer. `87a7d96a` ships in `v3.30.0`/`v3.30.1` with `js.load` residual; `c691e35e` is first-parent of `v3.30.2`. Uniqueness PASSes.

### GHSA-C4M7-2GWP-VW76 NARROW - unresolved `topology_gate`

Reviewed GHSA names untrusted project `.env` RCE including `OUROBOROS_CLI_PATH`. Atomic Claude `d30b6175` adds that env override on `ClaudeCodeAdapter`. Parent adapter lacks it. Member is not an ancestor of squash `4aaf9147` or `v0.38.2`. Adapter blobs are pairwise unequal. Closer `4e70b760` is first-parent of `v0.39.0` and adds a loader denylist; the adapter still reads process env. Uniqueness PASSes.

### GHSA-G353-MGV3-8PCJ NARROW - unresolved `topology_gate`

Reviewed GHSA-g353 aliases only CVE-2026-32974. Atomic Claude `b0c67ea0` replaces unimplemented Feishu webhook mode. Parent said not implemented; but-for PASSes. Member is not an ancestor of squash `5c2cb6c5` or `v2026.2.12`. `monitor.ts` blob `31a890c2` equals `v2026.2.12`; blob equality is not SHA ancestry. Closer `7844bc89` requires `encryptKey` and is first-parent of `v2026.3.12`. `v2026.3.11` still has optional `encryptKey`. Distinct from uncounted GHSA-Q447 and GHSA-XH72. Uniqueness PASSes versus canonical87 and GHSA-8RW6.

### GHSA-G5CG-8X5W-7JPM NARROW - unresolved `topology_gate`

Reviewed GHSA names heartbeat `senderIsOwner` inheritance. Atomic Claude `01d568c9` adds `EXEC_EVENT_PROMPT`. Parent already scheduled `requestHeartbeatNow({ reason: exec-event })`. Member is not a tag ancestor. Carrier `483fba41` is any-ancestor of `v2026.3.28`, not first-parent. Heartbeat blob at the tag differs. Closer `a30214a6` adds `ForceSenderIsOwnerFalse` and is first-parent of `v2026.3.31`; it does not reverse the AI prompt hunk. Uniqueness PASSes.

### GHSA-MGXW-V6RH-WCV6 NARROW - unresolved `identity_gate`

Global GHSA is unreviewed with empty `affected[]`. Atomic Claude `d2b27f6f` adds multi-profile APIs. Parent already had `/api/sessions/search` over `all_sessions()`. Member is any-ancestor of `v0.51.268`, not first-parent; `routes.py` blobs differ. Fix member `8d8ae89d` is unmarked and is not a tag ancestor. Carrier `2c7b5300` peels `v0.51.269`. Canonical87 already counts GHSA-VVFR on the same candidate SHA for dotenv leak; shared SHA is not dedupe. Uniqueness PASSes versus GHSA-8RW6.

### GHSA-RQPP-RJJ8-7WV8 NARROW - unresolved `topology_gate`

Reviewed GHSA names unbound scopes on shared-token auth. Atomic Claude `079af0d0` adds `hasTokenAuth` device skip. That is not the named invariant. Candidate is any-ancestor of `v2026.3.11`, not first-parent; handler blobs differ. Closer `5e389d5e` clears unbound scopes and is first-parent of `v2026.3.12`. Uniqueness PASSes.

## Claim boundary

No edits outside this owned directory. No credentials. No durable clones, pages, packages, or caches. Canonical87 was not updated. GHSA-8RW6 was not admitted here.
