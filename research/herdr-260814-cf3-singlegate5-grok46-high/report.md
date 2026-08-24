# CF3 single-gate five (proposal only)

Verdict: **0 PASS_PROPOSAL / 1 REJECT / 4 NARROW / TERMINAL**. Canonical86 stays 86. Countable pass 0. Greater-than-200 remains unsupported. Worker PASS is proposal only. Prior singlegate/nearpass packets are routing hypotheses only.

Conservation: 5 = 5 + 0. Exact identities, no padding, no JJCJ substitute.

## Per-case (actual unresolved or failed gate)

### GHSA-2QRV-RC5X-2G2H REJECT - failed `ai_hunk_gate`

First-party reviewed GHSA names untrusted workspace channel shadows, closer `53c29df2`, npm `2026.4.2`. Identity PASSes. Assigned member `fc1b156d` is a Claude OOM snapshot commit. `catalog.ts` blob equals the parent. The member is not an ancestor of squash `f4cc93dc` or tags `v2026.3.22`/`v2026.4.1`/`v2026.4.2`. Human `b68c5911` authored catalog trust. An AI-marked squash cannot receive that member. Topology, but-for, fix-reversal, and release FAIL for this candidate. Uniqueness PASSes versus canonical86. Fatal FAIL is not promoted.

### GHSA-3J8Q-FWPJ-F8J5 NARROW - unresolved `identity_gate`

Repo advisory is an omnibus of nine findings; only VULN-02/03 name `notes.php`. Claude squash `b3edc225` adds that file. Closer `83c19611` names GHSA-jjcj and also patches family/timeline/photo. `7.3.3` contains the candidate without the closer; `7.4.0` contains the closer. Uniqueness PASSes versus canonical86. JJCJ is not counted here.

### GHSA-4524-X6PC-RR9X NARROW - unresolved `identity_gate`

Global GHSA-4524 is unreviewed with empty `affected[]`. Assigned repo `claude-hud/claude-hud` has no reviewed repository GHSA. Git remote is `jarrodwatts/claude-hud`. Claude `26a3e984` adds `createReadStream(transcriptPath)`. Closer `234d9aad` adds `realpathSync` without a root allowlist. `v0.0.12` ancestry is not blob equality.

### GHSA-92VG-F4FQ-FXM9 NARROW - unresolved `ai_hunk_gate`

Repo advisory PASSes identity (XXE in VMID parser, CVE-2026-42212). Candidate `d1944bca` equals tag `v1.0.0` and ships only changelog/readme/package plus `SolidCAM.GPPL.Server.exe`/`.pdb`. Zero C# files. Advisory closer `4939a1b` is absent from git. Assigned `9d0ba808` equals `v1.0.2` and is the same binary pattern. Binary strings are not a source hunk.

### GHSA-F7FH-QG34-X2XH NARROW - unresolved `identity_gate`

Reviewed GHSA names `/json/version` `webSocketDebuggerUrl` second-hop. Parent already has that hop. Claude `75602014` adds `isWebSocketUrl` and skips discovery on direct ws/wss. Closer `bc356cc8` guards the direct-ws branch only. Candidate is in `v2026.4.1`; closer is in `v2026.4.5`. But-for for the named hop fails. Release of the AI commit does not promote identity.

## Claim boundary

No edits outside this owned directory. No credentials. No durable clones, pages, packages, or caches. mktemp fetch for SolidCAM was deleted. Canonical86 was not updated.
