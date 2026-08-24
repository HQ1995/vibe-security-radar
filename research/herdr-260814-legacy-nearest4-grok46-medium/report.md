# Legacy nearest-4 NARROW upgrade

Verdict first: **0 KEEP**. Assigned **4**, reviewed **4**, unreviewed **0**. Equation **4=4+0**. All four rows are **REJECT** at HIGH confidence. Packet delta **0**. Canonical84 stays **84**. Publication and more-than-200 remain **HOLD**. Worker KEEP is a proposal only and is not issued.

Selection is exactly the four legacy NARROW cases from `autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh/result.json` that each had one non-PASS gate: ordinal 74 GHSA-4524-X6PC-RR9X, ordinal 98 GHSA-5GVR-V6QV-H5MM, ordinal 108 GHSA-WJHR-76VG-2HVC, ordinal 110 GHSA-92VG-F4FQ-FXM9. Those routing labels were not trusted.

## Sources

- Narrow-recovery-a result sha256 `fac9ebdc4d4eace59c13f4eb56e35439f4caae90023aedbf3a9afda293915bea`
- Narrow-recovery-a cases sha256 `023e5703b63cbf7f700ee6cb89041ee1824929eae17d43aec140945f0e59ebd9`
- Canonical84 ledger sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06` (counted overlap 0/4)
- Advisory cache objects copied under `work/pages/`
- Independent clones under `work/clones/` (removed after replay)

## Independent replay

| Ord | ID | Routing non-PASS | This review | Failing gates |
|----:|----|------------------|-------------|----------------|
| 74 | GHSA-4524-X6PC-RR9X | fix_reversal | REJECT | identity, fix_reversal |
| 98 | GHSA-5GVR-V6QV-H5MM | fix_reversal | REJECT | topology, fix_reversal |
| 108 | GHSA-WJHR-76VG-2HVC | topology | REJECT | topology, but_for, release |
| 110 | GHSA-92VG-F4FQ-FXM9 | ai_hunk | REJECT | ai_hunk |

### Ordinal 74 GHSA-4524-X6PC-RR9X REJECT

Identity FAIL. The local GHSA object is unreviewed (`github_reviewed=false`, `affected=[]`). `https://github.com/jarrodwatts/claude-hud/security/advisories/GHSA-4524-x6pc-rr9x` returned HTTP 404. `github.com/claude-hud/claude-hud` does not exist. Unreviewed empty-affected identities are not countable.

AI hunk PASS on jarrodwatts/claude-hud `26a3e984` (single-parent, Claude Opus 4.5). Parent has no `src/transcript.ts`. Candidate adds `stdin.transcript_path` -> `parseTranscript` -> `fs.createReadStream`. Topology PASS: ancestor of `v0.0.12`, not the closer. Release PASS: `v0.0.12` contains the candidate and not `234d9aad`; `v0.1.0` contains the closer.

Fix reversal FAIL. Closer `234d9aad` realpathSync-canonicalizes then still reads that path. No root allowlist. Absolute `/etc/passwd` still resolves. Cache `0o600` does not close the named arbitrary-file read. Uniqueness PASS versus counted canonical84.

### Ordinal 98 GHSA-5GVR-V6QV-H5MM REJECT

Identity PASS from github-reviewed global JSON (sha256 `0de1f53d38bce75a729efe3e4157db4ae2297a9a1659de169a2f2f043c798e16`) naming npm `claude-mem`, `computeObservationContentHash`, patch `f32fda8b`, and release `v12.0.0`. Repo advisory HTML 404; same-repo commit and release refs bind the object. Title/details/function/patch are consistent.

Assigned member `924a11ee` is Claude-marked and blob-equal to `v11.0.0` `store.ts`, but it is not an ancestor of `v11.0.0`. Squash `c6f93298` is the tag ancestor and is also Claude-marked. Authorship is not transferred from the non-ancestor member onto the squash. Topology FAIL for the assigned member edge.

Fix reversal FAIL at high confidence. Atomic closer `9cfa57d4` inserts NUL delimiters and keeps `slice(0,16)`. The GHSA names weak hash / hash collision. Truncation remains. A delimiter-only narrowed KEEP is refused. Release PASS on git tags `v11.0.0` / `v12.0.0` for the squash/closer blobs. Uniqueness PASS.

### Ordinal 108 GHSA-WJHR-76VG-2HVC REJECT

Identity PASS. Repo advisory HTML sha256 `aba55870e684e4c6db4c7c8a97d32bef1acb4edc41b6963afe7a33bc8f70ab8a` plus github-reviewed JSON sha256 `a2f6091eaa2f5f2801c7854e7152b2f7d4d0feb1c634df45aea17258c76d06ce`. Not withdrawn. Names `dump()` umask hole, `<=0.3.4`, patched `0.3.5`.

AI hunk PASS on `21aea2d` (Claude Opus 4.6, adds `client.py` `write_text` dump). Topology FAIL: `21aea2d` is not an ancestor of `0.3.4` or `0.3.5`. Human `e36613f3` has the same `client.py` blob `e612db67`, no AI trailer, and is an ancestor of `0.3.4`. Released `0.3.4` blob is `4f1a9c88`, not the AI blob. Named closer `77a3837` is not an ancestor of `0.3.5`. Tag `0.3.5` merge `7fd695f` lands human `8256b577` with equal closer blob `ddda26b2` and no AI marker. But-for FAIL: deleting `21aea2d` does not remove the released hole. Release FAIL for AI containment on the named tags. Fix reversal PASS for the permission rewrite that is in `0.3.5` content. Uniqueness PASS.

### Ordinal 110 GHSA-92VG-F4FQ-FXM9 REJECT

Identity PASS from independently fetched repo advisory HTML sha256 `1f42b016f3249f073813d3beed5be7052c3c54f68f0b8a0400586ecfdbe5f7d6`. Not withdrawn. Names VMID `XDocument.Load` DTD/XXE, v1.0.0 and v1.0.1, patched v1.0.2. Advisory names fix `4939a1b`, which is not a git object.

AI hunk FAIL. Claude-marked `d1944bca` is peeled `v1.0.0` and only changes changelog, readme, package.json, and `SolidCAM.GPPL.Server.exe` / `.pdb`. No C# source is in the tree. Binary strings mentioning `GpplVmidParser` / `XDocument` are not an atomic source hunk. Closer `9d0ba808` (peeled `v1.0.2`) is the same class of binary+changelog rewrite. But-for and fix-reversal stay UNKNOWN without a source hunk; they are not converted into FAIL. Topology PASS for tag peeling. Release PASS for `v1.0.0`/`v1.0.1`/`v1.0.2`. Uniqueness PASS.

## Conservation and claim boundary

Assigned 4 = reviewed 4 + unreviewed 0. KEEP 0. REJECT 4. Canonical ledger not edited. Fetched clones removed. No greater-than-200 claim.

Replay commands are in `cases.jsonl`. Temporary clones lived only under `work/clones/` and are deleted.
