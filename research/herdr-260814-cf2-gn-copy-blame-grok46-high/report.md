# CF2 G-N copy-blame packet (proposal only)

Verdict: **1 PASS_PROPOSAL / 13 REJECT / TERMINAL**. Canonical85 stays 85. Countable pass 0. Greater-than-200 remains unsupported. Worker PASS is proposal only.

Universe: unreviewed G-N subject-only intersections (640), minus 7 canonical/foundation/source-shard identities, leaving 633. This packet fully adjudicated the 14 strongest net-new rows (7 copy-blame hunk/follow hits plus 7 targeted no_refs / incomplete-language rows). Heavy repos were left UNREVIEWED, not REJECT. Did not pad to 40.

Source-policy correction: the G-N scan regex `Co-authored-by:.*anthropic` is invalid. Hits were recomputed with production `source_matcher` (exact Claude/Cursor/Copilot/Codex/bot identity or known AI trailer). Corporate human email is not AI. One blamed hunk was dropped: `7901552eba29` (`ihrpr <inna@anthropic.com>`). `568cbd1a` (`Claude <noreply@anthropic.com>`) remains a valid AI marker and still REJECT for refactor-move.

## PASS_PROPOSAL: GHSA-V52W-28XH-V562

First-party active GHSA on `kozou-dev/kozou`. Scope is issues 1 and 2 only: the unauthenticated MCP Streamable HTTP server in `packages/mcp/src/startHttpServer.ts` shipped without Host/Origin DNS-rebinding validation and without a request-body cap. Issues 3 (READ ONLY transactions, closer `41f68fec`) and 4 (`kozou-dev` 0.0.0.0 defaults from later `46e36e48`) are out of scope.

- Identity: advisory-database `GHSA-v52w-28xh-v562`, not withdrawn, no CVE alias, npm `@kozou/mcp` introduced 0 fixed 1.8.1.
- Exact AI hunk: PR #20 member `4f86724bd112b07e68033098562c1c4ddc37d93b` is a single commit on `c84c70c7088f`. Parent lacks `startHttpServer.ts`. Member adds that file. Trailer `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`. `readJsonBody` is unbounded `for await (const chunk of req)` with no Host/Origin allowlist.
- Topology: GitHub squash carrier `bc9dc69d62aaa567a2ccefee12d28a58b96d96c4` has the same tree `c743d1b43bd3` and the same blob `1c4a96662fa3`. The AI marker is on the member itself; the squash does not transfer authorship. An advisory-listed closer is not an origin.
- But-for: removing the member removes the MCP HTTP surface named in issues 1 and 2.
- Minimum fix: `7c3ae2e3b7c996571acc07c96222b6dc2de01a3e` (PR #163 squash) adds Host/Origin guard and `maxBodyBytes`. Blob `91cc618dbf3c`. PR #163 head `9287e701` differs; use the merged squash.
- Release: git tag `v1.8.0` is `e631527918dc` (`@kozou/mcp` 1.8.0), blob `9643e54351d6` still unbounded and unguarded. Origin squash is an ancestor of `v1.8.0`; harden is not. Annotated tag `v1.8.1` peels to `17f3207e24ca` (`@kozou/mcp` 1.8.1), same blob as harden. Harden is an ancestor of `v1.8.1`.
- Uniqueness: absent from canonical85, foundation, and the G-N source-shard cases.

Subject-overlap SHAs on this row (`46e36e48` bundled dev, JWT wiring) are routing only.

## REJECT counterevidence

- GHSA-232V-J27C-5PP6 (MCPJam): `--follow -A` lands on Claude `b7912f08` Create hono server with no hostname. `0.0.0.0` is human `dd2abd38` Docker. Fix only rebinds hostname.
- GHSA-4MPH-V827-F877 (locutus): blame -M hits a Claude TS migration; `--follow -A` is the old phpjs move. Preserving unserialize is not origin. Shared closer with counted GHSA-VC8F is routing only.
- GHSA-3QHF-M339-9G5V / GHSA-J975-95F5-7WQH (python-sdk): Claude `568cbd1a` (`Co-authored-by: Claude <noreply@anthropic.com>`) moves a stream; parent already called uncaught `model_validate`. `7901552eba29` is `Co-authored-by: ihrpr <inna@anthropic.com>`, a human employee identity; production source_matcher returns no match and it is not in the candidate set. Same-file / shared SHA is routing; the two GHSAs stay distinct and both REJECT.
- GHSA-6XJ8-QV9J-XCJQ (oh-my-posh): AI palette/segment feats are not `path.go` setStyle. Fix globally renames Render to RenderTrusted.
- GHSA-JMH7-G254-2CQ9 (gradio): AI-marked squash `029034f78` is 1264 files. Carrier does not transfer hunk authorship.
- GHSA-35HP-HQMV-8QG8 (fiber): Copilot review binds an already path-only KeyGenerator (`5482edcc`).
- GHSA-X7J8-49R8-MR43 (ts-utils): Copilot hardens sibling `objMergeIf`/`objDefaults`; `_copyProps` unchanged. Sibling-path incomplete remediation is REJECT.
- GHSA-F89H-2FJH-2R9Q (gitoxide): "found by AI" is finder not author. Codex `b5608877` fixes a different GHSA. stack.rs closer is `93d0ff634`.
- GHSA-25GQ-J9JX-43PG (gitea): parent CVE-2025-68939 closer `7adc4717ec` is human. AI branch-protection allowlist is a different path.
- GHSA-6CQF-375W-639G (gitea): AI `#37698` scoped downloads; feeds are an untouched sibling path.
- GHSA-47CR-F226-R4PQ (vikunja): AI OpenID uniqueness vs CalDAV TOTP closer `cdf5d30a`.
- GHSA-RJRW-MJQ6-HPMM (goshs): parent empty-username check is human; AI hits are ConPtyShell, not SFTP.

## Conservation

633 = 14 inspected + 619 remaining unreviewed. PASS_PROPOSAL 1, REJECT 13, BLOCKED 0, UNKNOWN 0. Packet delta 0. No GitHub REST/GraphQL. No full clones. No edits outside this owned directory. No credentials.
