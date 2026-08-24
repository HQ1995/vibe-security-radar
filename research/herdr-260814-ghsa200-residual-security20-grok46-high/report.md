# Residual-security20: 2 PASS proposals; 18 REJECT

Verdict first: 2 PASS proposals (GHSA-HC8V-WWC9-VGXM, GHSA-425G-FJHQ-5H92), 18 REJECT. Assigned 20, reviewed 20, unreviewed 0. Conservation 20=20+0. Worker PASS is proposal only. Start count is not rebuilt. Current leader-accepted count 82 (canonical82, commit 6800d212, ledger hash 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23). Packet delta 0. Publication and greater-than-200 stay HOLD. This packet does not rebuild canonical82.

Pinned `selected.jsonl` sha256 f179f86d9097f71a0d632b2ea572dba0d1f6b1bb16743a332f331f66af6aba3f. Selection was not changed. The four leftover later-fix hits were not backfilled. fixblame20x outcomes were not inspected.

## Method

Later-fix semantics for `AI_INCOMPLETE_REMEDIATION`, not the exhausted advisory-keyword lane. Freeze ranked github-reviewed 2025-2026 first-party GHSAs whose fix hunk amends an existing security boundary and whose pre-fix lines blame onto a distinct explicit-AI security-attempt commit. Cross-lane: mechanically subtract the 14 identities owned by fixblame20x before freeze. Remaining hits 24, frozen 20.

Each frozen row was independently proved or falsified on identity, AI hunk, topology, but-for / patch-delta, fix reversal, public release, and uniqueness. PASS_proposal requires all seven gates plus `remediation_patch_delta_gate` PASS. Weak PASS is not emitted.

## PASS proposals

Worker PASS is a proposal. Leader plus independent hostile red-team must accept before the count moves.

### GHSA-HC8V-WWC9-VGXM (go-git/go-git)

All seven gates plus patch-delta PASS at incomplete-remediation scope.

- Identity: github-reviewed GHSA-hc8v-wwc9-vgxm, CVE-2026-71556, not withdrawn. Go module github.com/go-git/go-git/v5, last known affected <= 5.19.1, fixed 5.19.2.
- AI hunk: d83871ed single-parent. Assisted-by Claude Opus 4.6. First-parent creates worktree_fs.go worktreeFilesystem and calls validPath on mutating operations.
- Topology: atomic. Candidate is an ancestor of closer 008a78f2 and of peeled v5.19.1. Closer is not in v5.19.1. Later NTFS/HFS edits do not transfer the wrapper's origin.
- But-for / patch-delta: the AI commit is an explicit path-validating worktree boundary. The GHSA residual is following an existing symlink through a string that validPath accepts. Reverting the AI wrapper removes that incomplete boundary.
- Fix reversal: 008a78f2 changes the same wrapper so mutating ops call validWritePath, which adds validNoLeadingSymlink.
- Release: GitHub release v5.19.1 published, not draft, not prerelease; peeled commit 3c3be601; local tag plus source tarball have validPath and not validNoLeadingSymlink. GitHub release v5.19.2 published 2026-07-29, not draft, not prerelease; source tarball worktree_fs.go sha256 11d7a155bf28b8e86fc2e5833eb363ede45c13a941006199e813e4d03594cb46 equals `git show 008a78f2:worktree_fs.go`.
- Uniqueness: not in canonical82 strict 82. Distinct from onnx symlink/hardlink rows in this packet.

### GHSA-425G-FJHQ-5H92 (jahlives/openssl_encrypt)

All seven gates plus patch-delta PASS at incomplete-remediation scope.

- Identity: github-reviewed GHSA-425g-fjhq-5h92, not withdrawn. PyPI openssl-encrypt, introduced 0, fixed 1.4.0. Advisory quotes the fail-open skip in json_validator.py.
- AI hunk: a3d7f417 single-parent. Co-Authored-By Claude. Adds json_validator.py with `if not JSONSCHEMA_AVAILABLE: print(...); return`.
- Topology: atomic. a3d7f417 is an ancestor of closer 6e7f938d (subject cites this GHSA).
- But-for / patch-delta: the AI commit is an explicit schema-validation security attempt. The GHSA residual is that missing-jsonschema skip. Reverting the AI validator removes that fail-open branch.
- Fix reversal: 6e7f938d raises JSONValidationError on the same branch.
- Release: PyPI openssl-encrypt 1.3.5 wheel not yanked, uploaded 2026-01-09, skip block identical to a3d7f417. PyPI 1.4.0 wheel not yanked, uploaded 2026-03-03, json_validator.py byte-identical to 6e7f938d. No git tags; PyPI is the public artifact.
- Uniqueness: not in canonical82 strict 82.

## REJECT (18)

| ID | Class | Minimal counterexample |
| --- | --- | --- |
| GHSA-F3RG-XQJJ-CJ9W | old bug | urlParts[2] = '[domain]' blames to 5960d282, not AI 597bd290 |
| GHSA-WPPH-CJGR-7C39 | new surface | 3b0c80ce introduces toolsBySender; not a later residual |
| GHSA-28GM-JRMW-XX93 | import/squash | aebe49c5 is Consolidating all projects, not a STUN length check |
| GHSA-3R9X-F23J-GC73 | refactor + no tag | Copilot already added islink/realpath; tag --contains empty |
| GHSA-CMW6-HCPP-C6JP | refactor + no tag | same SHAs; hardlink check already in the attempt |
| GHSA-CWJ3-VQPP-PMXR | pre-AI denylist | PROTECTED_GATEWAY_CONFIG_PATHS exists on 29f206 parent |
| GHSA-72M8-9M7M-H278 | sibling | blamed MCP/ollama; closer is custom-code guardrail RCE |
| GHSA-4GGG-H7PH-26QR | new surface | feat multi-tenant instance-URL SSRF |
| GHSA-33RQ-M5X2-FVGF | new surface | feat Twitch Plugin |
| GHSA-CMRH-WVQ6-WM9R | sibling | AI SSRF helper; closer wires N8N_API_URL |
| GHSA-667W-MMH7-MRR4 | new surface | feat new auth-kit package |
| GHSA-8RGJ-VRFR-6HQR | new surface | same SHA as 667W; IDOR still new-package origin |
| GHSA-8G7G-HMWM-6RV2 | sibling | feat mutation telemetry vs path/SSRF advisory |
| GHSA-2QJ5-GWG2-XWC4 | sibling | undefined cwd fallback vs new sanitize-for-prompt.ts |
| GHSA-WG4G-395P-MQV3 | new surface | feat n8n integration logs tool-call args |
| GHSA-9PF5-HG6P-4PWP | human | trop[bot]; sattard@anthropic.com is a person |
| GHSA-F229-3862-4942 | already covered | 9e1a930c already handles array coercion; closer is tests |
| GHSA-MQ5J-PW29-JCV3 | new surface | feat apm install local-bundle tar extract |

CWJ3 is the nearest miss: the AI commit is a real Claude-marked gateway mutation guard, and npm tags v2026.4.22 / v2026.4.23 exist. It still fails patch-delta because the GHSA residual is the pre-AI path denylist, which the closer converts to an allowlist, while 29f206 only adds a sibling dangerous-flag set-diff.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 82. Only leader-reviewed rows with all seven gates PASS enter that bound after independent hostile red-team. This packet does not rebuild canonical82 and does not support a greater-than-200 claim.

Unreviewed remaining later-fix hits outside this freeze (not padded): GHSA-X9CF-3W63-RPQ9, GHSA-V3QC-WRWX-J3PW, GHSA-CHFM-XGC4-47RJ, GHSA-JXX9-PX88-PJ69.
