# Near-PASS hard-gate eight: independent seven-gate review

Lane: `herdr-260814-ghsa200-nearpass-hardgate8-grok46-low`.
Conservation: assigned 8 = reviewed 8 + unreviewed 0.
Worker PASS is proposal only. This packet emits **zero** PASS proposals.
Canonical count is not updated. Publication and greater-than-200 remain **HOLD**.

## Verdict

All eight assigned first-party GHSA identities stay **NARROW**. Routing labels from `canonical81/ledger.jsonl` were frozen, then ignored as proof. Each row was re-audited against `CONTRACT.md` using repository GHSA objects and Git history. Closing the named routing gate never promoted a case.

PASS proposals for independent high/xhigh red-team: **none**.

## Method

- Source rows: exact `PRESERVED_HYPOTHESIS` lines in `selected-8.jsonl`.
- Identity: non-withdrawn repository GHSA on the assigned repo naming that repo and mechanism. Global-only, empty `vulnerabilities`, 404 repo advisory, same-repo nearby GHSA, or cross-advisory semantic overlap do not suffice.
- Topology / AI-hunk: expand PR members. Squash/carrier/import ancestry uses `merge-base --is-ancestor`. Member authorship is not transferred.
- Fix reversal: later commit must atomically close the same scoped invariant.
- But-for, release, uniqueness rechecked even when the named gate moved.

Clones used read-only from `/home/hanqing/.cache/ghsa200-worker-clones/`. Advisory-database HEAD `a42c436870111aa3f221257c9d56126a93173ccc`.

## Per-case

| Ord | Case | Named routing gate | Terminal | Why not PASS |
|---:|---|---|---|---|
| 123 | GHSA-2QRV-RC5X-2G2H | identity | NARROW | Repo GHSA identity PASSes. Member is OOM snapshots, not workspace shadows. Not a tag ancestor. |
| 200 | GHSA-3J8Q-FWPJ-F8J5 | identity | NARROW | Repo GHSA is an omnibus of nine findings. Closer names GHSA-jjcj, a distinct identity. |
| 74 | GHSA-4524-X6PC-RR9X | fix_reversal | NARROW | No repo GHSA on claude-hud/claude-hud. Named fix is hyperlink/Windows hardening. |
| 126 | GHSA-5WP8-Q9MX-8JX8 | topology | NARROW | Allowlist member is not a tag ancestor. Carrier squash is multi-purpose and blob-unequal. |
| 110 | GHSA-92VG-F4FQ-FXM9 | ai_hunk | NARROW | Candidate and closer are binary exe/pdb ships. VMID parser source hunk is absent. |
| 107 | GHSA-CW23-QWR7-C655 | topology | NARROW | Repo GHSA 404. Member is not a tag ancestor. shell.rs blobs are three-way unequal. |
| 78 | GHSA-F7FH-QG34-X2XH | identity | NARROW | Repo GHSA names /json/version hop. Candidate adds a direct-ws skip. Parent already had the named hop. |
| 156 | GHSA-X34R-63HX-W57F | topology | NARROW | Copilot member is not a tag ancestor and does not edit pandas_utils.py WAF. |

### GHSA-2QRV-RC5X-2G2H (openclaw/openclaw)

First-party `openclaw/openclaw` advisory GHSA-2qrv-rc5x-2g2h is published, not withdrawn, and names untrusted workspace channel shadows during built-in setup, patched in 2026.4.2 / `53c29df2`. Identity of that object PASSes.

Assigned member `fc1b156d` is Claude-marked and is PR 46763 member 1 of 8. It does not edit `catalog.ts`. Catalog blob equals parent. Member is not an ancestor of squash `f4cc93dc` (`loader.ts` 86d83fa8 vs b9132c08). Catalog "trust manifest ids" is human `b68c5911`. Member is not an ancestor of `v2026.4.1`; carrier is. Distinct from GHSA-82qx-6vj7-p8m2.

### GHSA-3J8Q-FWPJ-F8J5 (ChurchCRM/CRM)

Repo advisory exists but is omnibus (IDOR, SSRF, weak token, credential disclosure). Global 404. Notes CRUD `b3edc225` is Claude-marked and is an ancestor of `7.3.3`. Named closer `83c19611` states it fixes **GHSA-jjcj-h3cm-p7x7**. Nearby GHSA-jjcj is kept distinct. Identity and fix-reversal stay NARROW. Release of the Notes commit versus `7.4.0` PASSes and does not promote 3j8q.

### GHSA-4524-X6PC-RR9X (claude-hud/claude-hud)

`repos/claude-hud/claude-hud/security-advisories/GHSA-4524` is 404. Global object has empty `vulnerabilities` and points at `jarrodwatts/claude-hud`. Identity NARROW.

`26a3e984` is Claude-marked and introduces `stdin.transcript_path`. Named fix `234d9aad` is "harden links and Windows version lookup". `v0.1.0` and later still lack a transcript root allowlist. Fix-reversal NARROW.

### GHSA-5WP8-Q9MX-8JX8 (qhkm/zeptoclaw)

Repo advisory PASSes identity. Allowlist member `3c4368da` is Claude-marked, is not an ancestor of squash `1712debb` or `v0.6.1`, and `shell.rs` blobs differ (member / carrier / `v0.6.1`). Carrier also adds sandbox runtimes. Closer `68916c3e` is in `v0.6.2` and also patches other GHSAs. Topology NARROW.

### GHSA-92VG-F4FQ-FXM9 (anzory/solidcam-gppl-ide)

Repo advisory PASSes identity (XXE in VMID parser). Candidate `d1944bca` is `release: v1.0.0` of `SolidCAM.GPPL.Server.exe` / `.pdb`. No parser source hunk. Closer `9d0ba808` is the same binary pattern. AI-hunk NARROW. `v1.0.0` GitHub Release object is 404; git tag peel equals the candidate.

### GHSA-CW23-QWR7-C655 (nearai/ironclaw)

Repo advisory 404. Global GHSA has empty `vulnerabilities`. Identity NARROW. Member `b20880c1` (Claude Sonnet 4.6) is not an ancestor of carrier `b58b4215` or `ironclaw-v0.29.1`. `shell.rs` blobs: member 4798d0c3, carrier fa92cb37, tag 8f574e90. Parent already had `NEVER_AUTO_APPROVE_PATTERNS`. Topology NARROW.

### GHSA-F7FH-QG34-X2XH (openclaw/openclaw)

Repo advisory exists. Summary is CDP `/json/version` `webSocketDebuggerUrl` second-hop. Parent of `75602014` already implements that hop plus `normalizeCdpWsUrl`. Candidate (Claude Opus 4.6) adds `isWebSocketUrl` and skips discovery. Closer `bc356cc8` adds one `assertCdpEndpointAllowed` call on the direct-ws branch. Identity, but-for, and fix-reversal stay NARROW. Candidate in `v2026.4.1`, closer in `v2026.4.5`.

### GHSA-X34R-63HX-W57F (langroid/langroid)

Repo advisory PASSes identity (pandas_eval WAF bypass, `_literal_ok`, dunders). Copilot member `b1c45e3f` edits only `table_chat_agent.py` and is not an ancestor of squash `0d9e4a7b` or tag `0.59.31`. `pandas_utils.py` on the member equals parent. `visit_Attribute` is absent in `0.59.31` and present in `30abbc1a` / `0.59.32`. Topology and relevant AI-hunk stay NARROW. PyPI 0.59.31/0.59.32 each have two non-yanked files.

## Uniqueness

None of the eight IDs is in canonical81 strict 81. GHSA-2QRV stays distinct from GHSA-82QX. GHSA-3J8Q stays distinct from GHSA-JJCJ.

## Limits

No credential was printed. No tracked file outside this directory was edited. No commit or push. Replay is `zsh autoresearch/herdr-260814-ghsa200-nearpass-hardgate8-grok46-low/replay.sh`.
