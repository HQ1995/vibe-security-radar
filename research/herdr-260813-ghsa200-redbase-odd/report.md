# Red-team: fp211 released-admitted odd ordinals

**Status: `REDTEAM_COMPLETE`.** Rows with `counting.fp211_released_publication_admitted=true` and `fp211_adjudication.ordinal % 2 == 1` were treated as hypotheses. Independent first-party GHSA fetch and Git replay. A KEEP here is still only a proposal.

Assigned ordinals (22): `[19, 23, 27, 39, 43, 49, 57, 63, 65, 73, 81, 111, 119, 135, 137, 147, 161, 163, 167, 171, 179, 185]`.

| Ordinal | GHSA | Class | Red-team |
|--------:|------|-------|----------|
| 19 | GHSA-97RM-XJ73-33JH | AI_DIRECT_ROOT | **KEEP** |
| 23 | GHSA-VVGP-4C28-M3JM | AI_DIRECT_ROOT | **KEEP** |
| 27 | GHSA-46Q5-G3J9-WX5C | AI_DIRECT_ROOT | **KEEP** |
| 39 | GHSA-X9QH-W4C4-54F9 | AI_DIRECT_ROOT | **KEEP** |
| 43 | GHSA-VCV2-R9JH-99M5 | AI_DIRECT_ROOT | **KEEP** |
| 49 | GHSA-76RV-2R9V-C5M6 | AI_DIRECT_ROOT | **NARROW** |
| 57 | GHSA-2GFJ-FR43-4735 | AI_DIRECT_ROOT | **KEEP** |
| 63 | GHSA-4564-PVR2-QQ4H | AI_DIRECT_ROOT | **KEEP** |
| 65 | GHSA-C6HR-W26Q-C636 | AI_DIRECT_ROOT | **KEEP** |
| 73 | GHSA-243V-5F97-VFQ3 | AI_DIRECT_ROOT | **KEEP** |
| 81 | GHSA-RV39-79C4-7459 | AI_DIRECT_ROOT | **KEEP** |
| 111 | GHSA-9HFR-GW99-8RHX | AI_DIRECT_ROOT | **NARROW** |
| 119 | GHSA-9F72-QCPW-2HXC | AI_DIRECT_ROOT | **KEEP** |
| 135 | GHSA-FVVP-RJ8G-C7GC | AI_INCOMPLETE_REMEDIATION | **KEEP** |
| 137 | GHSA-M4WX-M65X-GHRR | AI_INCOMPLETE_REMEDIATION | **KEEP** |
| 147 | GHSA-56C3-VFP2-5QQJ | AI_INCOMPLETE_REMEDIATION | **KEEP** |
| 161 | GHSA-VC8F-X9PP-WF5P | AI_INCOMPLETE_REMEDIATION | **KEEP** |
| 163 | GHSA-Q6RR-FM2G-G5X8 | AI_INCOMPLETE_REMEDIATION | **NARROW** |
| 167 | GHSA-6Q7J-XR26-3H2C | AI_INCOMPLETE_REMEDIATION | **NARROW** |
| 171 | GHSA-MV93-W799-CJ2W | AI_INCOMPLETE_REMEDIATION | **KEEP** |
| 179 | GHSA-5XXX-QHH7-9287 | AI_INCOMPLETE_REMEDIATION | **KEEP** |
| 185 | GHSA-HM7V-JRHM-FMFX | AI_DIRECT_ROOT | **KEEP** |

Clones: `/home/hanqing/.cache/ghsa200-worker-clones/redbase-odd/clones/`. Advisory JSON: `/home/hanqing/.cache/ghsa200-worker-clones/redbase-odd/pages/`. Sibling even-lane conclusions were not read.

## Verdicts

### Ordinal 19 — KEEP (GHSA-97RM-XJ73-33JH)

Claude authored updateEnvFile token writeback. Parent lacks the helper. v1.7.2 / v1.7.3 containment holds. Repo GHSA names the newline injection.

### Ordinal 23 — KEEP (GHSA-VVGP-4C28-M3JM)

Cursor-marked squash 20523b91 adds trustedProxyAuthOk without operator role. Member blobs match the tag but the member is not a tag ancestor. Fix adds role===operator. Distinct from token-presence skip.

### Ordinal 27 — KEEP (GHSA-46Q5-G3J9-WX5C)

Claude squash first adds webhook.rs trusting payload.sender/chat_id with auth_token default None. v0.7.5 / v0.7.6. Fix also touches other channels; origin is webhook identity.

### Ordinal 39 — KEEP (GHSA-X9QH-W4C4-54F9)

Repo GHSA (global 404) names unescaped docker build version. Claude commit first adds buildHelperImage. Blame on beta.447 holds. Official range has no lower bound.

### Ordinal 43 — KEEP (GHSA-VCV2-R9JH-99M5)

Two Claude execSync origins ship in npm 2.0.13 gitHead; 2.0.14 gitHead is the execFileSync fix. No matching git tags. Side-branch gitHead ancestry is not used as a substitute for npm gitHead.

### Ordinal 49 — NARROW (GHSA-76RV-2R9V-C5M6)

Initial Claude commit created entity-scoped DynamoDB PKs. Hypothesized minimum 9f66c42f is later shard selection. GHSA names 481ce44d after a long pre-shard series; 94a129ae is the PK migration. Origin real, minimum-fix KEEP refused.

### Ordinal 57 — KEEP (GHSA-2GFJ-FR43-4735)

Claude Code adds message_id.strip directory join plus rmtree. No repo GHSA; global CVE GHSA plus named fix commit. v1.1.0 / 1.3.4.

### Ordinal 63 — KEEP (GHSA-4564-PVR2-QQ4H)

Claude OAuth refresh interpolates tokens into execSync security -w. 9dce3d8b switches that write to execFileSync. Human 66d7178f later removes remaining shell on find-generic-password.

### Ordinal 65 — KEEP (GHSA-C6HR-W26Q-C636)

Missing top-level mechanism_key reconstructed as unescaped Feishu mention RegExp in stripBotMention. Upstream Claude 4286755f; openclaw import 2267d58a; fix 7e67ab75. Extra named commit is tests.

### Ordinal 73 — KEEP (GHSA-243V-5F97-VFQ3)

Claude EventTemplateImporter overwrite preserves org_id without a caller org check. NVD-imported GHSA, no repo advisory, first-party fix commit 7c2200d1. v2.5.37 / v2.5.39.

### Ordinal 81 — KEEP (GHSA-RV39-79C4-7459)

Claude commit explicitly skips device identity when a token is present. Fix requires sharedAuthOk. Distinct invariant from ordinal 23.

### Ordinal 111 — NARROW (GHSA-9HFR-GW99-8RHX)

Claude ARC broadcaster treats only REJECTED/DOUBLE_SPEND as failure. INVALID/MALFORMED/ORPHAN stay success. Security commit also patches unrelated P0s. Origin real, umbrella KEEP refused.

### Ordinal 119 — KEEP (GHSA-9F72-QCPW-2HXC)

Claude native prompt-image loader omits workspaceOnly. Candidate in v2026.2.23; fix first in v2026.2.24. Shared SHA with other image rows is not a duplicate.

### Ordinal 135 — KEEP (GHSA-FVVP-RJ8G-C7GC)

Repo GHSA (global 404) says the CVE-2026-33645 filename fix was not applied to public checkSum. Copilot 157386c8 is that incomplete rem. 70b5b35a alnum-filters checkSum in v1.5.3.

### Ordinal 137 — KEEP (GHSA-M4WX-M65X-GHRR)

Peeled v3.11.1 Claude patch uses require === false and leaves omit-require in scope-out. Human 01a7552 is not an ancestor of v3.11.1-3.11.3. Complete 86ab819f in v3.11.4.

### Ordinal 147 — KEEP (GHSA-56C3-VFP2-5QQJ)

Claude fork-merge adds IPv4-only validateUrlSync at v2.47.4. Official range starts there. IPv6 family extension in v2.47.14.

### Ordinal 161 — KEEP (GHSA-VC8F-X9PP-WF5P)

Claude swaps includes() for RegExp.test() in parse_str at v2.0.39. Official range starts there. Residual is overwriting RegExp.prototype.test until v3.0.25.

### Ordinal 163 — NARROW (GHSA-Q6RR-FM2G-G5X8)

Copilot LoopLimit in 7.0.0 does not edit ScriptArray.cs. GHSA array*int range starts at 3.0.0. Old sibling, not GHSA-level AI origin. Distinct from 167.

### Ordinal 167 — NARROW (GHSA-6Q7J-XR26-3H2C)

Non-enforcing ExpressionDepthLimit is in 6.6.0 (b5ac4bf, 2026-03-19). Copilot f55280a0 (2026-03-21) extends array initializers with the same LogError-and-continue. Official range starts 6.6.0.

### Ordinal 171 — KEEP (GHSA-MV93-W799-CJ2W)

Codex value-only control-char rejection in 3.1.49 is incomplete of config injection. Section/option newline closed in 3.1.50. Distinct from 179.

### Ordinal 179 — KEEP (GHSA-5XXX-QHH7-9287)

Codex blame denylist has --output and omits --contents/-S. Repo GHSA (global 404). 3.1.58 / 3.1.59. Distinct from 171.

### Ordinal 185 — KEEP (GHSA-HM7V-JRHM-FMFX)

Claude Tabler squash first writes data-person_name. Member is not a 7.5.1 ancestor. Later human escapeHtml is still wrong. 7.6.0 merge uses escapeAttribute and also patches two other GHSAs.

## Sources

| Clone | HEAD | Date |
|-------|------|------|
| ebay-mcp | `fe295c3da1d65b717a6ff7ea750ce20955172e62` | 2026-08-07T18:18:10+03:00 |
| openclaw | `2dcd47d4f45f0bdd1e22c707ac26e33991b7a37a` | 2026-08-13T13:49:00-07:00 |
| zeptoclaw | `6c74d59fc2853cd81df191fb1da02fa514573c8a` | 2026-07-25T01:49:50+08:00 |
| coolify | `a02d02d19bedd3b68880721d449a646559e234ea` | 2026-08-13T21:38:23+02:00 |
| agentic-flow | `d3735a33533da2e12a68439177a791bf1c5c91e1` | 2026-07-29T21:18:20-04:00 |
| zae-limiter | `ced59de08fc227d9de9826671d83f4b79b52180f` | 2026-06-25T23:00:42-04:00 |
| mail-mcp-bridge | `638b162b26532e32fa8d8047f638537dbdfe197a` | 2026-04-12T20:51:11+08:00 |
| clawdbot-feishu | `b07885b756accb6756ddf696b60972a413317287` | 2026-03-29T23:07:33+08:00 |
| misp | `4af1c16d3f23cf90239b68050dd530e749e7edfd` | 2026-08-13T10:39:02+02:00 |
| bsv-ruby-sdk | `791b49b724af9809d63ed24ebba91252311d3d43` | 2026-07-08T10:46:53+01:00 |
| fireshare | `7889e7f1166c5092c42a00768d03a3182d23193b` | 2026-08-08T08:33:21-06:00 |
| vm2 | `7a1f5100b96f48d34e0fe104ab37c0acc5944f92` | 2026-05-19T00:24:37+09:00 |
| n8n-mcp | `5e3c425faaf0823b320c67ed8936903b00c55267` | 2026-08-09T12:48:38+02:00 |
| locutus | `0f8ed0e29dd1d8073a718d4c2226a330eb9c4e46` | 2026-05-16T12:15:55+02:00 |
| scriban | `420513a9d017fa54b23ba78a9f21a12187a8dd97` | 2026-07-29T09:18:31+02:00 |
| GitPython | `f44c1fb0e5dc3b3f0df58c7834ceed336f0d36fc` | 2026-08-11T15:54:56+02:00 |
| churchcrm | `d8d0f16369d6c15bc7c1860ba114ea82c014de6c` | 2026-08-12T08:48:31-07:00 |

Frozen ledger SHA-256 `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`.

Counterexample classes actively tested: old-bug preservation, remediation-as-origin, squash/merge attribution, later-human blame, insufficient fix, umbrella fix, alias duplicates, missing mechanism_key uniqueness.

