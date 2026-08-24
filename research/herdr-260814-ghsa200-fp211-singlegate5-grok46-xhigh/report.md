# fp211 single-gate remainder (exact 5)

Verdict first: **0 PASS**. Five fp211 NARROW mechanism rows have identity, AI hunk, or fix reversal as the only non-PASS contract gate. Ord180 uniqueness-only GHSA-3WXW-XV34-2FRG is already in canonical84 and is excluded. This packet freezes exactly those five rows / six GHSA identities in the stated order. Independent replay of every inherited PASS gate keeps five identities **NARROW** and rejects GHSA-JJCJ-H3CM-P7X7 as an explicit duplicate of GHSA-3J8Q-FWPJ-F8J5 (`uniqueness_gate=FAIL`). Worker PASS is a proposal and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Scope

Deterministic input: fp211 NARROW rows whose only non-PASS gate is `identity_gate`, `ai_hunk_gate`, or `fix_reversal_gate`.

Leader mechanical exclusion because canonical84 already counts it:

- ord180 GHSA-3WXW-XV34-2FRG (uniqueness-only)

Frozen remainder, no padding or substitution:

1. ord74 GHSA-4524-X6PC-RR9X (fix_reversal)
2. ord78 GHSA-F7FH-QG34-X2XH (identity)
3. ord110 GHSA-92VG-F4FQ-FXM9 (ai_hunk)
4. ord123 GHSA-2QRV-RC5X-2G2H (identity)
5. ord200 GHSA-3J8Q-FWPJ-F8J5 and GHSA-JJCJ-H3CM-P7X7 (identity)

Conservation: assigned mechanism rows = 5. Declared GHSA identities = 6. Reviewed identities = 6. Unique countable cases = 0. selected.jsonl has 5 rows. cases.jsonl has 6 rows (one per reviewed identity, with explicit duplicate/identity disposition for both ordinal-200 GHSAs). Verdicts: NARROW=5, REJECT=1. Equation: 5 mechanism rows = 5 reviewed rows + 0 unreviewed. Identities: 6 = 6 + 0.

Inherited fp211 PASS values are not proof. OSV routing, commit subject, AI-on-fix, CVE alias, shared SHA, and official page existence alone are insufficient. Member authorship is never transferred onto a squash/merge carrier.

## Per-case

### GHSA-4524-X6PC-RR9X (74, claude-hud/claude-hud) — NARROW

Identity NARROW. Assigned-repo and jarrodwatts repository advisories are 404. Global GHSA-4524 is unreviewed with empty `vulnerabilities[]`.

Atomic Claude Opus 4.5 commit `26a3e984` first-parent-introduces `src/transcript.ts` `createReadStream` and `stdin.transcript_path`. Parent lacks those files. AI-hunk PASS. Topology PASS. But-for PASS for the unvalidated read.

Fix-reversal NARROW: named closer `234d9aad` is "harden links and Windows version lookup". It adds `realpathSync` and cache mode `0o600`. No path root allowlist at `v0.1.0` or `v0.7.1`. Release NARROW: `v0.0.12` contains the candidate as an ancestor, but the transcript blob is not the candidate blob. Uniqueness PASS versus canonical84.

### GHSA-F7FH-QG34-X2XH (78, openclaw/openclaw) — NARROW

Identity NARROW. First-party repo GHSA names CDP `/json/version` `webSocketDebuggerUrl` second-hop. Parent of `75602014` already has that hop plus `normalizeCdpWsUrl`. Candidate (Claude Opus 4.6, parent_count=1) adds `isWebSocketUrl` and skips discovery on direct ws/wss.

AI-hunk PASS for the direct-ws surface. Topology PASS: first-parent pickaxe of `isWebSocketUrl` on `v2026.4.1` hits the candidate, then later commits move the file into `extensions/browser`. But-for NARROW for the named hop. Fix-reversal NARROW: closer `bc356cc8` (PR 60469) adds `assertCdpEndpointAllowed` on the direct-ws branch only. npm `2026.3.8` gitHead equals tag peel `3caab926`. Release of the AI commit versus `v2026.4.5` PASSes and does not promote identity. Uniqueness PASS.

### GHSA-92VG-F4FQ-FXM9 (110, anzory/solidcam-gppl-ide) — NARROW

Identity PASS on the published repository advisory (XXE in VMID parser, CVE-2026-42212). Global advisory 404.

Candidate `d1944bca` equals tag `v1.0.0`. Files are changelog, readme, package.json, and `SolidCAM.GPPL.Server.exe` / `.pdb`. Zero C# files. Claude Opus 4.6 trailer on that ship is not a source hunk. Parent exe lacks `GpplVmidParser` / `ResolveVmidPath` strings; candidate adds them. That is binary evidence, not an atomic source hunk. AI-hunk NARROW. Trailer authorship is not transferred.

Advisory names fix `4939a1b`, which is not in git. Assigned closer `9d0ba808` equals `v1.0.2` and is the same binary pattern with a Claude Opus 4.7 trailer. GitHub Release object for `v1.0.0` is 404. Fix-reversal and release stay NARROW. Uniqueness PASS.

### GHSA-2QRV-RC5X-2G2H (123, openclaw/openclaw) — NARROW

The repository GHSA object exists, is not withdrawn, and names untrusted workspace channel shadows during setup, patched by `53c29df2` in `2026.4.2`. That object is not the assigned member.

Member `fc1b156d` is PR 46763 member 1 of 8, Claude-marked, parent_count=1, and adds `onlyPluginIds` OOM snapshots. `catalog.ts` blob equals parent `a853dcdf`. Human member `b68c5911` authored "Catalog: trust manifest ids". Member is not an ancestor of squash `f4cc93dc`, `v2026.3.22`, or `v2026.4.1`. `loader.ts` blobs are three-way unequal. Do not transfer the member trailer onto the squash even though the squash also quotes Claude.

Identity, AI-hunk (relevant GHSA hunk), topology, but-for, fix-reversal, and release stay NARROW for this candidate. Distinct from GHSA-82QX. Uniqueness PASS versus canonical84.

### GHSA-3J8Q-FWPJ-F8J5 (200, ChurchCRM/CRM) — NARROW, independent row

Two first-party repository advisories, both published, neither withdrawn. Identifier sets do not overlap. They are not formal aliases. They share mechanism fingerprint `churchcrm-notes-object-scope-authorization`. Never count two IDs for that fingerprint.

GHSA-3J8Q is an omnibus of nine findings. Only VULN-02/03 name `notes.php`. Global GHSA-3j8q is 404. Candidate `b3edc225` (PR 8347 squash, Claude Sonnet 4.6, parent_count=1) introduces `notes.php`; parent lacks that file. Family profile and timeline predate the candidate.

Closer `83c19611` (PR 8964 squash) names **GHSA-jjcj-h3cm-p7x7** and also patches sibling family/timeline/photo routes. That is not a notes-only minimum reversal of the candidate boundary. `7.3.3` contains the candidate without the closer; `7.4.0` contains the closer. Release of the notes residual window PASSes and does not promote omnibus identity. Uniqueness PASS versus canonical84. This row remains NARROW and is not counted.

### GHSA-JJCJ-H3CM-P7X7 (200, ChurchCRM/CRM) — REJECT, uniqueness FAIL

`duplicate_mechanism_of` is exactly `GHSA-3J8Q-FWPJ-F8J5`. The first-party object is real and names family profile, family notes, and timeline. That does not mint a second counting unit. `uniqueness_gate=FAIL`. Countable and countable_proposal stay false. Explicit duplicate is fatal in this schema.

## Uniqueness

None of the six reviewed identities is in the canonical84 counted set of 84. GHSA-3WXW remains counted and was not reviewed here. GHSA-82QX stays a different identity and is not substituted in. Shared repository or shared SHA does not merge identities. Equal mechanism fingerprint does not mint a second count. GHSA-JJCJ-H3CM-P7X7 therefore has `uniqueness_gate=FAIL` and is REJECT; GHSA-3J8Q-FWPJ-F8J5 stays the independent NARROW row.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. packet_delta=0. start_count=84. current_leader_accepted_count=84. Publication stays HOLD. Greater-than-200 remains unsupported.

Status is **TERMINAL**. Expansion stopped. No further candidates.
