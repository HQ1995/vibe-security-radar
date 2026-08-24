# Shard 02 adversarial false-positive audit

Coverage: **exactly ordinals 37-72** from `inputs/shard-02.jsonl` against `AUDIT_CONTRACT.md`.
Owned outputs: `shards/shard-02.jsonl`, `reports/shard-02.md`.
JSONL is **36/36**, one compact row per ordinal in order 37–72. Incremental close is done; no further assigned rows remain on this shard. Closed rows stay on disk rather than being held until a final dump.
No canonical ledger, code, manifest, other shards, or caches were edited. No commit.
Temporary clones and raw pages: `/tmp/fp211-shard-02`.

Checkpoint: did not infer CONFIRM to fill coverage. UNKNOWN 48/51/53/56 stay UNKNOWN (no published artifact, unproven AI hunk, or missing tags). Ordinal 52 keep/remove is already written: keep `GHSA-7C3W-FXGH-FRC7`; remove `CVE-2026-61462` + `GHSA-5383-J2P9-QFG3`.

## Verdict counts

| Verdict | n | ordinals |
|---------|---|----------|
| CONFIRM | 13 | 39, 42, 43, 44, 46, 49, 54, 57, 58, 63, 64, 65, 66 |
| NARROW | 10 | 37, 40, 47, 52, 55, 60, 61, 62, 70, 71 |
| FALSE_POSITIVE | 9 | 38, 41, 45, 50, 59, 67, 68, 69, 72 |
| UNKNOWN | 4 | 48, 51, 53, 56 |
| BLOCKED | 0 | — |

Only CONFIRM/HIGH is claim-grade without another review. This shard's CONFIRM rows are 39, 42, 43, 44, 46, 49, 54, 57, 58, 63, 64, 65, 66.

## Public-case counting (this shard)

Audit rows stay mechanism evidence units. User-facing cases count by verified public-advisory identity: prefer a first-party `GHSA-*` as `case_id`; a GHSA and its **formal** CVE alias count once; multiple sinks inside one GHSA stay one case; two GHSAs merge only on first-party formal alias or duplicate publication. Same repository, fix, or mechanism is not an alias.

## Ordinal 52 public IDs (explicit)

`public_ids_keep`: `GHSA-7C3W-FXGH-FRC7`
`public_ids_remove`: `CVE-2026-61462`, `GHSA-5383-J2P9-QFG3`

This row is **one** public case (`GHSA-7C3W-FXGH-FRC7`). The unreviewed CVE wrapper is left explicit in `remove` so it neither silently aliases the first-party GHSA nor inflates a second case from the same mechanism row.

| Public ID | identity_relation | Formal alias of | Mechanism relation | keep/remove |
|-----------|-------------------|-----------------|--------------------|-------------|
| **GHSA-7C3W-FXGH-FRC7** | `FIRST_PARTY_GHSA_NO_CVE` | none (`cve_id` null; global GHSA API 404) | First-party job_id path-forgery under the operator token. Names both `/jobs/${jobId}/trace` and `/jobs/${jobId}/artifacts`. Patched `< 2.1.32`. Trace+artifacts are mechanism children of this **one** GHSA, not two cases. | **keep** (preferred `case_id`) |
| **GHSA-5383-J2P9-QFG3** | `GLOBAL_UNREVIEWED_FORMAL_ALIAS` | **CVE-2026-61462** only (`aliases=[CVE-2026-61462]`, `github_reviewed: false`) | Same job_id `../` path-forgery and same fix `e2a81a04` / issue 587. Not first-party. Does **not** alias GHSA-7C3W. | **remove** |
| **CVE-2026-61462** | `FORMAL_ALIAS` of GHSA-5383 | **GHSA-5383-J2P9-QFG3** only (VulnCheck CNA; no GHSA-7c3w in CNA/ADP) | Same bug publication (issue 587, commit `e2a81a04`) but affected `< 2.1.18` vs first-party 2.1.32. Same-repo/same-fix/same-mechanism is not a formal alias of GHSA-7C3W. | **remove** |

But-for (mechanism, not identity): Claude `c156ac76` adds artifacts tools; parent already had unencoded `trace|play|retry|cancel`. Fix reversal: squash `e2a81a04` encodes job/pipeline IDs and names GHSA-7c3w. Release: `v2.0.32` has origin without fix; `v2.1.32` has `e2a81a04`. Listed member `32a9d408` was missing from the local clone.

## FALSE_POSITIVE counterexamples

- **38** `strict-200-v3:alias-72b82f9a2e737ed2c555363e` `OLD_BUG_PRESERVING_REFACTOR`: Deleting b6115302 leaves the advisory regex injection intact; Path->EscapedPath is an old-bug-preserving backport, not but-for origin
- **41** `strict-200-v3:alias-8215494358ad2dbd50e4323c` `OLD_BUG_PRESERVING_REFACTOR`: PUBLIC_PREFIX_PATHS re-lists an already-public register path; deleting the candidate leaves the advisory bypass
- **45** `strict-200-v3:alias-93fa45f75fcf8a90730ee3e9` `WRONG_EDGE`: Human a1520d70 later adds WRITE_SCOPE; 2a1db0c0 sets plugin-auth scopes to [] and does not restore the 405; Deleting 3e9c8721 leaves the advisory WRITE_SCOPE path
- **50** `strict-200-v3:alias-9b86599ed7002e4df341ef1d` `NOT_CAUSAL`: The candidate delete wrapper never fires the CVE bypass; the fix does not reverse a candidate-specific surface
- **59** `strict-200-v3:alias-b2364e4376391dd977cef4fa` `OLD_BUG_PRESERVING_REFACTOR`: Deleting the Claude parser leaves buildMessageWithAttachments / 1dd5c97a still vulnerable; this is a copied old bug, not but-for
- **67** `strict-200-v3:alias-c45218004b47b9754c596ca1` `SAME_MECHANISM_DUPLICATE`: Source/sink/invariant are materially identical to ordinal 61 (EventTemplatesController Galaxy.find in __setBuilderConfig); 8aa2bb6d completes 61's insufficient listed fix rather than originating a new AI mechanism; No second AI hunk; the residual is a human incomplete-remediation leftover
- **68** `strict-200-v3:alias-c6e0a965a87d452bf5cc44af` `IDENTITY_MISMATCH`: Public IDs do not describe the claimed create_backup write as a distinct origin of credential interpolation; those sinks preexist in DatabaseBackupJob; Same candidate/carrier SHAs as ordinal 35 (CVE-2026-34049 mongo collection via create_backup), so uniqueness fails for this claimed write
- **69** `strict-200-v3:alias-c819cf08c0a8bf17cf425ccc` `UNRELEASED_COMMIT_ONLY`: No published tag contains the weakened check without eb398971; CNA affected 3.0-3.4.0 is false for this rewrite; Claude trailer is also on the fix, which does not make an unreleased pair a released case
- **72** `strict-200-v3:alias-d019f5b5ca91c8bb1d8b320d` `UNRELEASED_COMMIT_ONLY`: No published tag contains the innerHTML sink without cf42409b

## NARROW counterexamples

- **37** `strict-200-v3:alias-7119f1cb6cfa481172422dc5` `AI_NEW_SURFACE_CONTRIBUTOR`: GHSA/CVE describe product-wide missing auth and hardcoded JWT, not origin of those invariants; a7319f0e only adds a new state-changing debug sink; minimum closure is API-wide auth middleware c31f2968 plus RequirePermission on the debug route a82f9278
- **40** `strict-200-v3:alias-81f12adb7f1b7ae03d0c07f1` `AI_NEW_SURFACE_CONTRIBUTOR`: Deleting /v1/responses leaves Tailscale HTTP on parent openai-http.ts; this row is a new call site, not AI_DIRECT_ROOT of Tailscale header auth; same candidate SHA f4b03599 is also used by ordinals 13 and 29 on different mechanisms (trusted-proxy origin; SecretRef capture)
- **47** `strict-200-v3:alias-9764e28bbc2e093b13aaac3e` `AI_NEW_SURFACE_CONTRIBUTOR`: parent already had unbounded req.on(data) on other channel monitors; GHSA is product-wide, not Feishu-only origin; same candidate/carrier SHAs appear on ordinal 124 for missing encrypt-key fail-open, a different mechanism
- **52** `strict-200-v3:alias-9dc5f3e6176baf486fd2696c` `AI_NEW_SURFACE_CONTRIBUTOR`: keep only first-party `GHSA-7C3W-FXGH-FRC7`; remove `CVE-2026-61462`+`GHSA-5383-J2P9-QFG3` (unreviewed formal-alias pair, not an alias of 7C3W). Parent already had unencoded `trace|play|retry|cancel`; artifacts is a new surface of that one GHSA, not a second public case.
- **55** `strict-200-v3:alias-a45f374601ed322c071603fe` `AI_NEW_SURFACE_CONTRIBUTOR`: Candidate is not origin of the missing admin gate on self-hosted; it makes the ungated Updates surface reachable on cloud
- **60** `strict-200-v3:alias-b36a7cd7bcd0e76bbb7491b4` `AI_NEW_SURFACE_CONTRIBUTOR`: Not origin of missing workspaceOnly; it only makes the already-unscoped tool reachable for vision-capable primaries; ordinal 77 shares 8d74578c for a native-media UNC mechanism, which is distinct
- **61** `strict-200-v3:alias-b52bedc69eca463aef477f74` `AI_DIRECT_ROOT`: 8aa2bb6d (ordinal 67) documents that the PHP comparison is not a query condition, so d3adfe1a does not close other-org distribution-0 galaxies; same candidate SHA and same Galaxy.find sink as ordinal 67; listed min-fix is insufficient
- **62** `strict-200-v3:alias-b957cebfc80b884b647c24e8` `AI_NEW_SURFACE_CONTRIBUTOR`: Not origin of unscoped process kill; parent pkill -f already existed; GHSA wording is unvalidated PID kill; the AI sink is a pattern-wide ps|grep|kill of suspended processes
- **70** `strict-200-v3:alias-ca54d2dace0b4a1f719ce3be` `AI_NEW_SURFACE_CONTRIBUTOR`: Not origin of symlink dereference; parent finder already followed links; this row is a new Claude-agents deploy call site of that helper; Copilot is also coauthor on the fix, which does not change origin
- **71** `strict-200-v3:alias-cfe8a69b17c7144c755c5961` `AI_NEW_SURFACE_CONTRIBUTOR`: Not origin of pre-auth transcription; it activates a latent detector bug; Fix topology is a squash/rebase; 295bc874 recovered via API is absent from the fixed tag

## UNKNOWN (preserved)

- **48** `strict-200-v3:alias-994d3f3f9e29079393c87538` `RELEASE_CONTAINMENT_UNPROVEN`: No published git tag or package was shown to contain origin without the SSRF repair
- **51** `strict-200-v3:alias-9c7a2c50a4f4725177cca843` `UNKNOWN_AI_HUNK`: f0555341 body is only 'Generated by staged fix workflow'; author Coy Geek; no Co-Authored-By; /tmp/fp211-shard-02/pages/pr-14876.json title/body are CommandAuthorized hardcoded true, not pairing-store AI attribution
- **53** `strict-200-v3:alias-9dd227fdd8e2b88da77a7ff2` `UNKNOWN_UNPUBLISHED_ARTIFACT`: No published artifact containing origin without isDeliverableUrl was recovered; Do not treat the fix-PR merge SHA as the origin carrier
- **56** `strict-200-v3:alias-a57df415a930e4db1ef3b6f7` `UNKNOWN_UNPUBLISHED_ARTIFACT`: No currently fetchable published artifact contains origin without 57b76343; ordinal 84 uses 57b76343 as a candidate SHA for a different later mechanism

No BLOCKED row: GitHub auth, local clones, and `/tmp/fp211-shard-02` clones were enough to inspect every ordinal. Missing *published artifacts* were recorded as UNKNOWN, not BLOCKED.

## Primary-source citations (non-exhaustive)

- Repo advisories under `/tmp/fp211-shard-02/pages/repo-GHSA-*.json` for global-404 GHSAs: X9QH, 378W, 7C3W, 8JQH, C339, 6MWV, 4VFF.
- Harvest diffs: `/tmp/fp211-shard-02/evidence/NNN/{harvest.json,candidate.diff,fix.diff}`.
- npm packuments: `/tmp/fp211-shard-02/pages/npm-agentic-flow.json`, `npm-taylored.json`.
- PR mismatch for 51: `/tmp/fp211-shard-02/pages/pr-14876.json`.
- Clones: cache `~/.cache/cve-analyzer/repos/` plus `/tmp/fp211-shard-02/clones/{gitlab-mcp,wacrm,mail-mcp-bridge,apm,clawdbot-feishu,cti-transmute}`.

## Replay commands

Per-row `replay_commands` are in the JSONL. Shard-wide conservation:

```bash
python3 -c 'import json,pathlib; p=pathlib.Path("autoresearch/orchestrator-260813-fp211-audit/shards/shard-02.jsonl"); rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]; assert len(rows)==36; assert [r["ordinal"] for r in rows]==list(range(37,73))'
python3 autoresearch/orchestrator-260813-fp211-audit/verify.py --allow-partial
git diff --stat -- autoresearch/orchestrator-260813-fp211-audit/shards/shard-02.jsonl autoresearch/orchestrator-260813-fp211-audit/reports/shard-02.md
```

Representative git checks used during inspection:

```bash
git -C ~/.cache/cve-analyzer/repos/maziggy_bambuddy show a7319f0e7087 -- backend/app/api/routes/printers.py
git -C ~/.cache/cve-analyzer/repos/rancher_fleet show b6115302142d -- pkg/webhook/webhook.go
git -C /tmp/fp211-shard-02/clones/clawdbot-feishu grep -n feishu_img_ a604df8c83d1 -- src/media.ts
git -C /tmp/fp211-shard-02/clones/gitlab-mcp grep -n 'jobs/${jobId}/artifacts' c156ac767520^ -- index.ts
git -C ~/.cache/cve-analyzer/repos/misp_misp show 8aa2bb6d1af6 -- app/Controller/EventTemplatesController.php
git -C ~/.cache/cve-analyzer/repos/mruby_mruby merge-base --is-ancestor cf8faed585e1 3.4.0
git -C /tmp/fp211-shard-02/clones/cti-transmute merge-base --is-ancestor 5a4344884f93 v1.3
```

## Limitations

- Did not treat baseline PASS/REJECT/NARROW/UNKNOWN, OSV `introduced`, or prior votes as proof.
- Global GHSA 404s were not treated as missing identity when a repo advisory existed.
- Squash members absent from tags were accepted only after the carrier blob showed the same sink (44, 47, 62).
- Quay (48), wacrm (53), and taylored 7.0.5-7.0.8 (56) have no currently fetchable vulnerable artifact; UNKNOWN is preserved rather than inferred FAIL/unreleased.
- Ordinal 51's pairing-store hunk is real, but AI provenance is unproven (staged-fix workflow; PR #14876 is CommandAuthorized).
- Ordinal 61 listed fix `d3adfe1a` is insufficient; 67 is the residual closer of the same sink and is counted as a duplicate, not a second origin.
- Ordinal 52 packs two public identities onto one mechanism row. First-party `GHSA-7C3W` is kept as `case_id`; the unreviewed `GHSA-5383`/`CVE-2026-61462` pair is explicit in `public_ids_remove` (not a formal alias of 7C3W, not a second mechanism case).
- Cache clones were read-only; extra fetches lived under `/tmp/fp211-shard-02` only.

## Reusable lessons

1. **Carrier/import Claude trailer ≠ origin member.** Feishu rows 42/58/65/66: origin is `a604df8c` or `4286755f`; `2267d58a` is import.
2. **CVE "fix" URL can be the merge of the fix PR** (53: `23838a99`), not origin.
3. **Same SHA, distinct mechanism** does not fail uniqueness (40 vs 13/29; 54 vs 15/33; 58 vs 31; 47 vs 124; 60 vs 77). **Same source/sink/invariant does** (61 vs 67; 68 vs 35).
4. **Old-bug-preserving refactors:** Path→EscapedPath, includes→PUBLIC_PREFIX_PATHS, copied Buffer.from-before-limit, CRUD delete wrapper.
5. **New call site of an old helper is NARROW**, not CONFIRM/HIGH product origin (37, 40, 47, 52, 55, 60, 62, 70, 71).
6. **Unreleased:** candidate and fix in the same published tag, or CNA "dev branch only" (69, 72). Missing tags without that proof stay UNKNOWN (48, 53, 56).
7. **Staged-fix / Conductor / Jules / Rovo** still need a relevant-hunk AI marker. Jules on 56 passed; staged-fix on 51 did not; Conductor on 68 is not the advisory hunk.
8. **Public cases count by advisory identity, not mechanism.** Prefer first-party `GHSA-*` as `case_id`. A GHSA and its formal CVE alias count once. Same-mechanism unreviewed CVE wrappers are not aliases of a first-party no-CVE GHSA (ordinal 52: keep `GHSA-7C3W`, remove `CVE-2026-61462`+`GHSA-5383`). Multiple sinks named by one GHSA stay one case.
9. **PHP `'Galaxy.distribution' > 0` inside a conditions array** is not SQL. Insufficient listed fixes fail reversal (61) and must not mint a second counted origin (67).
10. **`introduced: 0` / CNA affected ranges** overclaim inherited bugs and unreleased rewrites.

Mechanical 36/36 coverage is not proof that every CONFIRM is final. Independent review is still required for every non-CONFIRM/HIGH row and before promoting CONFIRM/HIGH into a rebuilt HOLD ledger.
