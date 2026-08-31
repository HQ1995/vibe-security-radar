# Provisional closure — shard 04

Date: 2026-08-31  
Scope: eight assigned provisional records only.  
Method: vulnerability-first review under [`docs/AUDIT-PROTOCOL.md`](../../docs/AUDIT-PROTOCOL.md), using the current publisher snapshot, the local full-history clones, first-party GitHub advisories, commit objects, immediate-parent trees, and tag ancestry. A gate is `PASS` only when those sources close it; contradictions are `FAIL`, and missing reconstruction remains `UNKNOWN`.

## Disposition

| Case | Outcome | Necessary action |
|---|---|---|
| CVE-2026-40583 | `RESEARCH_GAP` | Keep provisional: exact origin/fix close, but no tagged vulnerable or fixed release contains them. |
| GHSA-P7MM-R948-4Q3Q | `READY_TO_BACKFILL` | Correct the causal class to direct AI root and add tag witnesses. |
| GHSA-75HX-XJ24-MQRW | `READY_TO_BACKFILL` | Fill the three missing gates and narrow the candidate's claimed scope. |
| GHSA-HHFF-FJ5F-QG48 | `READY_TO_BACKFILL` | Record the human dormant origin and AI activation separately. |
| GHSA-VFGX-5Q85-58Q3 | `READY_TO_BACKFILL` | Replace the refactor/carrier with the true first writer. |
| GHSA-J48Q-4C78-RHF9 | `READY_TO_BACKFILL` (merge-only) | Delete the standalone provisional record and merge the GHSA into the existing Whirlpool class; do not publish `cb07e5f8 -> 963d0d1` as a closed pair. |
| GHSA-8X4M-QW58-3PCX | `RESEARCH_GAP` | Clear the unrelated header-serialization chain and reconstruct the advisory's ten payment branches. |
| GHSA-P6Q4-FGR8-VX4P | `NOT_AI_REVIEW` | Human BIC; keep the Copilot partial fix only in the separate incomplete-remediation class. |

## 1. CVE-2026-40583 / GHSA-q8wx-2crx-c7pp

**Gate recommendation:** `identity=PASS`, `ai_hunk=PASS`, `topology=PASS`, `but_for=PASS`, `fix_reversal=PASS`, `release=FAIL`, `uniqueness=PASS`.

- The [vendor advisory](https://github.com/UltraDAGcom/core/security/advisories/GHSA-q8wx-2crx-c7pp) and [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-40583) describe the same `SmartOp::Vote` order: fee/nonce mutation precedes council authorization, the finalized-error path increments nonce again, and the supply invariant halts the node.
- [`361e71d4329b672482531122117631ec5358953a`](https://github.com/UltraDAGcom/core/commit/361e71d4329b672482531122117631ec5358953a) is a one-parent first writer. Parent `8fc13090d657934b74bcdc6f770433f60cb81130` has no `apply_smart_op_tx`; the commit adds the vulnerable Vote path and carries a Claude Opus 4.6 co-author trailer.
- [`45bcf7064741897319b6196d3d9f9e1307093511`](https://github.com/UltraDAGcom/core/commit/45bcf7064741897319b6196d3d9f9e1307093511) is the minimum direct reversal for the advisory's Vote/CreateProposal path: it moves council checks before mutation and removes the outer double increment. [`2f5a3a237ea519b48d71e6e3093c89f60694c7be`](https://github.com/UltraDAGcom/core/commit/2f5a3a237ea519b48d71e6e3093c89f60694c7be) is later all-SmartOp hardening, not the minimum fix for the disclosed path.
- Release contradiction: tags `v0.1.0` (`3b0589a2…`) and `latest` (`a82ffe84…`) predate the BIC; no tag contains the BIC or either fix. The vendor advisory lists affected `0.1` and patched versions `None`, so the current `vulnerable_release.version=0.1.0` is not a Git-containment witness.

**Field corrections:** repository and every commit URL must use `UltraDAGcom/core`, not `sumitshahorg/core`; set `minimum_fix_set=[45bcf706…]` and retain `2f5a3a23…` as follow-up hardening; clear the asserted `0.1.0` release witness and set `fixed_release=null`; add `unresolved_reason="No public tag contains 361e71d4 or either advisory-linked fix; the vendor advisory declares no patched version."` Keep `AI_ROOT_CAUSE` / `AI_DIRECT_ROOT`, but remain provisional.

Primary local source: `.ai-slop/state/legacy87/clones/UltraDAGcom_core`.

## 2. GHSA-P7MM-R948-4Q3Q

**Gate recommendation:** `identity=PASS`, `ai_hunk=PASS`, `topology=PASS`, `but_for=PASS`, `fix_reversal=PASS`, `release=PASS`, `uniqueness=PASS`.

- The [first-party advisory](https://github.com/paperclipai/paperclip/security/advisories/GHSA-p7mm-r948-4q3q) identifies the authenticated request body's `decidedByUserId` flowing into the authoritative approval row and budget-policy attribution.
- [`abadd469bc85e9fa5137ff5ffce433f1c2db2c0b`](https://github.com/paperclipai/paperclip/commit/abadd469bc85e9fa5137ff5ffce433f1c2db2c0b) first adds the approval routes/services and the body-to-database sink; parent `8c830eae70a14723749828f0ce5d9ae435270e9c` has only the shared validator, not this reachable sink. The BIC has a Claude Opus 4.6 trailer.
- [`32a9165ddf6308f3b46eae0653b6f583e502e538`](https://github.com/paperclipai/paperclip/commit/32a9165ddf6308f3b46eae0653b6f583e502e538) removes the body field and derives the deciding identity from `req.actor.userId` on approve/reject/request-revision.
- `canary/v2026.415.0-canary.0` through `.2` contain the BIC but not the fix; `.3` contains the fix; stable `v2026.416.0` contains both. Sharing the large BIC with GHSA-GWMJ-HF32-5V8V and the aggregate fix with GHSA-XFQJ-R5QW-8G4J is not duplication: those advisories have different entry points, sinks, and mechanisms.

**Field corrections:** `ledger_status=AI_ROOT_CAUSE`, `contribution_class=AI_DIRECT_ROOT`, `candidate_set=[abadd469…]`, parent `8c830eae…`, `minimum_fix_set=[32a9165d…]`; add the vulnerable/fixed tag witnesses above and a scope statement limited to approval decision attribution (not every security change in either aggregate commit). Fill all seven gates `PASS`.

Primary local sources: `.ai-slop/state/repos/paperclipai_paperclip` and `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/04/GHSA-p7mm-r948-4q3q/GHSA-p7mm-r948-4q3q.json`.

## 3. GHSA-75HX-XJ24-MQRW

**Gate recommendation:** `identity=PASS`, `ai_hunk=PASS`, `topology=PASS`, `but_for=PASS`, `fix_reversal=PASS`, `release=PASS`, `uniqueness=PASS`.

- The [first-party advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-75hx-xj24-mqrw) covers unauthenticated MCP session termination plus operational metadata disclosure.
- [`a597ef5a924ebe17a6a202bbb841965f52328032`](https://github.com/czlonkowski/n8n-mcp/commit/a597ef5a924ebe17a6a202bbb841965f52328032) first adds unauthenticated `DELETE /mcp`, active GET session handling, and session identifiers in `/health`; parent `a4053de998595b4321576ad6a908e65590816ee0` lacks those causal additions. The BIC is explicitly generated/co-authored by Claude Code.
- [`ca9d4b3df6419b8338983be98f7940400f78bde3`](https://github.com/czlonkowski/n8n-mcp/commit/ca9d4b3df6419b8338983be98f7940400f78bde3) adds the shared authentication guards to GET/DELETE `/mcp` and reduces `/health` to liveness data. Tag `v2.47.5` contains the BIC and not the fix; `v2.47.6` contains both.
- GHSA-PFM2-2MHG-8WPX also uses the large feature BIC but concerns secret-bearing debug logs and has a different fix (`ef9a8562…`); the mechanisms are unique when scoped.

**Field corrections:** retain the current candidate/fix and `AI_ROOT_CAUSE` / `AI_DIRECT_ROOT`; add parent `a4053de9…`, tag witnesses, and a scope statement limited to DELETE/GET MCP authentication plus health metadata. Do not attribute later health fields that `a597ef5a…` did not write. Fill all seven gates `PASS`.

Primary local sources: `.ai-slop/state/repos/czlonkowski_n8n-mcp` and `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/04/GHSA-75hx-xj24-mqrw/GHSA-75hx-xj24-mqrw.json`.

## 4. GHSA-HHFF-FJ5F-QG48 / CVE-2026-41374

**Gate recommendation:** `identity=PASS`, `ai_hunk=PASS`, `topology=PASS`, `but_for=PASS`, `fix_reversal=PASS`, `release=PASS`, `uniqueness=PASS`.

- The [maintainer advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-hhff-fj5f-qg48) explicitly narrows the issue to pre-authorization resource consumption, not a general authorization bypass.
- Human commit [`a2ddcdadebfe0c18dab38816be097a094888d03e`](https://github.com/openclaw/openclaw/commit/a2ddcdadebfe0c18dab38816be097a094888d03e) placed transcription before member authorization but used the nonexistent camelCase `contentType`, leaving the path dormant. AI-marked [`b9b47f50023d9f6384372bad6eee1a181b98c48e`](https://github.com/openclaw/openclaw/commit/b9b47f50023d9f6384372bad6eee1a181b98c48e) changes it to Discord's real `content_type`, making the pre-auth path live; parent `319b7c68a1add87eaca148cfe3d3df422ec180f4` lacks that activating hunk.
- [`ee52f64226a03efadfdf1e3b759e13424a3d4e41`](https://github.com/openclaw/openclaw/commit/ee52f64226a03efadfdf1e3b759e13424a3d4e41) gates transcription on member access and adds the unauthorized-member regression. `v2026.3.28` contains the human origin and AI activation but not the fix; `v2026.3.31` contains all three.

**Field corrections:** retain `candidate_set=[b9b47f5…]`, `minimum_fix_set=[ee52f642…]`, `AI_ROOT_CAUSE`, and `AI_NEW_SURFACE_CONTRIBUTOR`; explicitly store `preexisting_human_origin=a2ddcdad…` and parent `319b7c68…`; scope the mechanism to activation of the dormant preflight path. Fill all seven gates `PASS`.

Primary local sources: `.ai-slop/state/repos/openclaw_openclaw` and `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/04/GHSA-hhff-fj5f-qg48/GHSA-hhff-fj5f-qg48.json`.

## 5. GHSA-VFGX-5Q85-58Q3

**Gate recommendation:** `identity=PASS`, `ai_hunk=PASS`, `topology=PASS`, `but_for=PASS`, `fix_reversal=PASS`, `release=PASS`, `uniqueness=PASS`.

- The [first-party advisory](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-vfgx-5q85-58q3) identifies Mersenne-Twister/weak seeded selection of steganography pixels and samples.
- Current candidate `990c09c4…` is not the BIC: its parent already contains `random.seed`, `random.sample`, and NumPy weak-seed paths; it is a move/refactor into the plugin layout. The first writer is [`5f60678d7da2eef6404355ecdad28148cb1a37f7`](https://github.com/jahlives/openssl_encrypt/commit/5f60678d7da2eef6404355ecdad28148cb1a37f7), whose parent `f2e251b13b9b23c0509762e2c99c1735fa9b7544` has no steganography code. The actual BIC also carries Claude Code generation and co-author markers.
- [`09e96e090417d34d2f533f6810d3cd4f77810101`](https://github.com/jahlives/openssl_encrypt/commit/09e96e090417d34d2f533f6810d3cd4f77810101) replaces the password-keyed pixel/sample shuffles with HMAC-SHA256-derived deterministic shuffles. `v1.3.0` and `v1.3.6` contain the BIC but not the fix; `v1.4.0` contains both.

**Field corrections:** `candidate_set=[5f60678d…]`, parent `f2e251b1…`, `carrier_set=[990c09c4…]`, `minimum_fix_set=[09e96e09…]`; keep `AI_ROOT_CAUSE` / `AI_DIRECT_ROOT`, update candidate URL/hunks/patch hash to the true first writer, and fill all gates `PASS`.

Primary local sources: `.ai-slop/state/repos/jahlives_openssl_encrypt` and `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-vfgx-5q85-58q3/GHSA-vfgx-5q85-58q3.json`.

## 6. GHSA-J48Q-4C78-RHF9

**Gate recommendation for the current standalone record:** `identity=PASS`, `ai_hunk=PASS`, `topology=PASS`, `but_for=PASS`, `fix_reversal=FAIL`, `release=FAIL`, `uniqueness=FAIL`.

- The [vendor advisory](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-j48q-4c78-rhf9) names the `hash_registry.py` `whirlpool*py313*.so` glob followed by `ExtensionFileLoader.exec_module`.
- AI-marked [`f6770c1e774ff46a591257c1e62063f39a6f568b`](https://github.com/jahlives/openssl_encrypt/commit/f6770c1e774ff46a591257c1e62063f39a6f568b) first writes that exact registry branch. The product-wide mechanism existed earlier in AI-marked [`cb07e5f88a98f4459a5f828142e740c024810692`](https://github.com/jahlives/openssl_encrypt/commit/cb07e5f88a98f4459a5f828142e740c024810692), which added broad native-module globs, unauthenticated selection, symlink/copy, and import in `setup_whirlpool.py`.
- Claimed fix [`963d0d1278b722ea134272f9df65fddcd3e6ab47`](https://github.com/jahlives/openssl_encrypt/commit/963d0d1278b722ea134272f9df65fddcd3e6ab47) changes only `setup_whirlpool.py`; it does not touch the advisory-quoted registry loader. Tag `v1.4.0` contains `f6770c1e…`, the unchanged loader, and `963d0d1…`, so both fix-reversal and release claims fail.
- The current site already has confirmed class `alias-0ae1e9b85f4a9eebb8ee56b3` (GHSA-CCP9-5G7C-PJ86 / CVE-2026-74872) for the same product-wide Whirlpool mechanism, with the same `cb07e5f8…` origin. A second standalone class is a duplicate. No release through `v1.4.9` contains the actual removal [`fdb5d72999914f5604a419225949db669d4be3f2`](https://github.com/jahlives/openssl_encrypt/commit/fdb5d72999914f5604a419225949db669d4be3f2).

**Field corrections:** remove standalone class `alias-bf499d08da8dae005eecbbc0`; add GHSA-J48Q-4C78-RHF9 to `alias-0ae1e9b85f4a9eebb8ee56b3`; keep `candidate_set=[cb07e5f8…]`, record `f6770c1e…` as a later duplicate/carrier, and remove `963d0d1…` from `minimum_fix_set`. Model the merged class as unpatched through `v1.4.9`, with `fdb5d729…` only as an unreleased potential-fix reference. The outcome is merge-ready, **not** permission to confirm the current standalone pair.

Primary local sources: `.ai-slop/state/repos/jahlives_openssl_encrypt`, `web/src/generated/research-data.json`, and `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-j48q-4c78-rhf9/GHSA-j48q-4c78-rhf9.json`.

## 7. GHSA-8X4M-QW58-3PCX

**Gate recommendation:** `identity=FAIL`, `ai_hunk=UNKNOWN`, `topology=UNKNOWN`, `but_for=FAIL`, `fix_reversal=FAIL`, `release=FAIL`, `uniqueness=UNKNOWN`.

- The [first-party advisory](https://github.com/wevm/mppx/security/advisories/GHSA-8x4m-qw58-3pcx) covers multiple `tempo/charge` and `tempo/session` payment-bypass/replay/griefing branches fixed in `0.4.8`.
- Current [`2566a1a0c2d9b8b2a80a4afbc1a95c9f6b7e56ba`](https://github.com/wevm/mppx/commit/2566a1a0c2d9b8b2a80a4afbc1a95c9f6b7e56ba) -> [`81ba76322f7d77af9e9466fcf6788a296d6fc543`](https://github.com/wevm/mppx/commit/81ba76322f7d77af9e9466fcf6788a296d6fc543) chain is a description/header quoting issue from a different release line. It has no path to charge/session payment validation and cannot satisfy advisory identity or but-for.
- `mppx@0.4.7..mppx@0.4.8` shows a large aggregate [`1092d43eeecefd4a8e675d4b753103e3eca105a8`](https://github.com/wevm/mppx/commit/1092d43eeecefd4a8e675d4b753103e3eca105a8) touching charge/session validation and tests. It is a fix lead, not proof of one atomic fix or any of the ten origin/parent/AI boundaries.

**Field corrections:** clear the current candidate, fix, mechanism, code hunks, and AI attribution from this advisory class; keep the advisory/repository/version identity; set `unresolved_reason="Published record is bound to an unrelated header-serialization vulnerability; the 0.4.8 charge/session aggregate has not been decomposed into the advisory's ten causal branches."` Do not mark any unknown gate `PASS` until each branch has an atomic BIC, parent absence, direct reversal, AI marker, and release witness.

Primary local sources: `.ai-slop/state/repos/wevm_mppx` and `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-8x4m-qw58-3pcx/GHSA-8x4m-qw58-3pcx.json`.

## 8. GHSA-P6Q4-FGR8-VX4P

**Gate recommendation:** `identity=PASS`, `ai_hunk=FAIL`, `topology=PASS`, `but_for=PASS`, `fix_reversal=PASS`, `release=PASS`, `uniqueness=PASS`.

- The [first-party advisory](https://github.com/scriban/scriban/security/advisories/GHSA-p6q4-fgr8-vx4p) describes the nested-array recursive descent path. Root commit [`46054810b50b03a6d19cd51886321cbbefa5d589`](https://github.com/scriban/scriban/commit/46054810b50b03a6d19cd51886321cbbefa5d589) first creates `ParseArrayInitializer` and its recursive expression path; it is authored/committed by Alexandre Mutel in 2016 and has no BIC-local AI marker.
- Copilot-marked [`f55280a09575e577fcf7f5629007e0814594e3ac`](https://github.com/scriban/scriban/commit/f55280a09575e577fcf7f5629007e0814594e3ac) is a remediation attempt, not the BIC. The later [GHSA-6Q7J-XR26-3H2C](https://github.com/scriban/scriban/security/advisories/GHSA-6q7j-xr26-3h2c) establishes that this guard only logged and continued recursion. Human [`8fdbd687bbe8f00085c4c4c5b2b3b8d529933949`](https://github.com/scriban/scriban/commit/8fdbd687bbe8f00085c4c4c5b2b3b8d529933949) is the full stop-parsing closure.
- Tag `7.2.0` contains the human root and Copilot partial but not `8fdbd687…`; `7.2.1` contains the final closure. This reconciles the original advisory's obsolete `7.0.0` “fixed” boundary with the later maintainer advisory. The root-vulnerability NOT_AI class and the separate AI incomplete-remediation class are unique when their roles are not mixed.

**Field corrections:** send this record to `NOT_AI_REVIEW` with `introducer_sha=46054810…`, human author kind/name, `direct_fix_sha=8fdbd687…`, vulnerable witness `7.2.0`, and fixed witness `7.2.1`; remove `AI_CODE_FLAWED` and all claims that the Copilot marker belongs to the BIC. Keep `f55280a0… -> 8fdbd687…` exclusively in confirmed class `alias-469595425f9374edbd871410` as `AI_INCOMPLETE_REMEDIATION`.

Primary local sources: `.ai-slop/state/repos/scriban_scriban`, `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-p6q4-fgr8-vx4p/GHSA-p6q4-fgr8-vx4p.json`, and `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/06/GHSA-6q7j-xr26-3h2c/GHSA-6q7j-xr26-3h2c.json`.

## Backfill boundary

Ready without additional causal research: P7MM, 75HX, HHFF, VFGX, plus J48Q as an alias-merge/de-duplication only. CVE-2026-40583 and GHSA-8X4M must remain provisional with explicit unresolved reasons. GHSA-P6Q4 must leave the AI publication set and enter NOT_AI review. No recommendation above changes a `FAIL` or `UNKNOWN` gate to `PASS` by inference.
