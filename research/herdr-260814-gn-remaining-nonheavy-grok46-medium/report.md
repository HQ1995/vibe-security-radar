# G-N remaining non-heavy packet (proposal only)

Verdict: **0 PASS_PROPOSAL / 12 REJECT / TERMINAL**. Canonical94 stays 94. Countable pass 0. Greater-than-200 remains unsupported. Worker PASS is proposal only and this packet emits none.

## Selector and conservation

Source universe is G-N subject-only intersections (no matched_ai_commit_refs, has subject_overlap_hits): 640. Drop the 7 identities in canonical85 strict/excluded/negatives or the G-N source-shard terminal cases.jsonl. Foundation-only GHSA-V52W-28XH-V562 stays in the 633, matching CF2. CF2 conserved 633=14 inspected+619 remaining. Reconstruct remaining by subtracting the CF2 assignment 14.

As of assignment freeze, subtract canonical94 overlap (0 in remaining) and 161 later TERMINAL verdict identities that sit inside that remaining set. After subtract: 458. Heavy repos n8n-io/n8n, go-gitea/gitea, jdx/mise, MervinPraison/PraisonAI, gogs/gogs stay UNREVIEWED (234 of 458). Non-heavy 224.

Hard-qualify: first-party, not withdrawn, same-repo closer, and summary matches incomplete/residual/bypass or added/new-surface/MCP language. Pool size 13. Rank (new AND inc, new, inc, gid). Inspect the strongest 12. Leave GHSA-33G4-646G-QWMM UNREVIEWED. Did not pad. Do not inherit CF2 labels.

Source hashes: G-N cases `47538e731f8c4979651ff36ead7063ea23a1adc05e551a99ae94ceaafd835b2d`, G-N result `4443df9d098302be1b3fc3b73dbdc0ae7b76471a5f2f67aeed97c98ec1d6c08a`, CF2 cases `cc50fc12ef27f9e417acd6e58f2bd4bbbfb7e8a43c8f9f1234b0296ea31b8437`, CF2 result `0f3e056a36daec32658ffd9434def475308b9d9ff452ee5686c7862e46d2ff97`, canonical94 ledger `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`, CONTRACT.md `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.

Overbroad `Co-authored-by:.*anthropic` is invalid. Hits use production source_matcher. Human vendor email is not AI. Local advisory-database HEAD `a42c436870111aa3f221257c9d56126a93173ccc`. No GitHub REST/GraphQL. No credentials.

## REJECT counterevidence (rebuilt gates)

- GHSA-C73C-X77G-854R (openclaude): MCP OAuth `!error && state` lives in root import `d2542c9a628b` (n_parents 0, not policy-AI). Claude overlap is version-gate/provider routing. Closer `739b8d1f40fd` is human atomic. Tags absent; `c0b8a59a2377` is a 0.5.1 bump and is not a tag.
- GHSA-XH92-RQRQ-227V (mastra): `docs.ts` add `65f2a4ca3734` is Tyler Barnes. Closer-parent blame is human path-validation. Claude overlap is requiresAuth on a different server package.
- GHSA-382C-VX95-W3P5 (gittensory): Claude `eb440f1f5ea7` adds gated `/v1/extension/contributors/*` routes. Vulnerable `/v1/contributors/:login/profile` already exists on closer parent. Blame on the inserted gate is human `a613357f6d59`.
- GHSA-RMXW-PQ4X-3FVH / GHSA-HQ33-8JGP-8QQ3 / GHSA-964W-F6GJ-5236 (goshs): overlap is ConPtyShell `ccf4e5fc7baa`. Closers blame human ACL/webdav/upload history. Residual of a human parent fix is not AI incomplete-remediation.
- GHSA-PV22-FQCJ-7XWH (inspektor-gadget): closer is a two-parent merge carrier. Overlap is a GPU telemetry design doc. topology_gate FAIL.
- GHSA-MMG9-6M6J-JQQX / GHSA-9R5M-9576-7F6X (liquidjs): Cursor `8a0c74a7fcb1` hardens pop/array, not replace or limiter. Closers blame human mem-limit commits. Shared SHA does not merge the two GHSAs.
- GHSA-M6RX-7PVW-2F73 (openclaude sandbox): bashPermissions.ts comes from the same human root import. Overlap version-gate is routing. Distinct from C73C.
- GHSA-G9XJ-752Q-XH63 (vikunja): avatar.go add is human. AI OpenID issuer uniqueness is a sibling auth feat.
- GHSA-FW9Q-39R9-C252 (langsmith): lodash.set inline `a872906b8f0c` is human incomplete remediation of lodash. Claude overlap is js-yaml deps and v2 client resources.

## Conservation

640 = 7 + 633. 633 = 14 + 619. 619 = 161 later terminal + 458. 458 = 234 heavy + 224 non-heavy. 13 hard-qualified = 12 inspected + 1 leftover. Packet 12 = 12 REJECT + 0 unreviewed. PASS_PROPOSAL 0. Packet delta 0. No edits outside this owned directory. No commit or push.
