# herdr-260814-w2-1-ds — unreviewed-adj2 adjudication slice-1

**Verdict-first: 25/25 FALSE_POSITIVE. 0 countable, 0 PASS proposals.**

No candidate AI commit introduces the named advisory mechanism. Every candidate either touches files disjoint from the mechanism file, names a different product (identity mismatch), is a non-code supply-chain tag incident, or (where the diff was read) only refactors the mechanism file without adding the vulnerable sink. Packet delta = 0; the canonical count is unchanged and publication stays HOLD.

## Method

- Advisory mechanism read from the local advisory-database clone `advisories/unreviewed/` (origin/main FETCH_HEAD 8b901fa43d0e3d09e9bece095afb760dd9dff6e8).

- Candidate diffs read from the sweep pool `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`. Five missing repos were fetched via git smart-HTTP blobless clone (666ghj__BettaFish, mealie-recipes__mealie, npuwyw__PX4-Autopilot, tiddly-gittly__TidGi-Desktop, zevorn__rt-claw). No GitHub API, no blame/SZZ.

- Disjoint-file rows: `changed_files` evidence (`git diff-tree --name-only -r <sha>`). Same-file/adjacent rows: `diff_read` evidence (full `git show <sha> -- <file>`).

## Gates

identity=NARROW (unreviewed GHSA; FAIL on the two cross-product rows #4, #8), ai_hunk=FAIL, topology=NARROW, but_for=FAIL, fix_reversal=UNKNOWN (no fix ref in this lane), release=UNKNOWN, uniqueness=PASS (none of the 25 ids/aliases are in foundation.jsonl).

## Per-row

| # | GHSA | CVE | repo | mechanism file | candidate(s) | class | verdict |
|---|---|---|---|---|---|---|---|
| 1 | GHSA-QR7M-7592-RCVX | CVE-2026-57999 | openwrt/luci | luci-app-tailscale (do_login RPC) | a31eccfa,a5bedae6 | DISJOINT | FALSE_POSITIVE |
| 2 | GHSA-V6HV-2P8R-43V4 | CVE-2026-14687 | 666ghj/BettaFish | InsightEngine/agent.py | 745f5970,ae738e8a,5d90e7ff | DISJOINT | FALSE_POSITIVE |
| 3 | GHSA-7W79-PF8W-RG85 | CVE-2026-16016 | poco-ai/poco-claw | executor/app/api/v1/task.py | 02e5b695,7e26d41c,5ee19532 | DISJOINT | FALSE_POSITIVE |
| 4 | GHSA-8QFV-2G3C-H5JC | CVE-2026-16252 | gtsteffaniak/filebrowser | (unrelated JSP product) | b08c6c23,21dfc616,4708faec | IDENTITY_MISMATCH | FALSE_POSITIVE |
| 5 | GHSA-9HHJ-2JWX-R87P | CVE-2026-65315 | ollama/ollama | llm/gguf parser | 810d4f9c,b1d711f8,5e23c4f2 | DISJOINT | FALSE_POSITIVE |
| 6 | GHSA-72F8-2PFX-XX29 | CVE-2025-51684 | CleverTap/clevertap-web-sdk | src/util/clevertap.js renderCustomHtml | 566a2cc8,3b74c499,1dae6b88 | DISJOINT | FALSE_POSITIVE |
| 7 | GHSA-R7MX-568F-JGG3 | CVE-2026-11770 | 389ds/389-ds-base | replication C plugin (CleanAllRUV) | b90d03e0,22278a4e,87ef5060 | DISJOINT | FALSE_POSITIVE |
| 8 | GHSA-J255-R942-27Q8 | CVE-2026-19019 | poco-ai/poco-claw | poco-agent workspace.py | 02e5b695,7e26d41c,5ee19532 | IDENTITY_MISMATCH | FALSE_POSITIVE |
| 9 | GHSA-FCM7-V7R7-PVHR | CVE-2026-72586 | frangoteam/FUXA | server/runtime/index.js DAQ_QUERY | 8b56f14f,b4da1928,0861aa81 | DISJOINT | FALSE_POSITIVE |
| 10 | GHSA-96G7-R737-95HV | CVE-2025-70297 | mealie-recipes/mealie | media/SVG serving | cee2c351,874dc94d,9247204f | DISJOINT | FALSE_POSITIVE |
| 11 | GHSA-CX65-RPP3-QF6C | CVE-2025-70296 | mealie-recipes/mealie | Recipe Notes rendering | cee2c351,874dc94d,9247204f | DISJOINT | FALSE_POSITIVE |
| 12 | GHSA-HWQ5-3473-H97Q | CVE-2026-26741 | npuwyw/PX4-Autopilot | commander mode switch | 56327284,12745baf,efbc9e64,ec436d3b | DISJOINT | FALSE_POSITIVE |
| 13 | GHSA-R53Q-GCFW-Q36C | CVE-2026-26742 | npuwyw/PX4-Autopilot | commander re-arm grace | 56327284,12745baf,efbc9e64,ec436d3b | DISJOINT | FALSE_POSITIVE |
| 14 | GHSA-G938-H978-WF7V | CVE-2021-47986 | parse-community/parse-server | version tags (no code) | 34a6cf16,d3d6e9e2,756c2042,8eeab8dc | SUPPLY_CHAIN_TAG | FALSE_POSITIVE |
| 15 | GHSA-H6QH-8R3C-PC9V | CVE-2021-47987 | parse-community/parse-server | version tags (no code) | 34a6cf16,d3d6e9e2,756c2042,8eeab8dc | SUPPLY_CHAIN_TAG | FALSE_POSITIVE |
| 16 | GHSA-94C3-8CQ4-GWWG | CVE-2026-13587 | seladb/PcapPlusPlus | LightPcapNg/light_pcapng.c | 71d2307b,8f27144c | DISJOINT | FALSE_POSITIVE |
| 17 | GHSA-VV7R-8584-6PM6 | CVE-2026-14722 | tiddly-gittly/TidGi-Desktop | loadWikiTiddlersWithSubWikis.ts | 5cd8437e,b4ebaa66,fa9751e5 | DISJOINT | FALSE_POSITIVE |
| 18 | GHSA-P6C5-MJGJ-M4RM | CVE-2026-61448 | parse-community/parse-server | FilesRouter fileUpload | 34a6cf16,d3d6e9e2,756c2042,8eeab8dc | DISJOINT | FALSE_POSITIVE |
| 19 | GHSA-9GQ4-2485-Q63Q | CVE-2026-15809 | cri-o/cri-o | HOME / /etc/passwd env | 9c75852b,71e9babc,7eb2cc18,1e19a726 | DISJOINT | FALSE_POSITIVE |
| 20 | GHSA-3MC6-PQ7X-JQGV | CVE-2026-16127 | zevorn/rt-claw | claw/tools/tool_net.c | 32060f21,f414710e,6975078b,71e909ae | REFACTOR_ONLY | FALSE_POSITIVE |
| 21 | GHSA-8V54-V28Q-C3MX | CVE-2026-16126 | zevorn/rt-claw | claw/services/swarm/swarm.c | 32060f21,f414710e,6975078b,71e909ae | REFACTOR_ONLY | FALSE_POSITIVE |
| 22 | GHSA-QRH7-F8Q9-MRXF | CVE-2026-16125 | zevorn/rt-claw | claw/services/tools/net.c | 32060f21,f414710e,6975078b,71e909ae | DISJOINT | FALSE_POSITIVE |
| 23 | GHSA-F2C6-8JG6-287F | CVE-2026-16128 | zevorn/rt-claw | claw/services/swarm/swarm.c | 32060f21,f414710e,6975078b,71e909ae | REFACTOR_ONLY | FALSE_POSITIVE |
| 24 | GHSA-9869-2292-XXJ6 | CVE-2026-16200 | zevorn/rt-claw | claw/services/swarm/swarm.c | 32060f21,f414710e,6975078b,71e909ae | REFACTOR_ONLY | FALSE_POSITIVE |
| 25 | GHSA-QC6R-FR26-J2GM | CVE-2026-16201 | zevorn/rt-claw | claw/services/tools/net.c | 32060f21,f414710e,6975078b,71e909ae | DISJOINT | FALSE_POSITIVE |

## Detail (diff-read / overlapping rows)

- #6 CleverTap (566a2cc8 / 3b74c499 / 1dae6b88): candidates add `dismissActiveCampaigns()` popup removal and overlay div cleanup in `src/util/clevertap.js` + `src/clevertap.js`. `renderCustomHtml` and the `window.postMessage` listener are never touched; the XSS sink pre-exists.

- #7 389ds (22278a4e / 87ef5060): both diffs are cockpit/389-console React UI (getApiErrorMessage refactor, progress steppers) in `src/cockpit/389-console/**/replication*.jsx`; the vulnerable CleanAllRUV handler is the C server replication plugin, untouched.

- #10/#11 mealie (cee2c351 / 9247204f): RecipePage.vue + recipe_crud_routes.py diffs are duplicate-recipe-name error handling only; grep for v-html/svg/notes/innerHTML/sanitize/media = 0 hits.

- #20-25 rt-claw (71e909ae touches tool_net.c + swarm.c): commit is `fix double collection` — it only refactors registration (`(void)tool` signature, `CLAW_TOOL_REGISTER`, `tool->execute` -> `claw_tool_invoke`). The `cJSON_GetObjectItem(params, "url")` fetch sink and the missing-authz RPC handler are pre-existing context lines, not added by the diff. f414710e touches swarm.h only to add `SWARM_CAP_MOUSE`. rows #22/#25 target `services/tools/net.c`, which no candidate touches.

## Conclusion

This packet admits no countable case. All 25 rows close at ai_hunk/but_for FAIL (wrong edge or refactor-only). Canonical ledger untouched; publication HOLD.
