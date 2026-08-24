# Direct-root review: unreviewed GHSA slice 2 (unr-dr-slice-2.jsonl)

Verdict-first: **0 countable**. All 30 assigned rows are `FALSE_POSITIVE` (class `wrong_edge`): the AI ancestor commit does not author the vulnerable hunk. None is a PASS proposal for leader replay.

## Method
- Read each advisory JSON from the local advisory-database clone (commit-gn, `advisories/unreviewed/` tree, all `github_reviewed=false`).
- Read the exact `fix_ref` and `ai_ancestor` diffs from the local full clones under `/home/hanqing/.cache/cve-analyzer/repos/<owner>_<repo>`.
- Compared the vulnerable hunk (from the advisory + fix diff) against the AI ancestor diff. No blame/SZZ. No GitHub API.

## Result
| ord | case_id | repository | verdict | class | vulnerable surface | AI-ancestor surface |
|---:|---|---|---|---|---|---|
| 1 | GHSA-VJ73-H4QP-97X2 | osrg/gobgp | FALSE_POSITIVE | wrong_edge | pkg/packet/bgp/bgp.go::CapFQDN.DecodeFromBytes | pkg/packet/bgp/bgp.go::LsTLVUnidirectionalDelayVariation.Serialize (~line 7836) |
| 2 | GHSA-5JVQ-55XJ-6QFF | osrg/gobgp | FALSE_POSITIVE | wrong_edge | pkg/packet/bgp/bgp.go::PathAttributeAigp.DecodeFromBytes | pkg/packet/bgp/bgp.go::LsTLVUnidirectionalDelayVariation.Serialize (~line 7836) |
| 3 | GHSA-58RR-CHMF-5W2J | vim/vim | FALSE_POSITIVE | wrong_edge | src/xxd/xxd.c (LLEN_NO_COLOR) | src/insexpand.c (completion startcol) + src/version.c |
| 4 | GHSA-MFXW-Q267-MGP6 | vim/vim | FALSE_POSITIVE | wrong_edge | src/optiondefs.h + src/autocmd.c | src/register.c (do_put) + src/version.c |
| 5 | GHSA-XJWM-4PFW-49G2 | esnet/iperf | FALSE_POSITIVE | wrong_edge | src/net.c::Nrecv / Nrecv_no_select (nleft/total handling) | src/net.c (comment typo: bypassese->bypasses) |
| 6 | GHSA-M23P-3G32-H722 | saitoha/libsixel | FALSE_POSITIVE | wrong_edge | src/encoder.c::sixel_debug_print_palette | src/encoder.c::sixel_prepare_specified_palette (dither null-check) + include/sixel.h.in |
| 7 | GHSA-CRQJ-2V3F-C8G9 | danny-avila/librechat | FALSE_POSITIVE | wrong_edge | /api/convos/fork (server; fix adds rate limiting) | client/src/locales/en/translation.json (i18n update by github-actions bot) |
| 8 | GHSA-V43P-PV9W-GQMF | aardappel/lobster | FALSE_POSITIVE | wrong_edge | dev/src/lobster/idents.h::TypeName / Signature / FormatArg | dev/src/lobster/idents.h::StructAssign + typecheck.h |
| 9 | GHSA-5Q79-CFQM-5CXH | roundcube/roundcubemail | FALSE_POSITIVE | wrong_edge | program/lib/Roundcube/rcube_utils.php (address check) | plugins/enigma/* + program/lib/Roundcube/rcube_message.php |
| 10 | GHSA-7MFP-8XJR-G749 | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/auto-reply/reply/stage-sandbox-media.ts + src/infra/scp-host.ts | src/agents/model-selection.ts + src/config/config.pruning-defaults.ts |
| 11 | GHSA-R3GM-FV85-XJQJ | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/gateway/server/ws-connection/message-handler.ts | src/cron/isolated-agent/run.ts |
| 12 | GHSA-49M4-CHPX-GW3R | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/infra/net/fetch-guard.ts + src/media/store.ts | extensions/browser/src/browser/cdp.ts (screenshot params) |
| 13 | GHSA-72FJ-C222-7598 | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/media/image-ops.ts + src/media/web-media.ts | src/agents/tools/sessions-send-helpers.ts + src/config/sessions/* |
| 14 | GHSA-CP2C-JPV3-3R5R | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | docs/.generated/plugin-sdk-api-baseline.json(+jsonl) (fix pair); channel URL userinfo redaction | src/auto-reply/command-auth.ts (SecretRef resolution) |
| 15 | GHSA-JQM7-G5WF-CQ4G | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/browser/request-policy.ts + src/node-host/invoke-browser.ts | tsdown.config.ts (build dist entry) |
| 16 | GHSA-Q49F-7FGV-7HX8 | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | docs/.generated/plugin-sdk-api-baseline.json(+jsonl) (fix pair) | src/auto-reply/command-auth.ts (SecretRef resolution) |
| 17 | GHSA-QRRM-X53P-GPW4 | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/gateway/server-methods/devices.ts + ws-connection/message-handler.ts | src/agents/pi-embedded-subscribe.*.ts (compaction event handlers) |
| 18 | GHSA-V3P7-858R-PR8M | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/node-host/invoke-system-run-plan.ts | extensions/zalo/src/monitor.webhook.ts (replay dedupe) |
| 19 | GHSA-58PR-GW4M-RW8V | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | extensions/memory-core/src/memory/qmd-manager.ts | src/plugins/loader.ts (bundled setup-entry contract) |
| 20 | GHSA-5HJ5-7X2H-XHPR | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/gateway/control-ui.ts + ui/src/ui/controllers/control-ui-bootstrap.ts | src/agents/pi-embedded-runner/run/auth-controller.ts (AWS SDK IMDS auth) |
| 21 | GHSA-5W5H-C32Q-R6W9 | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | extensions/browser/src/browser/cdp-reachability-policy.ts + config.ts | extensions/discord|slack|msteams/* + src/agents/subagent-spawn.ts (Matrix account binding) |
| 22 | GHSA-9FC9-8V4X-F5CP | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/agents/tools/gateway-tool.ts + src/security/dangerous-config-flags.ts | src/auto-reply/reply/agent-runner-execution.ts + config schema (compaction notices) |
| 23 | GHSA-FR55-95RR-VM5X | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/agents/pi-embedded-runner/effective-tool-policy.ts + pi-tools.policy.ts | src/agents/pi-embedded-helpers/failover-matches.ts (INTERNAL 500 classification) |
| 24 | GHSA-GQ8X-6M4Q-4RG7 | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | extensions/nostr/src/nostr-profile-http.ts + src/gateway/server/plugins-http.ts | extensions/qqbot/src/config-schema.ts (extension fields) |
| 25 | GHSA-HF7P-489H-XHJ4 | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | extensions/feishu/src/card-action.ts | extensions/twitch/* (bundled setup entry) |
| 26 | GHSA-HH6M-M25H-86WQ | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/infra/exec-approvals-analysis.ts | extensions/discord/index.ts (channel registration perf) |
| 27 | GHSA-J47R-FQH5-HQCC | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | extensions/browser/src/browser/pw-tools-core.interactions.ts + routes/agent.act.ts | src/plugins/lazy-service-module.ts + src/infra/dotenv.ts (override loading) |
| 28 | GHSA-MW7V-RXQG-F85M | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/infra/heartbeat-events-filter.ts | extensions/browser/src/browser/bridge-server.ts + server-middleware.ts (noVNC helper auth) |
| 29 | GHSA-PRP6-V677-XQHQ | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | src/gateway/server-methods/chat-webchat-media.ts + chat.ts | scripts/stage-bundled-plugin-runtime-deps.mjs (build prune) |
| 30 | GHSA-XM83-JC96-GW22 | openclaw/openclaw | FALSE_POSITIVE | wrong_edge | extensions/browser/src/browser/bridge-server.ts + server-middleware.ts + sandbox-info.ts | src/infra/outbound/message-action-params.ts (image param in media normalization) |

## Gate summary
Every row: `identity_gate=PASS` (advisory names repo + mechanism + identity, but `github_reviewed=false`), `ai_hunk_gate=FAIL`, `topology_gate=PASS` (no authorship transfer; AI ancestor is an unrelated sibling in fix ancestry), `but_for_gate=FAIL`, `fix_reversal_gate=FAIL`, `release_gate=UNKNOWN` (not evaluated for non-countable rows), `uniqueness_gate=PASS`.

## Per-row reasoning
### 1. GHSA-VJ73-H4QP-97X2 — osrg/gobgp
- fix_ref `2b09db390a3d455808363c53e409afe6b1b86d2d`, ai_ancestor `38c64c91204c0acf615eb38f6e5b69e81139a162` (`Update pkg/packet/bgp/bgp.go`)
- vulnerable surface: CapFQDN.DecodeFromBytes ignores DomainNameLen (pkg/packet/bgp/bgp.go, ~line 1060)
- AI ancestor surface: pkg/packet/bgp/bgp.go::LsTLVUnidirectionalDelayVariation.Serialize (~line 7836)
- counterevidence: Same file, different function. AI commit 38c64c9 (Copilot co-authored) changes buf[0]=l.Reserved->0 in a link-state TLV serializer; it does not touch the CapFQDN domain-length parsing hunk that the fix reverses.

### 2. GHSA-5JVQ-55XJ-6QFF — osrg/gobgp
- fix_ref `51ad1ada06cb41ce47b7066799981816f50b7ced`, ai_ancestor `38c64c91204c0acf615eb38f6e5b69e81139a162` (`Update pkg/packet/bgp/bgp.go`)
- vulnerable surface: PathAttributeAigp.DecodeFromBytes buffer overflow (pkg/packet/bgp/bgp.go, ~line 15279)
- AI ancestor surface: pkg/packet/bgp/bgp.go::LsTLVUnidirectionalDelayVariation.Serialize (~line 7836)
- counterevidence: Same file, different function. Same AI ancestor 38c64c9 (buf[0]=0 in LsTLV serializer) is unrelated to the AIGP attribute parser the fix hardens.

### 3. GHSA-58RR-CHMF-5W2J — vim/vim
- fix_ref `eeef7c77436a78cd27047b0f5fa6925d56de3cb0`, ai_ancestor `761ea77670c4fdb96d6c6fb7d4db6dc77eb8095f` (`patch 9.1.1609: complete: Heap-buffer overflow with complete function`)
- vulnerable surface: xxd bitwise-output buffer overflow (src/xxd/xxd.c LLEN_NO_COLOR macro, main)
- AI ancestor surface: src/insexpand.c (completion startcol) + src/version.c
- counterevidence: Overlap is only src/version.c (patch-number bump). AI commit 761ea776 is a completion buffer-overflow fix in insexpand.c; it does not touch xxd.c.

### 4. GHSA-MFXW-Q267-MGP6 — vim/vim
- fix_ref `664701eb7576edb7c7c7d9f2d600815ec1f43459`, ai_ancestor `80a0c355cff08bc8a20d548cc1e62a11a978babb` (`patch 9.2.0262: invalid lnum when pasting text copied blockwise`)
- vulnerable surface: tabpanel modeline %{expr} injection (src/optiondefs.h P_MLE, src/autocmd.c)
- AI ancestor surface: src/register.c (do_put) + src/version.c
- counterevidence: Overlap is only src/version.c. AI commit 80a0c355 fixes blockwise-paste lnum in register.c; unrelated to tabpanel/autocmd security fix.

### 5. GHSA-XJWM-4PFW-49G2 — esnet/iperf
- fix_ref `969b7f70c447513e92c9798f22e82b40ebc53bf0`, ai_ancestor `91894d1dc4f81377a9d0cb1be235f1cca161125f` (`Correct typo in net.c (#1874)`)
- vulnerable surface: net.c Nrecv buffer overflow with --skip-rx-copy MSG_TRUNC (src/net.c)
- AI ancestor surface: src/net.c (comment typo: bypassese->bypasses)
- counterevidence: Same file, but the AI commit 91894d1 is a one-word comment typo fix ('bypassese'->'bypasses'); it does not touch the nleft/total buffer logic the fix changes.

### 6. GHSA-M23P-3G32-H722 — saitoha/libsixel
- fix_ref `316c086e79d66b62c0c4bc66229ee894e4fdb7d1`, ai_ancestor `d67e842db906c85197a678d03d15f9b1e34077c2` (`Fix segfault caused by uninitialized dither`)
- vulnerable surface: sixel_debug_print_palette palette[i*3+3] heap-buffer-overflow (src/encoder.c:744)
- AI ancestor surface: src/encoder.c::sixel_prepare_specified_palette (dither null-check) + include/sixel.h.in
- counterevidence: Same file, different function. AI commit d67e842d adds an uninitialized-dither null check in sixel_prepare_specified_palette; it does not touch the debug-palette indexing that the fix corrects.

### 7. GHSA-CRQJ-2V3F-C8G9 — danny-avila/librechat
- fix_ref `97a99985fa339db0a21ad63604e0bb8db4442ffc`, ai_ancestor `4285d5841c4800da2759149949ee935a7645dcea` (`🌍 i18n: Update translation.json with latest translations (#8235)`)
- vulnerable surface: Unrestricted fork function /api/convos/fork -> JS heap OOM DoS (server-side)
- AI ancestor surface: client/src/locales/en/translation.json (i18n update by github-actions bot)
- counterevidence: Disjoint surfaces. AI commit 4285d584 is an automated i18n translation-file update; the vulnerable hunk is the server fork endpoint. Diff blobs not fetched (no network), but wrong-edge is established by commit subject + overlap file translation.json.

### 8. GHSA-V43P-PV9W-GQMF — aardappel/lobster
- fix_ref `8ba49f98ccfc9734ef352146806433a41d9f9aa6`, ai_ancestor `c8a60420b7501bdb462fcbfc4245b03a5210ed26` (`StructAssign did not pass Line info to lex.error FIXED (#394)`)
- vulnerable surface: TypeName/Signature uncontrolled recursion (dev/src/lobster/idents.h)
- AI ancestor surface: dev/src/lobster/idents.h::StructAssign + typecheck.h
- counterevidence: Same file, different function. AI commit c8a60420 adds a Line* param to StructAssign; it does not touch the TypeName/Signature recursion the fix guards with a depth parameter.

### 9. GHSA-5Q79-CFQM-5CXH — roundcube/roundcubemail
- fix_ref `294c7da6e7284166f040cef8607b677d459e0786`, ai_ancestor `5679995d55b1e4dbbac0ee5758a55736b651580f` (`Enigma: WOAT Support (#8626)`)
- vulnerable surface: SSRF via CSS sanitization bypass (program/lib/Roundcube/rcube_utils.php ::ffff/nip.io regex)
- AI ancestor surface: plugins/enigma/* + program/lib/Roundcube/rcube_message.php
- counterevidence: Overlap is only CHANGELOG.md. AI commit 5679995d is an Enigma WOAT email feature; it does not touch rcube_utils.php SSRF regex.

### 10. GHSA-7MFP-8XJR-G749 — openclaw/openclaw
- fix_ref `a54bf71b4c0cbe554a84340b773df37ee8e959de`, ai_ancestor `868fd32ee77424af5d0d27bba9ceb570b11fa929` (`fix(config): avoid Anthropic startup crash (#45520)`)
- vulnerable surface: iMessage attachment SCP command injection (stage-sandbox-media/scp-host)
- AI ancestor surface: src/agents/model-selection.ts + src/config/config.pruning-defaults.ts
- counterevidence: Overlap only CHANGELOG.md. AI commit 868fd32e (avoid Anthropic startup crash) touches model selection, not the SCP remote-operand path.

### 11. GHSA-R3GM-FV85-XJQJ — openclaw/openclaw
- fix_ref `8d1481cb4a9d31bd617e52dc8c392c35689d9dea`, ai_ancestor `15cfba7075ac9e3de7444a466281561a2e983ab6` (`fix: cron model fallback to agent defaults when payload.model fails (#26717)`)
- vulnerable surface: unpaired-device operator scope privilege escalation
- AI ancestor surface: src/cron/isolated-agent/run.ts
- counterevidence: Overlap only CHANGELOG.md. AI commit 15cfba7 (cron model fallback) is unrelated to device pairing authz.

### 12. GHSA-49M4-CHPX-GW3R — openclaw/openclaw
- fix_ref `e704323ff388ed21f6963f9b8e0b1b8dfaaabc5f`, ai_ancestor `44caf1ee3d7f8b1e0ae3af752d220e9737aa3324` (`fix(browser): prevent cross-origin images from disappearing in CDP screenshots (#54358)`)
- vulnerable surface: media download Authorization header cross-origin credential exposure
- AI ancestor surface: extensions/browser/src/browser/cdp.ts (screenshot params)
- counterevidence: Overlap only CHANGELOG.md. AI commit 44caf1e (CDP screenshot cross-origin images) is unrelated to media download redirect headers.

### 13. GHSA-72FJ-C222-7598 — openclaw/openclaw
- fix_ref `0ed4f8a72bb140045962e97ab01c94c076b758a4`, ai_ancestor `4ea1ca48495d7a941f7077d54daf0ad8a808deba` (`Sessions: parse thread suffixes by channel (#58100)`)
- vulnerable surface: image decompression bomb (missing pixel-limit guards on sips)
- AI ancestor surface: src/agents/tools/sessions-send-helpers.ts + src/config/sessions/*
- counterevidence: Overlap only CHANGELOG.md. AI commit 4ea1ca4 (parse thread suffixes by channel) is unrelated to image pixel-limit guards.

### 14. GHSA-CP2C-JPV3-3R5R — openclaw/openclaw
- fix_ref `630f1479c44f78484dfa21bb407cbe6f171dac87`, ai_ancestor `d4e3babdcc09c122bb068311a4da16fa2f069e42` (`fix: command auth SecretRef resolution (#52791) (thanks @Lukavyi)`)
- vulnerable surface: channel baseUrl/httpUrl credential disclosure (operator.read scope)
- AI ancestor surface: src/auto-reply/command-auth.ts (SecretRef resolution)
- counterevidence: Overlap only CHANGELOG.md. AI commit d4e3babd (command auth SecretRef) is unrelated to channel URL userinfo redaction. Note: shares fix_ref/ai_ancestor with GHSA-Q49F (row 16).

### 15. GHSA-JQM7-G5WF-CQ4G — openclaw/openclaw
- fix_ref `eac93507c36ccd0c359fba18fa466ef6448be8a5`, ai_ancestor `5ff60cc39f7493509686e971d26f8bf337cfcf14` (`fix(build): add stable memory-cli dist entry (#51759)`)
- vulnerable surface: allowProfiles access-control bypass (runtime profile selection)
- AI ancestor surface: tsdown.config.ts (build dist entry)
- counterevidence: Overlap only CHANGELOG.md. AI commit 5ff60cc (build: memory-cli dist entry) is a build change, unrelated to allowProfiles policy.

### 16. GHSA-Q49F-7FGV-7HX8 — openclaw/openclaw
- fix_ref `630f1479c44f78484dfa21bb407cbe6f171dac87`, ai_ancestor `d4e3babdcc09c122bb068311a4da16fa2f069e42` (`fix: command auth SecretRef resolution (#52791) (thanks @Lukavyi)`)
- vulnerable surface: Control UI device-less privileged-scope escalation
- AI ancestor surface: src/auto-reply/command-auth.ts (SecretRef resolution)
- counterevidence: Overlap only CHANGELOG.md. AI commit d4e3babd (command auth SecretRef) is unrelated to Control UI device identity checks. Note: shares fix_ref/ai_ancestor with GHSA-CP2C (row 14).

### 17. GHSA-QRRM-X53P-GPW4 — openclaw/openclaw
- fix_ref `5a12f30441d5b0b151f550daa2c5c9e8db61e2e6`, ai_ancestor `0a761a9eac2d1a891b83867eabe037921447b9a7` (`fix(agents): rename auto_compaction_start/end to compaction_start/end [AI] (#67713)`)
- vulnerable surface: paired-device pairing management authorization bypass
- AI ancestor surface: src/agents/pi-embedded-subscribe.*.ts (compaction event handlers)
- counterevidence: Overlap only CHANGELOG.md. AI commit 0a761a9e ([AI] rename compaction events) is unrelated to device pairing authz.

### 18. GHSA-V3P7-858R-PR8M — openclaw/openclaw
- fix_ref `176c059b05357df1bc09d4328a2380670859eeff`, ai_ancestor `7cea7c29705b188b464cc9cdc107c275b94b2a72` (`fix(zalo): scope replay dedupe cache key to path and account [AI] (#59387)`)
- vulnerable surface: pnpm dlx approval integrity (local script operand binding)
- AI ancestor surface: extensions/zalo/src/monitor.webhook.ts (replay dedupe)
- counterevidence: Overlap only CHANGELOG.md. AI commit 7cea7c29 ([AI] zalo replay dedupe) is unrelated to pnpm dlx approval plan.

### 19. GHSA-58PR-GW4M-RW8V — openclaw/openclaw
- fix_ref `37d5971db36491d5050efd42c333cbe0b98ed292`, ai_ancestor `1558a352f86a67957c5f8b6a4bf410773f3b9a17` (`fix(plugins): support bundled setup-entry contract in loader (#66261)`)
- vulnerable surface: QMD backend memory_get arbitrary file read
- AI ancestor surface: src/plugins/loader.ts (bundled setup-entry contract)
- counterevidence: Overlap only CHANGELOG.md. AI commit 1558a352 (plugins loader) is unrelated to QMD memory path containment.

### 20. GHSA-5HJ5-7X2H-XHPR — openclaw/openclaw
- fix_ref `2321d67263bc710e357644d59f746b08d891051b`, ai_ancestor `c7e5289fd20d991b466afa8c80cd0ba06ebd8eb3` (`fix: propagate AWS SDK auth sentinel for IMDS/instance role Bedrock auth (#68964)`)
- vulnerable surface: Control UI bootstrap config endpoint authentication bypass
- AI ancestor surface: src/agents/pi-embedded-runner/run/auth-controller.ts (AWS SDK IMDS auth)
- counterevidence: Overlap only CHANGELOG.md. AI commit c7e5289f (AWS SDK auth sentinel) is unrelated to Control UI bootstrap auth.

### 21. GHSA-5W5H-C32Q-R6W9 — openclaw/openclaw
- fix_ref `1fd049e3074cac72f6734a7fe88468c84f5f8bd7`, ai_ancestor `c39314c14aaab6dacee6167e974a16ee058b985e` (`fix(agents): prefer target agent's bound Matrix account for subagent spawns (#67508)`)
- vulnerable surface: browser CDP profile creation SSRF (skips strict-mode policy)
- AI ancestor surface: extensions/discord|slack|msteams/* + src/agents/subagent-spawn.ts (Matrix account binding)
- counterevidence: Overlap only CHANGELOG.md. AI commit c39314c1 (subagent Matrix account) is unrelated to CDP profile SSRF policy.

### 22. GHSA-9FC9-8V4X-F5CP — openclaw/openclaw
- fix_ref `fe30b31a97a917ecc6e92f6c85378b6b20352422`, ai_ancestor `f48d040bf523a23ce20b5141ca2d991bbcb82aa6` (`feat: send compaction start and completion notices (#67830)`)
- vulnerable surface: config.patch/config.apply guard bypass (operator-trusted settings)
- AI ancestor surface: src/auto-reply/reply/agent-runner-execution.ts + config schema (compaction notices)
- counterevidence: Overlap only CHANGELOG.md. AI commit f48d040b (compaction notices) is unrelated to gateway-tool config guard.

### 23. GHSA-FR55-95RR-VM5X — openclaw/openclaw
- fix_ref `0e7a992d3f3155199c1acc2dd9a53c5b3a4d3ada`, ai_ancestor `d0cf6731aa4e6328f1b2441ecb2fea4e03e77836` (`fix(failover): classify INTERNAL 500 responses as retryable timeouts (#68238)`)
- vulnerable surface: bundled MCP/LSP tool policy bypass
- AI ancestor surface: src/agents/pi-embedded-helpers/failover-matches.ts (INTERNAL 500 classification)
- counterevidence: Overlap only CHANGELOG.md. AI commit d0cf6731 (failover 500 retry) is unrelated to tool policy filtering.

### 24. GHSA-GQ8X-6M4Q-4RG7 — openclaw/openclaw
- fix_ref `6517c700de9bb0ee11b41ab625ef3b63d01b6083`, ai_ancestor `005b629b6d8f5f9705388f7d6de745bfc533c14e` (`fix(qqbot): allow extension fields in channel config schema (#64075)`)
- vulnerable surface: Nostr plugin HTTP profile route insufficient access control
- AI ancestor surface: extensions/qqbot/src/config-schema.ts (extension fields)
- counterevidence: Overlap only CHANGELOG.md. AI commit 005b629b (qqbot config schema) is unrelated to Nostr profile HTTP authz.

### 25. GHSA-HF7P-489H-XHJ4 — openclaw/openclaw
- fix_ref `90979d7c3ef7ec30b9f8aa6963a5e38d2f17d166`, ai_ancestor `6184f17c9148a15f5a5dc6566d5a930cd061356c` (`Twitch: add bundled setup entry (#68008)`)
- vulnerable surface: Feishu card-action DM/group misclassification (dmPolicy bypass)
- AI ancestor surface: extensions/twitch/* (bundled setup entry)
- counterevidence: Overlap only CHANGELOG.md. AI commit 6184f17c (Twitch setup entry) is unrelated to Feishu card-action classification.

### 26. GHSA-HH6M-M25H-86WQ — openclaw/openclaw
- fix_ref `b2e8b7d4bb2f22eaa16f5c4b07547774e90b65a5`, ai_ancestor `6b185e2849a55f0927d9232908e5ae6a800a0db9` (`perf: speed up discord channel registration (#69791)`)
- vulnerable surface: exec allowlist heredoc shell-expansion bypass
- AI ancestor surface: extensions/discord/index.ts (channel registration perf)
- counterevidence: Overlap only CHANGELOG.md. AI commit 6b185e28 (discord registration perf) is unrelated to exec allowlist analysis.

### 27. GHSA-J47R-FQH5-HQCC — openclaw/openclaw
- fix_ref `5f5b3d733bdd791cb457f838514179e1288b10b3`, ai_ancestor `dafcaf9d69d228588d587eb309a0f690adf05116` (`fix(browser): harden browser control override loading (#62663)`)
- vulnerable surface: browser act/evaluate navigation guard bypass (file:// pivot)
- AI ancestor surface: src/plugins/lazy-service-module.ts + src/infra/dotenv.ts (override loading)
- counterevidence: Overlap only CHANGELOG.md. AI commit dafcaf9d (browser control override loading) is unrelated to act/evaluate navigation guard.

### 28. GHSA-MW7V-RXQG-F85M — openclaw/openclaw
- fix_ref `19a2e9ddb5a8a494abcba812bb11f51075026a27`, ai_ancestor `8dfbf3268bd224b7377d1ecca77a445100746085` (`fix(browser): gate sandbox noVNC helper auth`)
- vulnerable surface: heartbeat owner-downgrade detection misses async exec completion (privilege escalation)
- AI ancestor surface: extensions/browser/src/browser/bridge-server.ts + server-middleware.ts (noVNC helper auth)
- counterevidence: Overlap only CHANGELOG.md. AI commit 8dfbf326 (noVNC helper auth) is a different security fix (the row-30 mechanism), unrelated to heartbeat owner-downgrade filtering.

### 29. GHSA-PRP6-V677-XQHQ — openclaw/openclaw
- fix_ref `6e58f1f9f54bca1fea1268ec0ee4c01a2af03dde`, ai_ancestor `7c6f2c0a5a61e32e835a1aec59d4c5a26cc2a82d` (`Build: prune packaged runtime test cargo (#67275)`)
- vulnerable surface: webchat audio embedding arbitrary local file read
- AI ancestor surface: scripts/stage-bundled-plugin-runtime-deps.mjs (build prune)
- counterevidence: Overlap only CHANGELOG.md. AI commit 7c6f2c0a (build: prune runtime test cargo) is unrelated to webchat media containment.

### 30. GHSA-XM83-JC96-GW22 — openclaw/openclaw
- fix_ref `8dfbf3268bd224b7377d1ecca77a445100746085`, ai_ancestor `979c6f09d6fad96596feb91c905934be7e0b4f15` (`fix: include image param in sandbox media normalization [AI-assisted] (#64377)`)
- vulnerable surface: sandbox noVNC helper route authentication bypass (session credential exposure)
- AI ancestor surface: src/infra/outbound/message-action-params.ts (image param in media normalization)
- counterevidence: Overlap only CHANGELOG.md. AI commit 979c6f09 ([AI-assisted] sandbox media image param) is unrelated to the noVNC helper bridge auth.

## Cross-row notes
- Rows 14 (GHSA-CP2C-JPV3-3R5R) and 16 (GHSA-Q49F-7FGV-7HX8) share the same fix_ref `630f1479c44f78484dfa21bb407cbe6f171dac87` and ai_ancestor `d4e3babdcc09c122bb068311a4da16fa2f069e42`; distinct advisories, both wrong-edge.
- Row 28 ai_ancestor `8dfbf3268bd224b7377d1ecca77a445100746085` is the fix_ref of row 30 (sandbox noVNC helper auth); neither relationship yields a countable AI-direct-root.
- Many ai_ancestor commits carry no explicit AI marker (human co-authors, or a `github-actions[bot]` i18n commit in row 7); wrong-edge holds regardless, so no row is countable under any marker interpretation.
- Row 7 (librechat) diff blobs were not fetched (network blocked); wrong-edge is established by the ai_ancestor subject (i18n translation update) + overlap file `client/src/locales/en/translation.json` vs the server-side `/api/convos/fork` mechanism.

## Evidence
- Per-row full dumps: `work/01_...txt` .. `work/30_...txt` (advisory JSON + fix diff + AI-ancestor diff).
- Aggregated JSON: `work/evidence.json`.
- Advisory DB head: `a42c436870111aa3f221257c9d56126a93173ccc` (commit-gn clone, `advisories/unreviewed/` via `origin/main`).
