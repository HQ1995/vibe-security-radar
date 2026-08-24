# unr-adj-slice-3 adjudication report
Input: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj-slice-3.jsonl`
sha256: `6972c7cd4a7959e2ffac0f4a60c864455e9438c8ce1332e1050601b233f936f9`
## Verdict-first summary
- Rows reviewed: 25
- REJECT (not countable): 25
- PASS / countable: 0
Every candidate AI commit is either (a) an unrelated feature/refactor that does not touch the named vulnerable surface, or (b) a fix/defensive change on a pre-existing surface. In both cases `ai_hunk_gate` and `but_for_gate` FAIL, so no row is countable.
## Per-row
| # | GHSA | repo | mechanism | candidate | verdict |
|---|------|------|-----------|-----------|---------|
| 1 | GHSA-XVGX-9RPH-3PJ6 | Jovancoding/Network-AI | Missing authorization on ApprovalInbox GET routes; unauthenticate | feat: add MiniMax LLM adapter (27b549f4d3) | REJECT |
| 2 | GHSA-F3J8-8GGQ-F9X2 | eclipse-hawkbit/hawkbit | Privilege escalation in Direct Device Integration (DDI) Controlle | Remove schema generation annotations in Jpa layer (e6367d0b0c) | REJECT |
| 3 | GHSA-Q8PQ-98HQ-MG7F | firefly-iii/firefly-iii | Webhook URL validator explicitly allows loopback -> blind SSRF /  | Fix chart API balance carry-forward bug and add mi (ed3f4f62ee) | REJECT |
| 4 | GHSA-Q274-QF66-4HQ6 | Koha-Community/Koha | Blind SQL injection via order_by CGI parameter in reports/guided_ | Bug 41950: (follow-up) Add DBIC relationship alias (713c5c3343) | REJECT |
| 5 | GHSA-7CRV-RQ8J-WXC3 | DataLinkDC/dinky | Unauthenticated arbitrary file write / system-config disclosure ( | [Bug] Fix operator submit bug (#4402) (6783e2625b) | REJECT |
| 6 | GHSA-83JG-X5RH-3X8C | DataLinkDC/dinky | Unauthenticated arbitrary file write / system-config disclosure ( | [Bug] Fix operator submit bug (#4402) (6783e2625b) | REJECT |
| 7 | GHSA-8GXJ-MV75-3MRM | Cockpit-HQ/Cockpit | Missing authorization (candidate commit is the fix: prevent users | Prevent users to update their active status withou (b49e0e2b29) | REJECT |
| 8 | GHSA-64VJ-7C55-24W2 | Jovancoding/Network-AI | ClaudeHookBridge denyPattern bypass via 500-char target truncatio | feat: add MiniMax LLM adapter (27b549f4d3) | REJECT |
| 9 | GHSA-X5MX-WQ8Q-46PH | Jovancoding/Network-AI | SandboxPolicy blocklist bypass via quote-preserved vs quote-strip | feat: add MiniMax LLM adapter (27b549f4d3) | REJECT |
| 10 | GHSA-PRXP-75XX-3CXW | RocketChat/Rocket.Chat | parseMessage in apps/meteor/app/irc/server/servers/RFC2813/parseM | fix: CORS headers incorrectly set for GET (b9d69482e9,2f382137b5) | REJECT |
| 11 | GHSA-9M93-62Q8-9JMX | sipwise/rtpengine | Origin-validation error in media-relay endpoint-learning allows R | MT#55283 recording pause/resume timestamp markers  (80240f62ef,2d5565738f) | REJECT |
| 12 | GHSA-WV45-CW2M-63R8 | MCSManager/MCSManager | Daemon runs as root; tokens/terminal content stored world-readabl | progress-throttle + cache-write logging tweaks (b95039f6cc,2b082319c9) | REJECT |
| 13 | GHSA-6Q56-MRMC-CPH4 | ollama/ollama | Null-pointer dereference in multi-modal image processing via /api | x: add skills spec / fix agent loop message handli (b1d711f8cc,5e23c4f2f7) | REJECT |
| 14 | GHSA-H7V7-PR65-4W53 | run-llama/llama_index | VannaQueryEngine SQL execution / resource exhaustion | Add Apertis LLM integration / workflow import refa (a72b1c9028,335844d077) | REJECT |
| 15 | GHSA-M592-CR2F-4QG5 | run-llama/llama_index | BGE M3 index unsafe deserialization | Add Apertis LLM integration / workflow import refa (a72b1c9028,335844d077) | REJECT |
| 16 | GHSA-H73V-MC67-XW25 | ollama/ollama | Panic DoS via unchecked length in GGUF decoder copy | x: add skills spec / fix agent loop message handli (b1d711f8cc,5e23c4f2f7) | REJECT |
| 17 | GHSA-JR3X-Q8GX-4GW3 | ollama/ollama | Panic in readGGUFV1String via GGUF-v1 string length | x: add skills spec / fix agent loop message handli (b1d711f8cc,5e23c4f2f7) | REJECT |
| 18 | GHSA-2RR6-9W84-3V7P | swoole/swoole-src | Integer overflow / wraparound in thirdparty/hiredis sds.c | add SWOOLE_ODBC_LIBS / Add stdext module (f819fa8cb1,809eb827f5) | REJECT |
| 19 | GHSA-V546-JRFG-PH8Q | RawTherapee/RawTherapee | Integer overflow / wraparound in rtengine dcraw.cc | Denoise blur/sharpening improvements / guiutils co (cc4fcc32e0,c4b0400710) | REJECT |
| 20 | GHSA-2678-G677-R4GX | open5gs/open5gs | DoS in CCA Message Handler (smf_gx_cca_cb / smf_gy_cca_cb / smf_s | pfcp: find_or_add + defensive FAR/URR resets (c42d7b7d9b,d28e2f7f49) | REJECT |
| 21 | GHSA-7H3P-2HJJ-2V8X | open5gs/open5gs | DoS via crafted PDU Session Modification Request causing ogs_asse | pfcp: find_or_add + defensive FAR/URR resets (c42d7b7d9b,d28e2f7f49) | REJECT |
| 22 | GHSA-CCV7-FR4H-54HJ | open5gs/open5gs | open5gs DoS (issue #4395) | pfcp: find_or_add + defensive FAR/URR resets (c42d7b7d9b,d28e2f7f49) | REJECT |
| 23 | GHSA-X3Q3-9P69-QVGQ | open5gs/open5gs | open5gs DoS (issue #4399) | pfcp: find_or_add + defensive FAR/URR resets (c42d7b7d9b,d28e2f7f49) | REJECT |
| 24 | GHSA-286X-7QF6-X2H4 | open5gs/open5gs | open5gs DoS (issue #4400) | pfcp: find_or_add + defensive FAR/URR resets (c42d7b7d9b,d28e2f7f49) | REJECT |
| 25 | GHSA-RQX4-V9GM-WJFH | open5gs/open5gs | open5gs DoS (issue #4401) | pfcp: find_or_add + defensive FAR/URR resets (c42d7b7d9b,d28e2f7f49) | REJECT |

### 1. GHSA-XVGX-9RPH-3PJ6 — Jovancoding/Network-AI (REJECT)

- Aliases: CVE-2026-64622
- Mechanism: Missing authorization on ApprovalInbox GET routes; unauthenticated read of approval shell-command details
- Candidate: feat: add MiniMax LLM adapter — `27b549f4d3a16c2a54a382d58b8ad01530f20b5d`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 2. GHSA-F3J8-8GGQ-F9X2 — eclipse-hawkbit/hawkbit (REJECT)

- Aliases: CVE-2026-16454
- Mechanism: Privilege escalation in Direct Device Integration (DDI) Controller; authenticated device escalates and exfiltrates tenant firmware
- Candidate: Remove schema generation annotations in Jpa layer — `e6367d0b0c755ca6efc47472d0313c4e59bbd2cd`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 3. GHSA-Q8PQ-98HQ-MG7F — firefly-iii/firefly-iii (REJECT)

- Aliases: CVE-2026-71250
- Mechanism: Webhook URL validator explicitly allows loopback -> blind SSRF / DNS-rebinding bypass
- Candidate: Fix chart API balance carry-forward bug and add missing deleted_at filter — `ed3f4f62ee09ac86789998e156262e29856bf2ee`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 4. GHSA-Q274-QF66-4HQ6 — Koha-Community/Koha (REJECT)

- Aliases: CVE-2026-71288
- Mechanism: Blind SQL injection via order_by CGI parameter in reports/guided_reports.pl
- Candidate: Bug 41950: (follow-up) Add DBIC relationship aliases for +count embeds — `713c5c33431d6c6f52f21bb2fae71fb671ae3b9c`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 5. GHSA-7CRV-RQ8J-WXC3 — DataLinkDC/dinky (REJECT)

- Aliases: (not confirmed locally)
- Mechanism: Unauthenticated arbitrary file write / system-config disclosure (dinky download/sysConfig surfaces)
- Candidate: [Bug] Fix operator submit bug (#4402) — `6783e2625bb4c9811270015d37620710acc7ac2d`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 6. GHSA-83JG-X5RH-3X8C — DataLinkDC/dinky (REJECT)

- Aliases: (not confirmed locally)
- Mechanism: Unauthenticated arbitrary file write / system-config disclosure (dinky download/sysConfig surfaces)
- Candidate: [Bug] Fix operator submit bug (#4402) — `6783e2625bb4c9811270015d37620710acc7ac2d`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 7. GHSA-8GXJ-MV75-3MRM — Cockpit-HQ/Cockpit (REJECT)

- Aliases: (not confirmed locally)
- Mechanism: Missing authorization (candidate commit is the fix: prevent users updating their active status without permission)
- Candidate: Prevent users to update their active status without needed permissions — `b49e0e2b29150fc083ebbff85d1f7e53f886809c`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 8. GHSA-64VJ-7C55-24W2 — Jovancoding/Network-AI (REJECT)

- Aliases: CVE-2026-73614
- Mechanism: ClaudeHookBridge denyPattern bypass via 500-char target truncation
- Candidate: feat: add MiniMax LLM adapter — `27b549f4d3a16c2a54a382d58b8ad01530f20b5d`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 9. GHSA-X5MX-WQ8Q-46PH — Jovancoding/Network-AI (REJECT)

- Aliases: CVE-2026-73615
- Mechanism: SandboxPolicy blocklist bypass via quote-preserved vs quote-stripped tokenization mismatch
- Candidate: feat: add MiniMax LLM adapter — `27b549f4d3a16c2a54a382d58b8ad01530f20b5d`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 10. GHSA-PRXP-75XX-3CXW — RocketChat/Rocket.Chat (REJECT)

- Aliases: CVE-2025-5892
- Mechanism: parseMessage in apps/meteor/app/irc/server/servers/RFC2813/parseMessage.js (IRC parsing flaw)
- Candidate: fix: CORS headers incorrectly set for GET — `b9d69482e9e0b721bfb96f20d83765ff0bca2e2a, 2f382137b54f9828b9c77e2e7cce2982ffb5378f`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 11. GHSA-9M93-62Q8-9JMX — sipwise/rtpengine (REJECT)

- Aliases: CVE-2025-53399
- Mechanism: Origin-validation error in media-relay endpoint-learning allows RTP/SRTP stream inject/intercept
- Candidate: MT#55283 recording pause/resume timestamp markers + auto-start fix — `80240f62ef019e149ca4058cc00c0e649aae9c4d, 2d5565738f9184e922685c65c1fe4635e738320d`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 12. GHSA-WV45-CW2M-63R8 — MCSManager/MCSManager (REJECT)

- Aliases: CVE-2025-50691
- Mechanism: Daemon runs as root; tokens/terminal content stored world-readable -> privilege escalation
- Candidate: progress-throttle + cache-write logging tweaks — `b95039f6cc119dd7a4d325109723bc79b688d968, 2b082319c9b486da769a530228506ced45b61317`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 13. GHSA-6Q56-MRMC-CPH4 — ollama/ollama (REJECT)

- Aliases: CVE-2025-15514
- Mechanism: Null-pointer dereference in multi-modal image processing via /api/chat base64 image
- Candidate: x: add skills spec / fix agent loop message handling — `b1d711f8cc6e4869f656f07bbdaf7ba62cd4758c, 5e23c4f2f74b6e2823d117523d821d9c78e699b4`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 14. GHSA-H7V7-PR65-4W53 — run-llama/llama_index (REJECT)

- Aliases: CVE-2024-58339
- Mechanism: VannaQueryEngine SQL execution / resource exhaustion
- Candidate: Add Apertis LLM integration / workflow import refactor — `a72b1c90287a41145bd1bb0e5f9ff36bc49d67e1, 335844d07773dda6778ac2ad5e427316abab38eb`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 15. GHSA-M592-CR2F-4QG5 — run-llama/llama_index (REJECT)

- Aliases: CVE-2024-14021
- Mechanism: BGE M3 index unsafe deserialization
- Candidate: Add Apertis LLM integration / workflow import refactor — `a72b1c90287a41145bd1bb0e5f9ff36bc49d67e1, 335844d07773dda6778ac2ad5e427316abab38eb`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 16. GHSA-H73V-MC67-XW25 — ollama/ollama (REJECT)

- Aliases: CVE-2025-66959
- Mechanism: Panic DoS via unchecked length in GGUF decoder copy
- Candidate: x: add skills spec / fix agent loop message handling — `b1d711f8cc6e4869f656f07bbdaf7ba62cd4758c, 5e23c4f2f74b6e2823d117523d821d9c78e699b4`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 17. GHSA-JR3X-Q8GX-4GW3 — ollama/ollama (REJECT)

- Aliases: CVE-2025-66960
- Mechanism: Panic in readGGUFV1String via GGUF-v1 string length
- Candidate: x: add skills spec / fix agent loop message handling — `b1d711f8cc6e4869f656f07bbdaf7ba62cd4758c, 5e23c4f2f74b6e2823d117523d821d9c78e699b4`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 18. GHSA-2RR6-9W84-3V7P — swoole/swoole-src (REJECT)

- Aliases: CVE-2026-24814
- Mechanism: Integer overflow / wraparound in thirdparty/hiredis sds.c
- Candidate: add SWOOLE_ODBC_LIBS / Add stdext module — `f819fa8cb11e9c58ada5fa4647c96c777f7fb1dd, 809eb827f54f57b94a232fdb6a096add95159e8b`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 19. GHSA-V546-JRFG-PH8Q — RawTherapee/RawTherapee (REJECT)

- Aliases: CVE-2026-24808
- Mechanism: Integer overflow / wraparound in rtengine dcraw.cc
- Candidate: Denoise blur/sharpening improvements / guiutils comment — `cc4fcc32e042b194f7b66d8bce20904ac53a2cc8, c4b04007107a426dd7011002e8085aa6f398ab60`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is an unrelated feature/refactor that does not touch the vulnerable surface; it cannot be the introducing change.

### 20. GHSA-2678-G677-R4GX — open5gs/open5gs (REJECT)

- Aliases: CVE-2026-4988
- Mechanism: DoS in CCA Message Handler (smf_gx_cca_cb / smf_gy_cca_cb / smf_s6b)
- Candidate: pfcp: find_or_add + defensive FAR/URR resets — `c42d7b7d9b930b5b421b02c5ad3625129e78ac60, d28e2f7f49f084bed6020440b0b54a784fbce56a`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 21. GHSA-7H3P-2HJJ-2V8X — open5gs/open5gs (REJECT)

- Aliases: CVE-2025-46115
- Mechanism: DoS via crafted PDU Session Modification Request causing ogs_assert failure in SMF
- Candidate: pfcp: find_or_add + defensive FAR/URR resets — `c42d7b7d9b930b5b421b02c5ad3625129e78ac60, d28e2f7f49f084bed6020440b0b54a784fbce56a`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 22. GHSA-CCV7-FR4H-54HJ — open5gs/open5gs (REJECT)

- Aliases: CVE-2026-7518
- Mechanism: open5gs DoS (issue #4395)
- Candidate: pfcp: find_or_add + defensive FAR/URR resets — `c42d7b7d9b930b5b421b02c5ad3625129e78ac60, d28e2f7f49f084bed6020440b0b54a784fbce56a`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 23. GHSA-X3Q3-9P69-QVGQ — open5gs/open5gs (REJECT)

- Aliases: CVE-2026-7535
- Mechanism: open5gs DoS (issue #4399)
- Candidate: pfcp: find_or_add + defensive FAR/URR resets — `c42d7b7d9b930b5b421b02c5ad3625129e78ac60, d28e2f7f49f084bed6020440b0b54a784fbce56a`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 24. GHSA-286X-7QF6-X2H4 — open5gs/open5gs (REJECT)

- Aliases: CVE-2026-7536
- Mechanism: open5gs DoS (issue #4400)
- Candidate: pfcp: find_or_add + defensive FAR/URR resets — `c42d7b7d9b930b5b421b02c5ad3625129e78ac60, d28e2f7f49f084bed6020440b0b54a784fbce56a`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

### 25. GHSA-RQX4-V9GM-WJFH — open5gs/open5gs (REJECT)

- Aliases: CVE-2026-7583
- Mechanism: open5gs DoS (issue #4401)
- Candidate: pfcp: find_or_add + defensive FAR/URR resets — `c42d7b7d9b930b5b421b02c5ad3625129e78ac60, d28e2f7f49f084bed6020440b0b54a784fbce56a`
- Gates: `{"identity_gate": "PASS", "ai_hunk_gate": "FAIL", "topology_gate": "UNKNOWN", "but_for_gate": "FAIL", "fix_reversal_gate": "FAIL", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN"}`
- Reasoning: candidate AI commit is a fix/defensive change on a pre-existing surface, not the vulnerable introduction; AI-authored fix for a pre-existing vuln is excluded.

