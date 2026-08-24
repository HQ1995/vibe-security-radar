# Adjudication report — unr-adj4-slice-8 (5 rows)

Verdict: **0 countable**. 5 REJECT. Every candidate AI commit is in a code area disjoint from the mechanism named by its advisory; none authors the vulnerable hunk.

Method: read each first-party advisory JSON from the local advisory-database clone (all 5 present), fetched/verified each candidate AI commit diff in the sweep pool via git smart-HTTP (--filter=blob:none, no GitHub API, no blame/SZZ), then compared changed files (git diff-tree) and message against the advisory mechanism. Closest call was diff-checked: be4bc916fd05 (Chinese AI providers) adds provider config/routing but contains no x-ai-provider header or info-leak hunk; 9bf0c7f23fae removes only a CI npm audit step (not a code vulnerability).

Cross-cutting: all 5 advisories are unreviewed (github_reviewed:false) with empty affected[]; no cross-repo mappings (identity_gate PASS on every row).

### GHSA-5RGR-3GCC-7FPH — DayuanJiang/next-ai-draw-io → REJECT

- aliases: CVE-2026-50757; CWE CWE-22
- mechanism: Directory Traversal vulnerability in DayuanJiang next-ai-draw-io 0.4.13 allowsa remote attacker to execute arbitrary code via the nex-ai-draw-io/mcp-server
- candidates: 3ca46f44c1b6, 9bf0c7f23fae, be4bc916fd05, 7fbc857d3a05
- candidate files: app/api/validate-model/route.ts (novita case); app/api/chat/route.ts + lib/ai-providers.ts + model-selector (Chinese AI providers); .github/workflows/ci.yml (npm audit step removal); components/ai-elements/model-selector.tsx + ui/command.tsx
- AI marker: co_author_trailer (Claude Opus 4.6, Copilot, Shinyi@openclaw.ai)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (next-ai-draw-io mcp-server directory traversal (RCE) (CWE-22)): app/api/validate-model/route.ts (novita case); app/api/chat/route.ts + lib/ai-providers.ts + model-selector (Chinese AI providers); .github/workflows/ci.yml (npm audit step removal); components/ai-elements/model-selector.tsx + ui/command.tsx

### GHSA-9F9R-G2R4-3GV5 — DayuanJiang/next-ai-draw-io → REJECT

- aliases: CVE-2026-50756; CWE CWE-1390
- mechanism: An issue in DayuanJiang next-ai-draw-io 0.4.13 allows a remote attacker to obtain sensitive information via the x-ai-provider component
- candidates: 3ca46f44c1b6, 9bf0c7f23fae, be4bc916fd05, 7fbc857d3a05
- candidate files: app/api/validate-model/route.ts (novita case); app/api/chat/route.ts + lib/ai-providers.ts + model-selector (Chinese AI providers); .github/workflows/ci.yml (npm audit step removal); components/ai-elements/model-selector.tsx + ui/command.tsx
- AI marker: co_author_trailer (Claude Opus 4.6, Copilot, Shinyi@openclaw.ai)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (next-ai-draw-io x-ai-provider sensitive information disclosure (CWE-1390)): app/api/validate-model/route.ts (novita case); app/api/chat/route.ts + lib/ai-providers.ts + model-selector (Chinese AI providers); .github/workflows/ci.yml (npm audit step removal); components/ai-elements/model-selector.tsx + ui/command.tsx

### GHSA-WJCQ-XP37-C947 — zhayujie/CowAgent → REJECT

- aliases: CVE-2026-18992; CWE CWE-285
- mechanism: A vulnerability was detected in zhayujie CowAgent up to 2.1.1. This vulnerability affects the function _select_tools of the file agent/evolution/executor.py of the component Self-Evolution Review Agent. Performing a manipulation results in incorrect authorization. The attack is possible to be carried out remotely. The exploit is now public and may be used.
- candidates: 41855ed51135, 02bc91f4af85, 52209217fc60
- candidate files: .github/workflows/release.yml (mac signing); desktop/build/* (backend packaging); channel/wecom_bot/wecom_bot_channel.py + channel/web/web_channel.py (callback path)
- AI marker: co_author_trailer (Copilot / Cursor)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (CowAgent _select_tools incorrect authorization (CWE-285)): .github/workflows/release.yml (mac signing); desktop/build/* (backend packaging); channel/wecom_bot/wecom_bot_channel.py + channel/web/web_channel.py (callback path)

### GHSA-2F59-92G6-QM58 — DayuanJiang/next-ai-draw-io → REJECT

- aliases: CVE-2026-72777; CWE CWE-918
- mechanism: Next AI Draw.io through 0.4.16 contains a server-side request forgery vulnerability in the POST /api/parse-url endpoint due to hostname validation that only checks string patterns without DNS resolution. Unauthenticated attackers can supply hostnames that bypass string validation but resolve to internal addresses, allowing them to reach arbitrary internal HTTP services and exfiltrate responses including cloud metadata.
- candidates: 3ca46f44c1b6, 9bf0c7f23fae, be4bc916fd05, 7fbc857d3a05
- candidate files: app/api/validate-model/route.ts (novita case); app/api/chat/route.ts + lib/ai-providers.ts + model-selector (Chinese AI providers); .github/workflows/ci.yml (npm audit step removal); components/ai-elements/model-selector.tsx + ui/command.tsx
- AI marker: co_author_trailer (Claude Opus 4.6, Copilot, Shinyi@openclaw.ai)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (next-ai-draw-io POST /api/parse-url SSRF (CWE-918)): app/api/validate-model/route.ts (novita case); app/api/chat/route.ts + lib/ai-providers.ts + model-selector (Chinese AI providers); .github/workflows/ci.yml (npm audit step removal); components/ai-elements/model-selector.tsx + ui/command.tsx

### GHSA-7WVW-5P69-5396 — DayuanJiang/next-ai-draw-io → REJECT

- aliases: CVE-2026-73037; CWE CWE-79
- mechanism: Next AI Draw.io 0.2.1 through 0.4.16 contains a reflected cross-site scripting vulnerability in the mcp query parameter that is interpolated without escaping into HTML and JavaScript. Attackers can craft malicious URLs to execute arbitrary JavaScript in the localhost origin, enabling exfiltration of diagram sessions and API data.
- candidates: 3ca46f44c1b6, 9bf0c7f23fae, be4bc916fd05, 7fbc857d3a05
- candidate files: app/api/validate-model/route.ts (novita case); app/api/chat/route.ts + lib/ai-providers.ts + model-selector (Chinese AI providers); .github/workflows/ci.yml (npm audit step removal); components/ai-elements/model-selector.tsx + ui/command.tsx
- AI marker: co_author_trailer (Claude Opus 4.6, Copilot, Shinyi@openclaw.ai)
- reasoning: candidate AI commit(s) do not introduce the named mechanism (next-ai-draw-io mcp query parameter reflected XSS (CWE-79)): app/api/validate-model/route.ts (novita case); app/api/chat/route.ts + lib/ai-providers.ts + model-selector (Chinese AI providers); .github/workflows/ci.yml (npm audit step removal); components/ai-elements/model-selector.tsx + ui/command.tsx
