# Fresh A-M batch 2 (first 80 remaining routed IDs)

Status: **COMPLETE for this 80-ID assignment**. Proposed PASS = **0**.  
Worker PASS is a proposal only. This batch does not make the parent A–M lane coverage-complete.

Independence: first-party advisory JSON, GitHub commit/repo API, and git clones. New clones and caches for this lane go under `/home/hanqing/.cache/ghsa200-worker-clones/fresh-am-batch2`. Do not add clones or large caches under `/tmp`. Historical `/tmp/ghsa200-worker-clones/fresh-am-batch2` files may remain; they were not moved. Sibling worker conclusions were not read as evidence. `fresh-am` artifacts were not modified.

## Assignment freeze

Source pool: `herdr-260813-ghsa200-fresh-am/routed-candidate-pool.jsonl` (376).  
Exclusions: 9 already deep-reviewed in `fresh-am/cases.jsonl`; 212 leader-declared `public_cases.jsonl` IDs (0 in pool); 25 pool IDs also in `freshness-qa/manifests/github_reviewed_window_added_ids.txt`.  
Remaining after exclusion: 346. Sorted uppercase GHSA lexicographically; this worker owns the first **80** (`GHSA-22C2-9GWG-MJ59` … `GHSA-6FPF-248C-M7WM`). Conservation and no-overlap checks are in `assignment-manifest.json`.

Advisory-database HEAD used for first-party JSON: `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86`.

## Verdicts (exactly 80 terminal rows)

| Worker verdict | Count |
|---|---:|
| PASS | 0 |
| REJECT | 25 |
| UNKNOWN | 51 |
| BLOCKED | 4 |

REJECT required decisive first-party git/API counterevidence. Incomplete clone census is UNKNOWN, not REJECT. Keyword hits remain routing only.

## REJECT (decisive)

Zero AI markers in a full clone of the affected product repository: `mcp-maigret`, `create-mcp-server-stdio`, `mcpo-simple-server`, `taskflow-ai`, `gemini-mcp-tool`, `mcp-kubernetes-server`, `fast-filesystem-mcp`, `gmaps-mcp`, `golang.org/x/crypto` (ssh/agent name), `node-code-sandbox-mcp`, `mcp-database-server`.

Unmarked introducing path plus AI only on a fix or a different surface:

| Case | Finding |
|---|---|
| `GHSA-27M7-FFHQ-JQRM` | Unmarked v1 adds `cloneRepo`; Claude only on a lockfile chore. |
| `GHSA-2C7F-FXWW-6W6C` | Unmarked `caption.go` history; Claude/OpenCode on unrelated tests/moderation. |
| `GHSA-3P2M-H2V6-G9MX` / `GHSA-5QHV-X9J4-C3VM` | Unmarked `android.ts`; AI hit is docs listing agent products. |
| `GHSA-3PVJ-JV98-QHJQ` | Unmarked daemon introduction; Jules later fixes `sessionId` traversal (wrong edge). |
| `GHSA-3R68-X3XC-RXPG` | Unmarked `client.py` first update; later Claude/OpenCode are fixes/docs. |
| `GHSA-4J28-22QP-RJCF` | Claude on `fix: patch path traversal`; `entry.py` history unmarked. |
| `GHSA-4XQG-GF5C-GHWQ` | Unmarked `port_forward.ts` by Suyog Sonwalkar. |
| `GHSA-5474-4W2J-MQ4C` | `memory.ts` introduced by `stainless-app[bot]` codegen, not a qualifying coding-agent marker. |
| `GHSA-54FQ-V6X8-244G` | Unmarked executor history; Copilot on a later remote-executor **fix**. |
| `GHSA-5CGR-J3JF-JW3V` | Unmarked git-server history (Spahr-Summers / Soria Parra). |
| `GHSA-63GR-G7JC-V8RG` | Unmarked first MCP `tools.ts`. |
| `GHSA-694P-3FXC-M92H` | Unmarked `first version`; Claude on command-injection **fix** / v1.0.4. |
| `GHSA-6F6R-M9PV-67JW` | Unmarked initial `src/index.ts`. |

## BLOCKED

Git tree used for routing is not the affected package, or the repo is gone:

- `GHSA-3VR4-CVMG-7FX4` package `copilot-api` vs PoC `August829/CVEP`
- `GHSA-5Q2P-3JG8-2M98` package `@samanhappy/mcphub` vs PoC `August829/YU1`
- `GHSA-4GC2-344Q-R2RW` package `ms-agent` vs PoC repo
- `GHSA-2R68-G678-7QR3` `doobidoo/mcp-memory-service` GitHub 404

## UNKNOWN (51)

Large uncloned product repos (LiteLLM, Flowise, PraisonAI, Claude Code, Magento, kubevirt, …), AI-heavy clones where the introducing hunk was not isolated (`phantom`, `git-mcp-server`, `python-sdk`), and cases where the only AI-marked advisory commit is a **security fix** but origin was not replayed (`n8n-mcp`, `mcp-gateway`, Langroid mitigation follow-up). Playwright MCP (`GHSA-6FG3-HVW7-2FWQ`): research-repo clone is the wrong tree; `microsoft/playwright` `1313fbd` is unmarked `allowed-hosts` **fix**, not origin.

No row closed all seven gates. Material-contributor / new-surface counting was allowed at narrowed scope; none had a demonstrated AI delta that removes a named surface with a released affected/fixed pair.

## Claim boundary

- Countable PASS requires all seven gates, including a released affected version and exact mechanism uniqueness.
- Proposed PASS: **0**.
- Unassigned remainder of the routed pool (266 IDs) is outside this batch.
