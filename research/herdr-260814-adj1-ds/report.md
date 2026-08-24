# GHSA unreviewed-adjudication slice 1 — verdict-first report

## Verdict: 0 countable / 25 UNKNOWN. No proposal passes; nothing forwarded to leader replay.

Every row is an **unreviewed** GHSA with an empty `description`/`summary`, so the vulnerable mechanism is not named in the first-party packet. Without a named mechanism, `identity_gate`, `but_for_gate`, `fix_reversal_gate`, and `uniqueness_gate` cannot close, and there is no fix commit to resolve topology/release. All 25 rows therefore stay UNKNOWN and are not countable under CONTRACT.md.

## What was actually verified (positive evidence, not a negative inference)

- All 8 distinct candidate commits were fetched (git smart-HTTP, blobless depth-2) and read. Every one carries an explicit AI marker: `Co-authored-by: Copilot <...>`, `google-labs-jules[bot]`, or authored by `copilot-swe-agent[bot]`.

- The candidates are feature/UI/build commits, not security fixes or security-boundary changes (see per-row notes).

- The Oneflow block is a clear triage artifact: commit `9fdc6d8a` (`interpolate_like`, PR #10644) was triage-matched to 18 distinct Oneflow advisories (CVE-2025-65886..65891, 70999..71011; issues #10648..#10666). One tensor-resize utility cannot be the introducing change for 18 different mechanisms.

## Per-row reasoning

- **GHSA-GX4M-RF3M-46FM** (woocommerce/woocommerce) — UNKNOWN. wrong_edge (advisory code ref = customize-store/utils.js; candidate = email-editor). Candidate `['ef42db49f0a5d8624dd4637c2f02eca8c0e7d6c7']`: Adds Personalization Tags support to the email-editor Button block (JS email-editor blocks + PHP Personalizer). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-GFGM-2FRC-X4F5** (openemr/openemr) — UNKNOWN. wrong_edge (CVE-2013-10044 SQLi privesc RCE; candidate = 2025 billing-form UI display fix). Candidate `['42169b1586e1f141eff3b9cafa71c2a9bbc4f6f0']`: Fixes HCFA-1500 Miscellaneous Billing Options qualifier dropdown defaulting (UI display/save fix). AI marker: Co-authored-by: google-labs-jules[bot] <161369871+google-labs-jules[bot]@users.noreply.github.com>.

- **GHSA-P2GR-8XQX-RXMG** (bunkerity/bunkerweb) — UNKNOWN. wrong_edge (1-line var->let JS refactor, no security surface). Candidate `['fa26668ff213ee3098d98a02cddc21c7dfc20f4c']`: One-line refactor in plugin_page.js (`var tableLength` -> `let tableLength`). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-F3FR-83VX-7F8C** (Pierrad/obsidian-github-copilot) — UNKNOWN. indeterminate (markdown/mermaid rendering feature could be an XSS surface, mechanism unnamed). Candidate `['7629f9fa23b5390fb19b2ab4e01cb9f17346b96a']`: Adds remark-gfm markdown-table rendering + Mermaid diagram rendering to chat messages. AI marker: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>.

- **GHSA-JVQ3-99WQ-J8XQ** (Qloapps/QloApps) — UNKNOWN. wrong_edge (1-line whitespace fix, no security surface). Candidate `['8179b4457a1f757c3cea70071682680be9687074']`: One-line whitespace fix in AdminOrdersController.php (removes trailing space in a label). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-FQ99-2537-XJQ6** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-GM99-G636-34FH** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-GXH3-VMJW-7F4Q** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-P4FC-FVWP-2M9P** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-PP3Q-3FPH-XPQH** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-M5GW-75M6-RGCF** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-M9P8-WVPP-VMMM** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-R8PW-F6W2-WJPH** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-878F-H9GJ-457W** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-2XQ9-F9FW-JGF9** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-4R9C-Q9J4-P457** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-6JJ7-2576-P556** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-9RXJ-WRX5-6463** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-HF2W-7552-3W3C** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-VMPG-M2MF-CWRV** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-QQ36-HR32-5HM8** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-V4CC-RFXV-6Q34** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-42VV-V8MP-5939** (Oneflow-Inc/oneflow) — UNKNOWN. wrong_edge (one interpolate_like commit #10644 triage-matched to 18 distinct CVEs/issues #10648-10666). Candidate `['9fdc6d8a67c857a1a032098a4d7246728e4d3ab8']`: Adds interpolate_like utility to oneflow.nn.functional (tensor resize). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-XJPF-MWM5-W4CR** (Autodesk/arnold-usd) — UNKNOWN. indeterminate (large meshlight rendering feature, CVE-2026-0659 mechanism unnamed). Candidate `['3cec10792ca2b3d310a4481c3bde854cee8e800f']`: MeshLightAPI support: new meshlight scene index + render delegate (large rendering feature). AI marker: Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>.

- **GHSA-RG64-8MRM-6X23** (yangjian102621/geekai) — UNKNOWN. wrong_edge (frontend build migration, CVE-2026-2558 mechanism unnamed). Candidate `['94a5187e752e350c815b75f02dc761758e69bf7e']`: Migrates frontend build from Vue CLI to Vite (build tooling only). AI marker: google-labs-jules[bot] <161369871+google-labs-jules[bot]@users.noreply.github.com>.


## Blockers for leader

- all 25 advisories are unreviewed entries with empty description/summary; the vulnerable mechanism is not named in the first-party GHSA object

- advisory references contain CVE/issue/release URLs but no minimum fix commit, so fix_reversal_gate and release_gate cannot close

- no row has all seven gates PASS; nothing is proposed for leader replay
