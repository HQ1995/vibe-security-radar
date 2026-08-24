# AI fix slice 3 adjudication

## Verdict first

All 25 assigned rows are terminal and non-countable. Every `fix_ref` is presented by the local first-party advisory as a closing patch for a vulnerability that predates that commit. The final verdict is therefore `REJECT_AI_FIX_ONLY` for all 25 rows. No row is `AI_INCOMPLETE_REMEDIATION`, no row is `AI_NEW_SURFACE_CONTRIBUTOR`, and the packet contributes zero countable proposals. Because there are no incomplete-remediation verdicts, no populated `original_vulnerability` block is required; every case records it as `null` rather than inventing an original advisory or introducing SHA.

One row has an additional identity failure: `GHSA-65F3-3278-7M65` is withdrawn as a duplicate of `GHSA-GW5H-H6HJ-F56G`. One gate remains unknown without affecting the terminal rejection: the Oak advisory records a last-affected version but no fixed release event, so its `release_gate` is `UNKNOWN`.

These are worker adjudications only. Canonical84 remains the claim layer, publication remains `HOLD`, and the greater-than-200 claim remains unsupported.

## Gate accounting

Gate order in the per-row table is identity / AI hunk / topology / but-for / fix reversal / release / uniqueness.

| Gate | PASS | FAIL | UNKNOWN | Decisive boundary |
| --- | ---: | ---: | ---: | --- |
| `identity_gate` | 24 | 1 | 0 | The Gogs row is a withdrawn duplicate; the other local GitHub-reviewed objects are active. |
| `ai_hunk_gate` | 0 | 25 | 0 | Nine explicit AI markers are on closing patches, not vulnerable hunks. Sixteen rows have no explicit AI marker at all. |
| `topology_gate` | 25 | 0 | 0 | Each assigned SHA is the exact advisory-referenced closing commit or one branch member of the advisory's minimum fix set; no authorship is transferred from a carrier. |
| `but_for_gate` | 0 | 25 | 0 | Removing a closing patch restores the older vulnerability; it does not eliminate or materially shrink a candidate-authored vulnerable surface. |
| `fix_reversal_gate` | 25 | 0 | 0 | Each first-party object names the exact candidate or its branch fix set, and the commit object describes the same invariant reversal. Local parent diffs were also available for 21 rows. |
| `release_gate` | 0 | 24 | 1 | For the countable-causality test, the candidate occurs on the fixed side rather than in a vulnerable artifact. Oak has no fixed release event and remains unknown. |
| `uniqueness_gate` | 24 | 1 | 0 | No active assigned identity appears in canonical84; the withdrawn Gogs identity duplicates another GHSA. |
| `remediation_patch_delta_gate` | 0 | 0 | 0 | `NOT_APPLICABLE` for all 25: no advisory describes a released residual of the assigned candidate followed by a later amendment of that same boundary. |

## Marker-source disagreement

The slice's stored `ai_authored_fix: true` value is not reliable. The producer at `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fetch_markers.py` treats the generic text `co-authored-by:` as sufficient for AI authorship. That turns ordinary human coauthor trailers into AI hits.

Only nine candidate objects contain an explicit AI marker: Avo and Oak (Cursor), two Open WebUI fixes and one OpenClaw fix (Claude), MCP Inspector (Claude Code), the other OpenClaw fix (`[AI]` in its subject), psd-tools (Claude Sonnet), and Pimcore deserialization hardening (Copilot). The other 16 rows contain only human or generic automation coauthors. This disagreement strengthens rejection for those 16 rows, but it does not change the role result: even the nine genuinely AI-marked SHAs are final repairs excluded by the study definition.

## Per-row adjudication

| # | Case and repository | Marker | Gates | Closing-patch evidence |
| ---: | --- | --- | --- | --- |
| 1 | `GHSA-4WHF-RMX5-8FRV` — `cgriego/active_attr` | Human coauthor only | `P/F/P/F/P/F/P` | The advisory names `dab95e58` as the ReDoS patch and fixes the range at 0.15.4. |
| 2 | `GHSA-6X8V-2FQ5-2229` — `zitadel/zitadel` | Human coauthor only | `P/F/P/F/P/F/P` | The fixed pseudo-version ends in `6082e59d47c1`; the commit adds explicit resource-owner overwrite behavior for recycled aggregate IDs. |
| 3 | `GHSA-VF5M-XRHM-V999` — `nautobot/nautobot` | Human coauthor only | `P/F/P/F/P/F/P` | `3d964f99` and `d33d0c15` are the 2.x and 1.x Job Button authorization fixes, not remediation stages. |
| 4 | `GHSA-8FQ9-273G-6MRG` — `avo-hq/avo` | Cursor | `P/F/P/F/P/F/P` | `995928e5` applies the missing attach check to the mutating create endpoint and explicitly says it fixes this GHSA. |
| 5 | `GHSA-RW72-V6C7-HF9R` — `nescalante/urlregex` | Human coauthors only | `P/F/P/F/P/F/P` | The advisory names `e5a085af` as the patch and 0.5.1 as fixed; its commit narrative replaces the vulnerable regex engine with RE2. |
| 6 | `GHSA-R3V7-PC4G-7XP9` — `oakserver/oak` | Cursor Agent | `P/F/P/F/P/U/P` | `b60e6033` is the sole forwarded-header ReDoS repair; the advisory supplies no fixed release event. |
| 7 | `GHSA-M3QF-58WF-W979` — `open-webui/open-webui` | Claude Opus | `P/F/P/F/P/F/P` | The exact diff adds `check_model_access` after arena selection and before `bypass_filter` recursion; 0.10.0 is fixed. |
| 8 | `GHSA-RQJ7-6WRP-6G2G` — `open-webui/open-webui` | Claude Opus | `P/F/P/F/P/F/P` | The exact diff adds the global edit switch and per-user permission wrapper around the direct image-edit route; 0.10.0 is fixed. |
| 9 | `GHSA-3R7G-Q6CG-Q2VX` — `open-webui/open-webui` | Human coauthor only | `P/F/P/F/P/F/P` | `c05de13b` removes source content from the remaining leaking per-ID response; its PR revisions are one atomic closure in 0.11.0. |
| 10 | `GHSA-RFFM-9Q57-Q649` — `open-webui/open-webui` | Human coauthor only | `P/F/P/F/P/F/P` | `5278eb90` installs the restricted Vega loader and URL-parser check in one atomic commit; no first revision shipped separately. |
| 11 | `GHSA-G9HG-QHMF-Q45M` — `modelcontextprotocol/inspector` | Claude Code | `P/F/P/F/P/F/P` | The exact diff creates shared redirect validation and applies it to all named OAuth paths; 0.16.6 is fixed. |
| 12 | `GHSA-4GV9-MP8M-592R` — `langflow-ai/langflow` | Generic `autofix.ci` automation | `P/F/P/F/P/F/P` | `c188ec11` enforces authentication for the superuser CLI and is the advisory's sole closure; no explicit AI-generation marker exists in the object. |
| 13 | `GHSA-V6H2-P8H4-QCJW` — `juliangruber/brace-expansion` | Human coauthor only | `P/F/P/F/P/F/P` | The four equal-purpose SHAs are branch closures for 1.1.12, 2.0.2, 3.0.1, and 4.0.1, not an attempted-fix chronology. |
| 14 | `GHSA-Q2QC-744P-66R2` — `openclaw/openclaw` | Claude Opus | `P/F/P/F/P/F/P` | The exact one-line fix preserves the original explicit-key flag through sessionId resolution and adds regression coverage. |
| 15 | `GHSA-939R-RJ45-G2RJ` — `openclaw/openclaw` | `[AI]` subject marker | `P/F/P/F/P/F/P` | `2d97eae5` prefers trusted provider origins and excludes untrusted workspace choices; 2026.4.9 is fixed. |
| 16 | `GHSA-4F78-QHMW-8J8M` — `electron/electron` | Bot and human coauthors only | `P/F/P/F/P/F/P` | `04614eed` is one of four release-line allowlist fixes for a dock-state sink already present in its parent. |
| 17 | `GHSA-53QW-Q765-4FWW` — `django/django` | Human coauthor only | `P/F/P/F/P/F/P` | The subject calls `2135637f` the 2.2.x CVE fix; the other SHAs close the same validator DoS on 3.2 and 4.0. |
| 18 | `GHSA-7FCJ-PQ9J-WH2R` — `pyinstaller/pyinstaller` | Human coauthor only | `P/F/P/F/P/F/P` | `42a67148` is the code repair and `be948cf0` supplies rebuilt bootloaders; both form the final 3.6 fix set. |
| 19 | `GHSA-24P2-J2JR-386W` — `psd-tools/psd-tools` | Claude Sonnet | `P/F/P/F/P/F/P` | The advisory explicitly calls the reported compression findings pre-existing; `6c0a78f1` is the final 1.12.2 hardening squash. |
| 20 | `GHSA-9XG6-75MH-7X3F` — `pimcore/pimcore` | Human coauthor only | `P/F/P/F/P/F/P` | The advisory instructs users to apply `6970649f` directly or upgrade to 10.5.21. |
| 21 | `GHSA-36FC-7WJG-MFVJ` — `pimcore/pimcore` | Copilot | `P/F/P/F/P/F/P` | The exact diff adds `allowed_classes` restrictions at the advisory sinks and removes unsafe deep-copy unserialization. |
| 22 | `GHSA-5Q6M-3H65-W53X` — `facebook/create-react-app` | Human coauthors only | `P/F/P/F/P/F/P` | `f5e415f3` is the named `getProcessForPort` command-injection repair and 11.0.4 closes the range. |
| 23 | `GHSA-9XG7-MWMP-XMJX` — `TryGhost/Ghost` | Human coauthor only | `P/F/P/F/P/F/P` | `9513d2a3` and `c3017f81` are v6/v5 fixes for the old trailing-slash blocklist mismatch. |
| 24 | `GHSA-4F53-XH3V-G8X4` — `keycloak/keycloak` | Human coauthor only | `P/F/P/F/P/F/P` | The subject and diff close CVE-2023-3597 by restricting token types and fixing step-up authentication. |
| 25 | `GHSA-65F3-3278-7M65` — `gogs/gogs` | Human coauthor only | `F/F/P/F/P/F/F` | The candidate is the final PAM repair, but this GHSA is withdrawn as a duplicate and cannot supply a distinct first-party identity. |

## Source disagreements and preserved unknowns

- The truth-layer document prints canonical84 SHA-256 `a9b23a7ca39104f851b684a4089fa58f43887bb379895b68f6306c47d969ec06`; the file recomputes to `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`. Neither frozen file was edited, and the mismatch is recorded in `result.json`.
- The ZITADEL advisory's patch paragraph contains unrelated verification-flag wording, while its identity, summary, range, sole SHA, and commit body all bind the resource-owner closure. This copy defect is reported, not used to reclassify the closer as an origin.
- The OpenClaw session-status object says first patched 2026.3.25 in prose but fixes the ecosystem range at 2026.3.28. Both place the assigned SHA after the vulnerable releases, so the role result is unchanged.
- The Oak object uses `last_affected` and gives no fixed event. Its release gate remains `UNKNOWN`; no missing value was turned into a failure or pass.
- Depth-one sweep pools lack some parent objects. The owned-directory restriction was honored: no cache was deepened or modified. Twenty-one candidate-parent diffs were available in other existing local clones; the remaining four rows are rejected independently by their exact first-party final-patch binding and failed AI-hunk/but-for gates. No acceptance depends on missing parent data.

## Evidence and claim boundary

The assigned input SHA-256 is `2e725976bd87b85a3f3ae2a54cc55637fd6f3913de86fc90bc2daaaab1c87ca5`. First-party objects came from the two local advisory-database snapshots at heads `a42c436870111aa3f221257c9d56126a93173ccc` and `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`. Candidate objects came from `/home/hanqing/.cache/ghsa200-sweep-fetch/`; existing local analysis clones supplied available parent diffs. Per-row paths and replay commands are in `cases.jsonl`.

No GitHub API, REST call, network fetch, commit, checkout, reset, or push was used. Only `result.json`, `cases.jsonl`, and `report.md` in the owned output directory were written.
