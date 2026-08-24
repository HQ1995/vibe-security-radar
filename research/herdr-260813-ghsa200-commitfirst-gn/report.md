# G-N commit-first GHSA discovery

Status: **PARTIAL / HOLD**. Proposed PASS = 2. Countable PASS = 0. 
Worker PASS is a proposal only. These two rows stay uncounted until independent leader review.

Contract SHA256: `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3` 
Advisory-database freeze: `a42c436870111aa3f221257c9d56126a93173ccc` (`2026-08-13T20:57:17+00:00`, origin/main at freeze).

Independence: first-party `github/advisory-database`, official GitHub advisory/release pages, and git history under `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn` only. Sibling worker proposals were not used as evidence. Shared tracked files were not edited. No commit, push, or credential output.

## Verdict

This shard proposes two first-party GHSA cases, both in `homeassistant-ai/ha-mcp`, after mining AI-marked commits first and then requiring same-mechanism identity, atomic member topology, minimum fix reversal, and released containment. Neither proposal is admitted here.

All other reviewed rows are REJECT, UNKNOWN, or BLOCKED. The remaining assignment is UNREVIEWED, not REJECT.

## Assignment conservation

Owner rule: first character of the repository owner, casefolded, in `g`-`n` inclusive. 
First-party rule: a reference URL matches `github.com/{owner}/{repo}/security/advisories/GHSA-*`. 
Window: published on or after `2025-05-01`. Active means not withdrawn.

| Set | Count |
|---|---:|
| First-party window-active partition A-F | 2423 |
| First-party window-active partition G-N | 2623 |
| First-party window-active partition O-Z | 3680 |
| First-party window-active partition digit-or-other | 31 |
| Partition sum | 8757 |
| G-N excluded by fp211 / canonical / publication union | 46 |
| G-N assigned (novel) | 2577 |
| Unique assigned repositories | 580 |

Conservation check: `46 + 2577 = 2623`, disjoint, no non-G-N leak, no exclusion leak. True.

Exclusion union at freeze: 505 public IDs (282 GHSA, 222 CVE, 1 other).

## Commit-first mine

Clones only under `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn`. Message scan uses a single POSIX ERE for production-style trailers and vendor addresses. Hits are routing, never causal proof.

| Mine result | Count |
|---|---:|
| Assigned repositories | 580 |
| Scanned | 578 |
| Clone fail / 404 | 2 |
| Repositories with at least one AI-marked commit | 358 |
| AI-marked commits (routing) | 43667 |
| Exact advisory-SHA AND AI-commit intersections | 93 |
| Subject-overlap intersections (routing only) | 640 |

The two 404 repositories are `IEatUranium238/Cattown` and `leshchenko1979/fast-mcp-telegram`. Their assigned GHSAs are BLOCKED.

## Deep-reviewed rows

| Worker verdict | Rows |
|---|---:|
| PASS (proposal only) | 2 |
| REJECT | 93 |
| UNKNOWN | 4 |
| BLOCKED | 2 |
| Unresolved assignment (UNREVIEWED) | 2476 |

### Proposed PASS

**GHSA-G39V-CVJH-8FPF** (`homeassistant-ai/ha-mcp`) -- `AI_DIRECT_ROOT`. 
PR #827 member `3f71508dad90fec6235b65b4d0bf234afd322352` is marked `Co-Authored-By: Claude Opus 4.6` and adds `backup_dir = config_dir / "www" / "yaml_backups"`. The squash carrier is `1f322cf05db736fe3df9c7e16ac87b0cb1c6d30e`. All seven PR members carry the same Claude trailer. `v7.4.0` (2026-04-29) contains the path and not the fix. `v7.5.0` (2026-05-13) moves backups to `.ha_mcp_tools_backups/`. Removing the AI member eliminates the unauthenticated `/local/` backup surface.

**GHSA-PF93-J98V-25PV** / `CVE-2026-32112` (`homeassistant-ai/ha-mcp`) -- `AI_DIRECT_ROOT`. 
Member `aae7acba91dc21fc897ef6b78989b1f548c4083e` is marked `Generated with Claude Code` / `Co-Authored-By: Claude` and adds `consent_form.py` f-string HTML with unescaped `display_name`, `client_id`, `redirect_uri`, and `state`. The squash carrier `39806871c9720bf8afdcf3e061095c0dd63dea7f` has the identical `consent_form.py` blob (`b2847749...`) as the member and as `v6.7.2`. `v7.0.0` applies `html.escape` in `dc8eaa16a8550f885614655f14b6fd9fe429b278`. This is a different mechanism from excluded `GHSA-FMFG-9G7C-3VQ7` / `CVE-2026-32111` (user-supplied `ha_url` SSRF in `provider.py`). Shared SHAs do not merge those cases.

### REJECT (commit-first exact refs and incomplete-language)

Ninety-three exact advisory-SHA AND AI-commit hits were reviewed. Almost all cited SHAs are AI-marked **fixes**. An AI-marked patch is not an introducing hunk. Those rows fail `ai_hunk_gate` / `but_for_gate` for origin and were not promoted as incomplete remediation without `remediation_patch_delta_gate`.

Specific incomplete-language rejects:

- `GHSA-9QHQ-V63V-FV3J` (PraisonAI): cited allowlist commit `47bff654` has no AI trailer.
- `GHSA-R78R-RWRF-RJWP` (Network-AI): parent fix closed CORS; residual is the pre-existing empty default secret. Sibling path, not patch-delta.
- `GHSA-22C2-9GWG-MJ59` (langroid): Copilot trailer is on a `try/finally` wrap, not the sanitizer.
- `GHSA-CVQ5-HHX3-F99P` (kyverno): Copilot trailer is on a unit test; the security hunk is unmarked.

### UNKNOWN (preserved)

- `GHSA-Q855-8RH5-JFGQ` -- AI-marked fix; introducing unauthenticated root settings mount not isolated.
- `GHSA-892R-P3JQ-JP24`, `GHSA-JXCW-QP4H-6JFQ`, `GHSA-RG3H-X3JW-7JM5` -- PraisonAI incomplete-auth / SQL claims; AI-marked incomplete guard plus later same-boundary closure not isolated.

### BLOCKED (preserved)

The two 404 repositories above.

## Hold reason

Keyword or commit-ref routing is not a census. Seven-gate review did not finish 2577 assigned GHSAs or 358 AI-commit repositories. Status stays PARTIAL/HOLD. Unresolved rows are UNREVIEWED.

## Claim boundary

- Countable PASS requires all seven gates on a first-party GHSA case and leader admission.
- Proposed PASS: **2**. Countable PASS: **0**.
- REJECT / UNKNOWN / BLOCKED are preserved. Absence of review is not negative proof.
- Routing, branding, OSV `introduced`, commit subjects, and ancestry alone are never causal proof.
- Incomplete remediation was not counted unless the contract patch-delta rule closed.
- No tracked file or other worker directory was edited. Clones only under the commit-gn cache.
