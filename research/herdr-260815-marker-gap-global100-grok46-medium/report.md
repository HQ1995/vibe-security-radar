# Unrecognized-marker gap audit (global first-party 100)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Matcher policy is not edited.

## Verdict

Inspected 100 strongest unseen exact atomic hits of the admitted unrecognized forms on the remaining first-party window: ROUTE 0, PASS 0, REJECT_ROUTING 100.
ROUTE IDs: none.

## Freeze

Pinned unrecognized-marker729 result SHA256 `833e70f45f95bb985f9b17b9dcd84c6546600adf86a747231b087664365f9bf6` report `8df1010a590be225bfb63d7a0d84b87b87417642a87e37787a570c40d009ba70` replay `569be260cccc85fa07784a27d81c5ef200992d573da9d9a21ac4387440a2087e`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
Commit-first G-N assignment-manifest SHA256 `f657aca2a1463e5f550e6cbdaa4e6b797a4133d6077ac1e6c15e74a6c0e12fe3` records first-party window-active total 8757 (A-F 2423, G-N 2623, O-Z 3680, digit-or-other 31).
Frozen github/advisory-database HEAD `a42c436870111aa3f221257c9d56126a93173ccc` committer 2026-08-13T20:57:17+00:00 used by the commit-first shards. github-reviewed tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`. Parsed 2025+2026 JSON 12817, parse errors 0.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only. Credential-like environment variables were stripped.

## Universe and exclusions

Starting population is the frozen first-party active GHSA universe used by the commit-first shards: unwithdrawn github-reviewed 2025-2026 JSON with a `github.com/{owner}/{repo}/security/advisories/GHSA-*` reference and published on or after 2025-05-01. Unique IDs 8757. Sorted-ID SHA256 `e4e79ff90f0331d993ef39e66a8fb4a4b20c8e72e7945b2f4f241aa1b0ea1ad0`.
Exclude canonical94 (75 of 94 sit in this universe), every explicit terminal identity in herdr/orchestrator 260813-260815 top-level cases/adjudication/result artifacts skipping work/notes/pages/snapshot/clones/cache/tmp/node_modules and files with mtime >= 1786775000 (files=722 cases.jsonl=335 adjudications=34 result.json=353 rows=17463 distinct explicit terminal verdict identities=12466, of which 7854 sit in the universe), and all 729 identities already audited in unrecognized-ai-marker729 (sorted-ID SHA256 `ffeceb62c6fa243e5865020390ba5de297d01ce3fc0ac1c9754f46d2739c63b1`; all 729 sit in the universe and all 729 already have terminal rows, so the extra 729 subtraction is 0).
Remaining 903. Sorted-ID SHA256 `55aaed45750bff64ad9cf91d84668a2eaa3a1c614048e718ee8238ce45feadd4`.

## Conservation

8757 = 75 canonical94-in-universe + 7779 later-or-equal terminals + 0 extra-729 + 903 remaining. Holds.
903 = 54 remaining identities on repos that contain an admitted-form atomic hit + 847 remaining identities with a local clone and no admitted form + 2 remaining identities with no local clone (GHSA-49P4-PX3H-RQ49 containers/buildah; GHSA-XFHR-Q72Q-JCRJ aws/bedrock-agentcore-starter-toolkit). Holds.
Atomic unrecognized v3-miss commits in remaining repos: 287 (of 288 exact-form commits; 1 merge). Linked remaining identity-commit pairs: 599.
599 = 28 ancestry-YES + 17 ancestry-NO with a hex object treated as closer + 554 with no resolvable same-repo closer. Code overlap with that hex object: 3, all ancestry-NO.
100 = 100 REJECT_ROUTING + 0 ROUTE + 0 UNREVIEWED. Assigned hits 100=100+0. Holds. Did not pad.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0.
CVE aliases are not counting units. Shared SHA is not identity dedupe.

## Admitted forms only (matcher v3 miss; first-party owned)

1. Complete attribution trailer `Made-with: Cursor`. Cursor Help documents Agent attribution as a `Made with Cursor` trailer (https://cursor.com/help/integrations/git). Cursor staff (deanrie, 2026-04-16) states IDE and CLI agents emit `Made-with: Cursor` (https://forum.cursor.com/t/fix-auto-commit-ammend-of-cursor-to-match-linux-kernel-recommendations/158177). Production verbs are Generated/Created/Written/Assisted only, so this complete line misses. Plausible earliest date 2026-03-01.

2. Help-page spacing `Made with Cursor` is the same vendor form and also misses. This remaining freeze has 0 exact-line hits of that spelling.

3. OpenCode vendor-owned coauthor `Co-Authored-By: opencode <noreply@opencode.ai>` and generated-with footer `Generated with [opencode](https://opencode.ai)` as quoted on first-party issue 558 created 2025-06-30 (https://github.com/anomalyco/opencode/issues/558) and issue 786. Policy already has alias OpenCode and email `opencode@sst.dev`, but not `noreply@opencode.ai` and not the markdown footer. Plausible earliest date 2025-06-01. Remaining freeze: 1 exact noreply coauthor (jlowin/fastmcp docs), 0 generated-with markdown footers.

Rejected near-misses from the 729 packet stay rejected: CodeRabbit, Codeflash, Mastra, `opencode@local`, filenames, prose, and carrier transfer.

## Method

Remaining identities only. Production `matches_for_commit` v3 is the miss oracle.
Pre-fix link requires a resolvable same-repo commit object from the advisory JSON. Hex blobs that are not the GHSA closer still fail same-mechanism. Cap was not used as a substitute for a missing closer.
Exact atomic means n_parents=1. Then same-mechanism hunk, ancestry, but-for, minimum fix reversal, release containment, and uniqueness. Fail closed: missing closer is ancestry FAIL. ROUTE only with no fatal FAIL. Never PASS.
Deterministic inspect order: one strongest pair per remaining identity on a hit repo (54), then leftover ancestry-YES pairs, then fill to 100 by the same gated rank (ancestry-YES, then code-overlap, then any hex closer, then n_code_files, case_id, sha).

## Why ROUTE is 0

The 28 ancestry-YES pairs are GHSA-MQXV-9RM6-W8QC (lin-snow/Ech0, 27 hub/docs/auth commits that are ancestors of release bump `451c7c10eb1f23f7525c163e83f8b39f46d5aad0` which only touches CHANGELOG.md and internal/version/version.go) and GHSA-9XQ9-36W5-Q796 (InternLM/lmdeploy `797c8fcaf4447a2722bdbfc4b69129f3fe55866e` n-gram route params; the hex closer `9df0eff7c38ae69b9d4b9f7ad1441e484d439f92` is an unrelated multimodal message-type commit). Neither is the named mechanism hunk. but-for FAIL.
Keras GHSA-MQ84-HJQX-CWF2 marker `b8909f88162e81d882713db7f0007eb272c2a5c8` is Normalization.adapt, not StringLookup.
Langflow hex objects are vulnerable snapshots or unrelated paths; the three file-overlap pairs are not ancestors of those objects and are starter-project JSON or gunicorn preload, not playground RCE / assistant eval.
OpenCode hit on FastMCP remaining rows: commit `71fb4ab6716b16931bb7ea234001d426ba18545f` only edits docs/clients/logging.mdx.
LobeHub/OpenClaw high file-count markers have no resolvable same-repo closer in the advisory JSON, so ancestry fails closed.
No inspected row closes identity+atomic hunk+ancestry+but-for+fix-reversal+release together.

## ROUTE IDs

none

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 94. This packet did not edit the matcher, canonical ledger, or any directory outside this packet. No commit or push. No PASS.

Stop.
