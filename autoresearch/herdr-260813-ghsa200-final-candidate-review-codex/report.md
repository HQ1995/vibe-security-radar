# Final candidate acceptance review

## Verdict first

The bounded 32-case candidate set closes at **31 ACCEPT, 1 NARROW, 0 REJECT, 0 UNKNOWN, and 0 BLOCKED**. The 31 accepted identities comprise **9 baseline revalidations** and **22 net-new GHSA candidates**. These are first-party GHSA identities; CVE aliases, mechanisms, commits, carriers, and report rows are not counting units.

Publication remains **HOLD**. This review does not edit or rebuild the canonical ledger, does not recompute the full strict-released lower bound, and does not support a greater-than-200 claim. The terminal `commitfirst-gn` input reviewed 101 of 2,577 assigned identities and left 2,476 explicitly unreviewed. No whole-shard completion is inferred.

The current leader contract was read in full and frozen at SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Exact packet hashes are in `manifest.json`; this includes the current post-ASCII-punctuation-fix `baseline-increm-odd/report.md` hash `d56ad50fa964772490e9609f5bca610b7953753822112ba4b6dbc40124b7d285` and unchanged cases hash `4d34a597329e2497b95ec68e9e893c07e07408f2f2775054821527532f79e94f`.

## Final disposition

| Cohort | ACCEPT | NARROW | REJECT | UNKNOWN | BLOCKED | Total | Counting effect |
|---|---:|---:|---:|---:|---:|---:|---|
| Baseline revalidations | 9 | 1 | 0 | 0 | 0 | 10 | Not net-new |
| Net-new candidates | 22 | 0 | 0 | 0 | 0 | 22 | Candidate additions pending canonical rebuild |
| **All final candidates** | **31** | **1** | **0** | **0** | **0** | **32** | 31 countable in this bounded review |

### Baseline revalidations

Accepted: `GHSA-56C3-VFP2-5QQJ`, `GHSA-5RV5-XJ5J-3484`, `GHSA-5XXX-QHH7-9287`, `GHSA-7P8R-X3MC-P8W7`, `GHSA-8WC8-HF36-MJH9`, `GHSA-JM78-9FVV-MHGR`, `GHSA-M4WX-M65X-GHRR`, `GHSA-MV93-W799-CJ2W`, and `GHSA-VC8F-X9PP-WF5P`.

Narrowed: `GHSA-4FXP-2M36-QV64` (ordinal 148).

### Net-new candidates

Accepted: `GHSA-3RP5-JJMW-4WV2`, `GHSA-3WXW-XV34-2FRG`, `GHSA-539M-9XH6-Q6RR`, `GHSA-5C6W-WWFQ-7QQM`, `GHSA-7C3W-FXGH-FRC7`, `GHSA-8JPQ-5H99-FF5R`, `GHSA-FMFG-9G7C-3VQ7`, `GHSA-G39V-CVJH-8FPF`, `GHSA-J4XF-96QF-RX69`, `GHSA-JV46-XFWM-36J7`, `GHSA-MF5G-6R6F-GHHM`, `GHSA-PF93-J98V-25PV`, `GHSA-PWF7-47C3-MFHX`, `GHSA-R48C-V28R-PF6V`, `GHSA-R9MR-M37C-5FR3`, `GHSA-RG8M-3943-VM6Q`, `GHSA-RQP8-Q22P-5J9Q`, `GHSA-W28W-GP39-M4P6`, `GHSA-WPXJ-VHFP-HHVM`, `GHSA-WV46-V6XC-2QHF`, `GHSA-WXHM-2MQ7-7697`, and `GHSA-XW8C-RRVX-F7XQ`.

## Gate findings

Every ACCEPT row closes identity, AI hunk, topology, but-for, fix reversal, affected/fixed release containment, and uniqueness under the exact recorded scope. Every accepted `AI_INCOMPLETE_REMEDIATION` row also closes `remediation_patch_delta_gate`: the AI change was an explicit security boundary attempt, a released artifact contained the incomplete boundary, the first-party GHSA covered its residual bypass, and the later fix directly amended that same boundary rather than an untouched sibling. These rows remain labeled incomplete remediation, not direct root.

Every accepted contributor row is narrowed to the AI-authored material delta. Shared SHAs were compared by GHSA identity, path, source, sink, invariant, and reversal. The shared OpenClaw, Prompty, GitPython, and ha-mcp SHAs therefore do not collapse distinct mechanisms. No candidate GHSA identity or mechanism key duplicates another final row, and no CVE alias is counted.

Affected/fixed release containment was evaluated existentially within the advisory range. Ordinal 211 therefore passes with real vulnerable release `v1.1.0` and fixed release `v1.2.0`; a nonexistent or unavailable `v1.0.0` artifact is not required. Conversely, ancestry, release routing, an advisory commit reference, or an AI-marked fix was never promoted into causal evidence.

Independent-review freshness is bound to the current contract and current input hashes at `2026-08-13T22:03:11Z`. Earlier hypotheses are counterevidence, not authority. Explicit superseded-edge handling is recorded for all four upgrade-A third-review rows, ordinal 211's release correction, `GHSA-W28W-GP39-M4P6`'s minimum-fix-member edge, and ordinal 148's final identity narrowing.

## Ordinal 148: NARROW

`GHSA-4FXP-2M36-QV64` closes AI hunk, topology, patch-delta but-for, fix reversal, release containment, and uniqueness, but it does not close `identity_gate`. The frozen repository advisory object is a 404. The frozen global GHSA is `unreviewed`, has an empty `vulnerabilities` array, and has no repository or source-code-location object. The matching first-party commit and GitHub releases prove code and release facts, but under the contract they do not substitute for a first-party GHSA object naming the affected repository, mechanism, and public identity. The worker KEEP is therefore superseded by final NARROW; no replacement identity is inferred.

## Terminal PARTIAL boundary

`autoresearch/herdr-260813-ghsa200-commitfirst-gn/` was terminal at freeze with status PARTIAL: 101 reviewed rows, 2 PASS proposals, 93 REJECT, 4 UNKNOWN, 2 BLOCKED, source `countable_pass=0`, and 2,476 explicitly unreviewed rows. This review independently accepts only the two proposed identities, `GHSA-G39V-CVJH-8FPF` and `GHSA-PF93-J98V-25PV`, after replaying their exact candidate/carrier/fix and vulnerable/fixed release edges. The 93/4/2 source nonpositive rows and 2,476 unreviewed rows are preserved as packet coverage accounting, not silently converted into final-candidate verdicts.

## Countable first-party GHSA list (31)

1. `GHSA-3RP5-JJMW-4WV2`
2. `GHSA-3WXW-XV34-2FRG`
3. `GHSA-539M-9XH6-Q6RR`
4. `GHSA-56C3-VFP2-5QQJ`
5. `GHSA-5C6W-WWFQ-7QQM`
6. `GHSA-5RV5-XJ5J-3484`
7. `GHSA-5XXX-QHH7-9287`
8. `GHSA-7C3W-FXGH-FRC7`
9. `GHSA-7P8R-X3MC-P8W7`
10. `GHSA-8JPQ-5H99-FF5R`
11. `GHSA-8WC8-HF36-MJH9`
12. `GHSA-FMFG-9G7C-3VQ7`
13. `GHSA-G39V-CVJH-8FPF`
14. `GHSA-J4XF-96QF-RX69`
15. `GHSA-JM78-9FVV-MHGR`
16. `GHSA-JV46-XFWM-36J7`
17. `GHSA-M4WX-M65X-GHRR`
18. `GHSA-MF5G-6R6F-GHHM`
19. `GHSA-MV93-W799-CJ2W`
20. `GHSA-PF93-J98V-25PV`
21. `GHSA-PWF7-47C3-MFHX`
22. `GHSA-R48C-V28R-PF6V`
23. `GHSA-R9MR-M37C-5FR3`
24. `GHSA-RG8M-3943-VM6Q`
25. `GHSA-RQP8-Q22P-5J9Q`
26. `GHSA-VC8F-X9PP-WF5P`
27. `GHSA-W28W-GP39-M4P6`
28. `GHSA-WPXJ-VHFP-HHVM`
29. `GHSA-WV46-V6XC-2QHF`
30. `GHSA-WXHM-2MQ7-7697`
31. `GHSA-XW8C-RRVX-F7XQ`

**Exact final counts: ACCEPT 31; NARROW 1; REJECT 0; UNKNOWN 0; BLOCKED 0.**
