# CF4 bucket-2 incomplete-remediation discovery

Verdict first: TERMINAL. PASS_PROPOSAL = 0. Countable PASS = 0.
Assigned 12. Reviewed 12. Unreviewed remainder 0. Equation 12=12+0 holds.
Canonical88 stays 88. Publication and more-than-200 remain HOLD.

## Universe

GitHub-reviewed from /home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database HEAD f2c6ab3202aeafb36fbea6e76d892532acfca1a6 (34389 files).
Unreviewed subtree only from /home/hanqing/.cache/cve-analyzer/advisory-database HEAD 39d8887723797efc1804585dd06585c9fd751226 (317316 files).
Union by uppercase GHSA ID; reviewed f2c6 wins on 23 bucket-2 collisions. Unreviewed cases were not dropped.

Owned bucket: int(sha256(uppercase GHSA ID),16) mod 6 = 2.
Active union bucket-2: 5702 + 52721 - 23 = 58400.
Prior structured terminal exclusions (case_id, ghsa_id, reviewed_case_ids, assigned_ids, strict_released_case_ids only): 11130.
First-party unassigned union after exclusion: 4048.
Probe pool (IR language or 2025-05+ with fix SHA): 308. Frozen the 12 strongest with git objects; no shortfall.

## Method

Priority: AI security or validation commits that attempted a guard whose residual the GHSA closer later closed.
Then other strong causal in-bucket rather than padding old IR-language rows with no AI hunk.
Local caches read-only. No GitHub REST. No credentials. No durable clones in the owned directory.

## Per case

1. GHSA-VP55-5C2V-3597 REJECT. Cursor harden on labels.py is not amended by listed closer 846568c7 (issue-ref + workflows). 0 tags.
2. GHSA-V626-428R-43P8 REJECT. Real ZIP declared-size residual after 2.0.1, closed in 2.0.2, but both SHAs are human Andy Miller. Unreviewed object is cross-bound to GHSA-8h9x.
3. GHSA-H2V8-4C3F-VQGV UNKNOWN. Claude origin e08547bc introduced exec URL interpolation; Claude closer 1e66c78c switches to spawn. Megapatch origin plus 0 tags. Other-causal, not IR. release_gate UNKNOWN.
4. GHSA-R3V6-QW6X-WF6H REJECT. Claude DPT-2..6 are the listed closers (AI-on-fix). DPT-1 is a sibling deleteSelection hole. v2.5.41 vs v2.5.42 is real release evidence and still not origin.
5. GHSA-3VHV-JX5J-GJ6P REJECT. Closer is Claude DPT-1 itself.
6. GHSA-X9X8-26MR-9WMM REJECT. Claude mass-assignment ancestor is a sibling AttributesController write path.
7. GHSA-9CQ9-W9QM-WC9P REJECT. Copilot abort-multipart residual is not DeleteObjects ../ traversal. Tags 4.33/4.34 prove release of a different mechanism.
8. GHSA-Q65P-7P84-495C REJECT. Cursor overlap is claude.yml; closer is workflow fork detection; GHSA is SQL dimension injection.
9. GHSA-226M-2JQQ-4XGV REJECT. Copilot ancestor names GHSA-7w46 cycle detection; closer is Conv shape inference.
10. GHSA-52VJ-FVRV-7Q82 REJECT. Unmarked SSRF closer in web-fetch.ts; AI ancestor overlaps CHANGELOG.md only. v2026.1.24 vs v2026.1.29.
11. GHSA-VQWP-45WM-R9R5 REJECT. Cursor marker is on the closer. AI-on-fix. 0 tags.
12. GHSA-MV8X-FG99-32MF REJECT. Unmarked .env sanitizer closer; AI tool validation is a different path. 0 tags.

## Conservation

frozen=12 reviewed=12 unreviewed=0 PASS_proposal=0
Worker PASS is proposal only. This packet proposes none.
