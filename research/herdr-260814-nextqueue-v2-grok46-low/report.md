# GHSA-200 next-queue v2 (canonical91, no duplication)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical91 stays 91 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none.

## Freeze

First-party github-reviewed tree HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` from read-only cache `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. Reviewed JSON identities: 34389.
Shared caches were read-only. No clone was retained. Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.

## Inventory (recomputed; not reused from prose)

Terminal herdr/orchestrator 260813-260814 cases/adjudication/result artifacts parsed: files=584 cases.jsonl=267 adjudication=34 result.json=283 rows=12504. Distinct identities with an explicit terminal verdict field: 7932. Skipped work/notes/pages/snapshot/clones/cache/tmp. Shared SHA is not identity dedupe. Mechanism fingerprint occupied-set was exact `repo|cwes|package` keys from those rows plus canonical91 ledger mechanism_key values.

## Conservation

reviewed 34389 = withdrawn 910 + no_repository 4053 + no_same_repo_fix 10631 + outside_coverage_window(before 2025-05-01) 9533 + terminal_verdict 7692 + no_first_party_repo_advisory 691 + canonical91_in_reviewed 76 + structural 803.
Check: 34389 = 34389. Holds.
structural 803 = no_local_clone 5 + fix_object_missing 38 + no_pre_fix_ai_marker 729 + ai_hit 31.
Check: 803 = 803. Holds.
ai_hit 31 = queued 20 + leftover 11. Holds.
assigned 20 = reviewed_gates 0 + unreviewed_routing 20. Equation 20=0+20. Holds. Did not pad.
Canonical91 strict count remains 91. Subtracted as the canonical bucket among reviewed identities: 76. The other 15 strict IDs are not in this reviewed-identity walk at the canonical bucket (absent from github-reviewed JSON identities at this HEAD, or classified withdrawn before that bucket).

## Exclusions (not queued)

- Canonical91 strict identities (91).
- Any identity with a terminal verdict in cases/adjudication/result (7932 distinct).
- Withdrawn, no GitHub repository, no exact same-repo 40-hex commit reference, published before 2025-05-01, no matching first-party repo-advisory URL, no local clone, missing fix object, or no source_matcher pre-fix hit on fix-touched history.
- AI marker on the closer itself is not a pre-fix candidate.
- CVE aliases are not counted.
- Leftover AI-hit identities not in the cap-20 rank: GHSA-R54C-2XMF-2CF3, GHSA-V5MV-P594-2X33, GHSA-V95X-XHQ5-4929, GHSA-WVMP-6R4V-J6CV, GHSA-375F-4R2H-F99J, GHSA-9Q9Q-324X-93R2, GHSA-FRH3-6PV6-RC8J, GHSA-PF94-94M9-536P, GHSA-Q6V9-R226-V65F, GHSA-RF5Q-VWXW-GMRF, GHSA-V56Q-MH7H-F735.

## Next queue (20, nonoverlapping, rank-capped)

Order: first-party repo-advisory, then more pre-fix matcher hits, then code-file overlap, then published date, then case_id.
01. GHSA-3GGV-QWCP-J6XG repo=mautic/mautic fp=mautic/mautic|CWE-204|mautic/core fix=6bc4f5f1aabb ai_n=8 tools=claude_code,github_copilot pub=2025-09-03
02. GHSA-438M-6MHW-HQ5W repo=mautic/mautic fp=mautic/mautic|CWE-283|mautic/core fix=882c2c5be646 ai_n=8 tools=claude_code,github_copilot pub=2025-09-03
03. GHSA-7P93-6934-F4Q7 repo=nicolargo/glances fp=nicolargo/glances|CWE-942|glances fix=dcb39c3f12b2 ai_n=8 tools=claude_code,github_copilot pub=2026-03-30
04. GHSA-G6W2-Q45F-XRP4 repo=NeoRazorX/facturascripts fp=neorazorx/facturascripts|CWE-79|facturascripts/facturascripts fix=2afd98cecd26 ai_n=8 tools=claude_code,github_copilot pub=2026-02-02
05. GHSA-HJ6F-7HP7-XG69 repo=mautic/mautic fp=mautic/mautic|CWE-918|mautic/core fix=6084f6de4c88 ai_n=8 tools=claude_code,github_copilot pub=2025-09-03
06. GHSA-WWJ6-VGHV-5P64 repo=kata-containers/kata-containers fp=kata-containers/kata-containers|CWE-281,CWE-732|github.com/kata-containers/kata-containers/src/runtime fix=6a672503973b ai_n=8 tools=claude_code,cursor,github_copilot pub=2026-02-19
07. GHSA-X744-4WPC-V9H2 repo=moby/moby fp=moby/moby|CWE-288,CWE-863|github.com/moby/moby fix=e89edb19ad7d ai_n=8 tools=claude_code,github_copilot pub=2026-03-27
08. GHSA-34P4-7W83-35G2 repo=getformwork/formwork fp=getformwork/formwork|CWE-269|getformwork/formwork fix=19390a0b408e ai_n=6 tools=github_copilot pub=2026-02-19
09. GHSA-396Q-4VC8-28X9 repo=microsoft/kiota-typescript fp=microsoft/kiota-typescript|CWE-178,CWE-200|@microsoft/kiota-http-fetchlibrary fix=09f8bd9b34d6 ai_n=4 tools=github_copilot pub=2026-06-26
10. GHSA-7J46-F57W-76PJ repo=getformwork/formwork fp=getformwork/formwork|CWE-79|getformwork/formwork fix=4abcd60ae769 ai_n=4 tools=github_copilot pub=2025-11-24
11. GHSA-GJX9-J8F8-7J74 repo=HubSpot/jinjava fp=hubspot/jinjava|CWE-1336|com.hubspot.jinjava:jinjava fix=3d02e504d8bb ai_n=4 tools=claude_code pub=2026-02-03
12. GHSA-QHJ8-Q5R6-8Q6J repo=matrix-org/matrix-rust-sdk fp=matrix-org/matrix-rust-sdk|CWE-682|matrix-sdk-base fix=ce3b67f80144 ai_n=3 tools=github_copilot pub=2025-09-11
13. GHSA-R4WM-X892-VJMX repo=nestjs/nest fp=nestjs/nest|CWE-863|@nestjs/platform-fastify fix=fd8d073e0e04 ai_n=3 tools=github_copilot pub=2026-03-02
14. GHSA-8GWM-58G9-J8PW repo=mermaid-js/mermaid fp=mermaid-js/mermaid|CWE-79|mermaid fix=2aa833027951 ai_n=2 tools=claude_code,github_copilot pub=2025-08-19
15. GHSA-VCV2-Q258-WRG7 repo=nicolargo/glances fp=nicolargo/glances|CWE-78|glances fix=6f4ec53d9674 ai_n=2 tools=claude_code,github_copilot pub=2026-03-16
16. GHSA-VX5F-957P-QPVM repo=nicolargo/glances fp=nicolargo/glances|CWE-346,CWE-522|glances fix=61d38eec5217 ai_n=2 tools=claude_code,github_copilot pub=2026-03-16
17. GHSA-2V6M-6XW3-6467 repo=fleetdm/fleet fp=fleetdm/fleet|CWE-200,CWE-201|github.com/fleetdm/fleet/v4 fix=23fc6804efe7 ai_n=1 tools=claude_code pub=2026-02-26
18. GHSA-3VCP-CHFH-F6R2 repo=kumahq/kuma fp=kumahq/kuma|CWE-346,CWE-942|github.com/kumahq/kuma fix=8fefa8595d44 ai_n=1 tools=github_copilot pub=2026-05-14
19. GHSA-F7VP-7XGX-4W4R repo=guzzle/guzzle fp=guzzle/guzzle|CWE-180,CWE-346,CWE-384|guzzlehttp/guzzle fix=3aeea0406aab ai_n=1 tools=claude_code pub=2026-08-03
20. GHSA-HRXH-6V49-42GF repo=grpc/grpc-go fp=grpc/grpc-go|CWE-248,CWE-770,CWE-863|google.golang.org/grpc fix=4ea465d4ab98 ai_n=1 tools=google_gemini pub=2026-07-21

Stop. No ledger, site, or other-directory edits. No retained clone or advisory fetch. No PASS.
