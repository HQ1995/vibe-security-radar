# Wave-2 marker triage (AI-hunk and topology only)

Verdict first: this packet is a bounded AI-hunk and topology screen, not final admission.
Worker PASS is a shortlist proposal only. Canonical ledger was not edited.
No case-count claim is made.

## Conservation

- Assigned: 26
- Reviewed: 26
- Unreviewed: 0
- shortlist PASS: 0
- rejected decisive mismatch: 3
- unknown missing evidence: 23
- Equation: 26=0+3+23
- Holds: true
- Did not pad, drop, or invent rows.

## Method

s5 result.json and cases.jsonl were routing only (repository, fix SHAs, shared clone paths).
Owned temporary clones used git object alternates to shared routing clones and fetched missing SHAs only into the owned directory. GitHub REST API was not used.
Deleted source hunks at each named fix parent were blamed.
PASS requires a recognized AI author or trailer on the atomic commit that owns the advisory mechanism hunk.
Generic PR or squash carrier branding, including Copilot trailers on GitHub squash subjects, does not transfer to human members.
Missing objects, empty deletions, or incomplete blame stay UNKNOWN.
Successful blame with no recognized AI marker on the hunk owner is REJECT.
Other gates were not closed. This is not countable admission.

## Rows

1. GHSA-FJGC-3MJ7-8RG8 ether/etherpad: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=e58dfa475297
2. GHSA-JWJP-4649-V8JP sipsorcery-org/sipsorcery: UNKNOWN (mechanism_path_not_in_blamed_deleted_hunks); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
3. GHSA-9HJ4-R449-HFVC ruby/json: UNKNOWN (no_same_repo_fix_refs); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
4. GHSA-X677-9FXG-V5C5 traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
5. GHSA-CXJQ-MRR5-89RV traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
6. GHSA-8RXV-JG7P-WVG3 traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
7. GHSA-6P8F-P8J2-RQMV traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
8. GHSA-62FC-8686-HFMQ traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
9. GHSA-3Q9R-P662-5J8M traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
10. GHSA-FGJJ-PX3W-67XX traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
11. GHSA-6765-C87H-8MRF traefik/traefik: REJECT (mechanism_hunk_human_atomic_no_ai_marker); ai_hunk=FAIL topology=PASS; cand=none; carrier=none
12. GHSA-3CCP-42PG-HGV6 traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
13. GHSA-42CJ-M3VJ-89WV traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
14. GHSA-QQ9Q-X9W4-CHHJ traefik/traefik: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
15. GHSA-5XVG-PMGG-3MXR FlowiseAI/Flowise: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
16. GHSA-8GJ2-2CVC-6XX7 FlowiseAI/Flowise: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
17. GHSA-RWRP-9823-P2XQ FlowiseAI/Flowise: UNKNOWN (no_same_repo_fix_refs); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
18. GHSA-CHM3-VQCF-52RX FlowiseAI/Flowise: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
19. GHSA-4J8X-X6V7-W9RQ FlowiseAI/Flowise: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
20. GHSA-52FH-8V99-63C2 FlowiseAI/Flowise: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
21. GHSA-X3HF-7CJ6-3R4M FlowiseAI/Flowise: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
22. GHSA-6VH2-WG4H-4VWJ FlowiseAI/Flowise: REJECT (mechanism_hunk_human_atomic_no_ai_marker); ai_hunk=FAIL topology=PASS; cand=none; carrier=none
23. GHSA-X6VM-W76M-8J7G FlowiseAI/Flowise: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
24. GHSA-VMV7-4M6C-3CG5 FlowiseAI/Flowise: UNKNOWN (incomplete_blame_or_missing_objects); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none
25. GHSA-WG86-R78F-74MP FlowiseAI/Flowise: REJECT (mechanism_hunk_human_atomic_no_ai_marker); ai_hunk=FAIL topology=PASS; cand=none; carrier=none
26. GHSA-G32J-MMXR-GFQ5 FlowiseAI/Flowise: UNKNOWN (no_same_repo_fix_refs); ai_hunk=UNKNOWN topology=UNKNOWN; cand=none; carrier=none

## Commands

```
python3 /home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-marker-triage-grok46-low/work/screen_ai_hunk.py
```

Temporary clones lived under work/tmp-clones and were deleted after emit.

## Claim boundary

- Did not edit the ledger.
- Did not claim any canonical case count.
- Publication status remains HOLD.
- Started: 2026-08-14T19:20:37.773676+00:00
- Ended: 2026-08-14T19:20:44.758854+00:00
- Input delta-term-1.jsonl sha256: ec0428a7aa1ac35bd0b8a7e3f835678178243b9c82ec98ca3d51050092b1d998
- Input s5 result.json sha256: 93812f2a8c2e68509b9e8a9c8f593fc4f54374839c17947fab208a9499ebe3d6
