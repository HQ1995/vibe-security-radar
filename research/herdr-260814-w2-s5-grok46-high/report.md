# Wave-2 delta-term-1 kind-2 adjudication (grok-4.6 high)

Verdict first: reviewed 26/26. CONFIRM 0, NARROW 0, FALSE_POSITIVE 0, UNKNOWN 26. terminal_true=0 terminal_false=26. Worker PASS/CONFIRM is proposal only. Canonical ledger was not edited. Publication and greater-than-200 stay HOLD.

## Method

Kind-2 advisory-blob rows. Local first-party GHSA objects from the frozen advisory-database clone, then same-repo fix commits, then rename-following blame of deleted source hunks at the fix parent, then an explicit AI marker on the blamed commit. GitHub API was not used. Missing evidence stays UNKNOWN and is not converted into FAIL/FALSE_POSITIVE. History walk stops at 2000 commits / named fix refs.

## Per-gate failures

1. GHSA-FJGC-3MJ7-8RG8 ether/etherpad: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/ether__etherpad; fixes=451bd9c3ebb0dded99dd0ff21811ee00e0940c29,63e9b2d4eb303cd341022591bdf9484584db36e3; AI=none
2. GHSA-JWJP-4649-V8JP sipsorcery-org/sipsorcery: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/sipsorcery-org__sipsorcery; fixes=a2466550bb2a28821c73fb1961bc33dcc467f8cf; AI=none
3. GHSA-9HJ4-R449-HFVC ruby/json: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/ruby__json; fixes=none; AI=none
4. GHSA-X677-9FXG-V5C5 traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=108a5264473a2cbc8f12d6d691a3c6553cdf2c1b; AI=none
5. GHSA-CXJQ-MRR5-89RV traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=3f10dd442479530560f010167cac2947676d9b29; AI=none
6. GHSA-8RXV-JG7P-WVG3 traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=759515bec1b9f628b21ea8968ef63da853be5e29; AI=none
7. GHSA-6P8F-P8J2-RQMV traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=8aada7a7d52e4588a75386d8b86d270f6fe8d549; AI=none
8. GHSA-62FC-8686-HFMQ traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=65ebf4b47fbdc33e3856803a5844a404e094d52d; AI=none
9. GHSA-3Q9R-P662-5J8M traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=7ae92d8c2c10ac04ef5a03df0ed5019ce0f44b2d; AI=none
10. GHSA-FGJJ-PX3W-67XX traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=a764166656f0cd337f917ac76315c381cca844f9; AI=none
11. GHSA-6765-C87H-8MRF traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=b5ace8eb5d6779980567f5e75efd2d9e08b7e350; AI=none
12. GHSA-3CCP-42PG-HGV6 traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=04d36f28e4eae7535e96a6351dd9f7bfb48a30e7,0807b6d5dd1da8b2f7f4076ea2392b5437bf2ab0,94a7508817d180f0ab2f1eae93df48d4ab19ecce; AI=none
13. GHSA-42CJ-M3VJ-89WV traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=67501cbe7bc7774e26ecbd1c29af97f098e14b0b; AI=none
14. GHSA-QQ9Q-X9W4-CHHJ traefik/traefik: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/traefik__traefik; fixes=655d6324ab4a1475892a958d4bae389720a67ea9; AI=none
15. GHSA-5XVG-PMGG-3MXR FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=f4e2794f6a576b94578f2fdafbf49c2fb304626c; AI=none
16. GHSA-8GJ2-2CVC-6XX7 FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=dbec8f9fd3c42faab49416fe81ff1774a5344cba; AI=none
17. GHSA-RWRP-9823-P2XQ FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=none; AI=none
18. GHSA-CHM3-VQCF-52RX FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=d81483b70c997ddf981acc9c49fbd9a02fa345cd; AI=none
19. GHSA-4J8X-X6V7-W9RQ FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=f4e2794f6a576b94578f2fdafbf49c2fb304626c; AI=none
20. GHSA-52FH-8V99-63C2 FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=f4e2794f6a576b94578f2fdafbf49c2fb304626c; AI=none
21. GHSA-X3HF-7CJ6-3R4M FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=d07186844263bad057008863037466aff7c3390f; AI=none
22. GHSA-6VH2-WG4H-4VWJ FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=23b997ee5ef9e269b628bad0f56f1ecb86bd2fca; AI=none
23. GHSA-X6VM-W76M-8J7G FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=c79fe56a6c249850e96bce9b4859f7a0083e4507; AI=none
24. GHSA-VMV7-4M6C-3CG5 FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=f4e2794f6a576b94578f2fdafbf49c2fb304626c; AI=none
25. GHSA-WG86-R78F-74MP FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=3f257bdc8196082a178da7134a075824401b13b9; AI=none
26. GHSA-G32J-MMXR-GFQ5 FlowiseAI/Flowise: UNKNOWN (LOW, UNRESOLVED; failing=none; open=ai_hunk_gate,topology_gate,but_for_gate,fix_reversal_gate,release_gate). clone=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/FlowiseAI__Flowise; fixes=none; AI=none

## Evidence paths

- Slice: autoresearch/orchestrator-260814-ghsa200-canvas/wave2/delta-term-1.jsonl
- Advisories: /home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database
- Local clones: commit-af/repos, commit-gn/clones, commit-oz/repos, current-delta/repos
- Contract: autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md

## Disagreement with stored labels

No stored seven-gate labels were treated as evidence. Slice collisions are sibling-alias notes only.

