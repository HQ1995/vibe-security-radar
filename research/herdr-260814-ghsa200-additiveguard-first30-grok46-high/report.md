# Additive-guard first30 mining packet: 0 hard-hit proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **0**. This is a mining/selection packet. The bounded additive-guard heuristic found **0 hard-hit proposals** among the 30 assigned rows. That is not a finding that those 30 have no AI origin. A hard-prefilter miss is **NOT_SELECTED**, not causal REJECT. Seven gates were **NOT_OPENED**. Fetch/history failure would be BLOCKED; this scan had none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false. Do not start the next additive slice until leader accepts this packet.

## Conservation

Raw unique `no_source_deleted` and no `diff_fail` pool: **381**.
Excluded / already-covered: **285**.
Eligible: **96**.
Assigned (scan_assigned): **30**.
Eligible leftover: **66**.
Raw outside this assignment: **351**.
Equations: 381=285+96; 96=30+66; 381=30+351.
Did not pad. Did not backfill. Did not exhaust leftover 66 or the 351 outside assignment.

## Method

Assigned first 30 genuinely unassigned rows in original scan-miss order after canonical84 and explicit terminal/current selected/cases snapshot. For each exact first-party fix, the bounded heuristic parsed added source hunks and unchanged parent context, then `git blame` / `git log -L` that window. Absence of deleted lines is not a negative. A freeze required an explicit AI-marked atomic origin or mapped squash member plus the remaining hard-hit bars. Freeze cap is the first 20 hard-hit proposals. First-party advisory summary and aliases were loaded during `scan_additive.py`. Empty aliases do not fail identity; identity was not opened.

## Scan assignment

Raw outcomes stay in `work/scan.jsonl`. Cases rows are scan-assignment records, not seven-gate adjudications.

| n | ID | Repository | Heuristic |
| --- | --- | --- | --- |
| 1 | GHSA-X958-RVG6-956W | matrix-org/matrix-rust-sdk | heuristic_no_hard_hit |
| 2 | GHSA-VHGQ-R8GX-5FPV | ibexa/admin-ui-assets | heuristic_no_hard_hit |
| 3 | GHSA-X3C7-22C8-PRG7 | handcraftedinthealps/goodby-csv | heuristic_no_hard_hit |
| 4 | GHSA-3GGV-QWCP-J6XG | mautic/mautic | heuristic_no_hard_hit |
| 5 | GHSA-438M-6MHW-HQ5W | mautic/mautic | heuristic_no_hard_hit |
| 6 | GHSA-QJ3P-XC97-XW74 | MetaMask/metamask-sdk | heuristic_no_hard_hit |
| 7 | GHSA-QHJ8-Q5R6-8Q6J | matrix-org/matrix-rust-sdk | heuristic_no_hard_hit |
| 8 | GHSA-6PVW-G552-53C5 | git-lfs/git-lfs | heuristic_no_hard_hit |
| 9 | GHSA-M732-5P4W-X69G | honojs/hono | heuristic_no_hard_hit |
| 10 | GHSA-JQ43-27X9-3V86 | netty/netty | heuristic_no_hard_hit |
| 11 | GHSA-7P73-8JQX-23R8 | langchain-ai/langgraph | heuristic_no_hard_hit |
| 12 | GHSA-4CWQ-J7JV-QMWG | getgrav/grav | heuristic_no_hard_hit |
| 13 | GHSA-4JJ9-CGQC-X9H5 | neuvector/neuvector | heuristic_no_hard_hit |
| 14 | GHSA-6H2F-WJHF-4WJX | Mayuri-Chan/pyrofork | heuristic_no_hard_hit |
| 15 | GHSA-4HX9-48XH-5MXR | keycloak/keycloak | heuristic_no_hard_hit |
| 16 | GHSA-M95P-425X-X889 | LFDT-Lockness/cggmp21 | heuristic_no_hard_hit |
| 17 | GHSA-2R4R-5X78-MVQF | kubevirt/kubevirt | heuristic_no_hard_hit |
| 18 | GHSA-RJ4J-2JPH-GG43 | lf-edge/ekuiper | heuristic_no_hard_hit |
| 19 | GHSA-5J98-MCP5-4VW2 | isaacs/node-glob | heuristic_no_hard_hit |
| 20 | GHSA-G582-8VWR-68H2 | mantisbt/mantisbt | heuristic_no_hard_hit |
| 21 | GHSA-9CWV-PXCR-HFJC | lf-edge/ekuiper | heuristic_no_hard_hit |
| 22 | GHSA-F238-RGGP-82M3 | navidrome/navidrome | heuristic_no_hard_hit |
| 23 | GHSA-CXRH-J4JR-QWG3 | nodejs/undici | heuristic_no_hard_hit |
| 24 | GHSA-24CH-W38V-XMH8 | juju/juju | heuristic_no_hard_hit |
| 25 | GHSA-X4RX-4GW3-53P4 | moby/moby | heuristic_no_hard_hit |
| 26 | GHSA-557J-XG8C-Q2MM | helm/helm | heuristic_no_hard_hit |
| 27 | GHSA-FM6C-F59H-7MMG | modelscope/ms-swift | heuristic_no_hard_hit |
| 28 | GHSA-3VG9-H568-4W9M | mmaitre314/picklescan | heuristic_no_hard_hit |
| 29 | GHSA-F54Q-57X4-JG88 | mmaitre314/picklescan | heuristic_no_hard_hit |
| 30 | GHSA-9GVJ-PP9X-GCFR | mmaitre314/picklescan | heuristic_no_hard_hit |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim.
