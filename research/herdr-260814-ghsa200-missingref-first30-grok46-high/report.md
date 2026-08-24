# Missing-ref first30 mining packet: 0 hard-hit proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **0**. This is a mining/selection packet. Independent analysis of the exact first-party fix found **0 hard-hit proposals** among the 30 assigned rows. That is not a finding that those 30 have no AI origin. A hard-prefilter miss is **NOT_SELECTED**, not causal REJECT. Seven gates were **NOT_OPENED** on nonhits. Fetch/history/evidence failure is **BLOCKED** (1 row: GHSA-W7JW-789Q-3M8P; advisory commit URL 1518179 does not expand to a full first-party SHA). packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false. Do not start the next missing-ref slice until leader accepts this packet.

## Conservation

Raw unique `missing_ref` with neither `diff_fail` nor `no_source_deleted` pool: **141**.
Excluded / already-covered: **98**.
Eligible: **43**.
Assigned (scan_assigned): **30**.
Eligible leftover: **13**.
Raw outside this assignment: **111**.
Equations: 141=98+43; 43=30+13; 141=30+111.
Did not pad. Did not backfill. Did not exhaust leftover 13 or the 111 outside assignment.

## Method

Assigned first 30 genuinely unassigned rows in original scan-miss order after canonical84 and explicit terminal/current selected/cases snapshot. The missing_ref note prefix is routing only. Exact full first-party fix SHAs were resolved from advisory commit URLs, GIT fixed events, and PRs, then cloned or fetched into `/tmp/ghsa200-missingref-first30`. Deleted or replaced source lines were blamed; additive fixes traced the protected parent sink, route, or context. A freeze required an atomic explicit AI hunk or mapped member, correct carrier topology, candidate before the fix and present in an affected release, same-mechanism fix reversal, candidate-parent but-for, and uniqueness. PR squash trailer transfer, later descendant member, old bug/refactor, unrelated path, remediation-as-origin, and shallow boundary fail closed. Freeze cap is the first 20 hard-hit proposals. First-party advisory summary and aliases were loaded during `scan_missingref.py`. Empty aliases do not fail identity; identity was not opened.

## Scan assignment

Raw outcomes stay in `work/scan.jsonl`. Cases rows are scan-assignment records, not seven-gate adjudications.

| n | ID | Repository | Heuristic |
| --- | --- | --- | --- |
| 1 | GHSA-FRC6-PWGR-C28W | librenms/librenms | heuristic_no_hard_hit |
| 2 | GHSA-6G2V-66CH-6XMH | librenms/librenms | heuristic_no_hard_hit |
| 3 | GHSA-3HW7-QJ9H-R835 | gardener/gardener | heuristic_no_hard_hit |
| 4 | GHSA-W7JW-789Q-3M8P | ljharb/shell-quote | UNKNOWN |
| 5 | GHSA-FHP4-PR5J-46M5 | julianhille/MuhammaraJS | heuristic_no_hard_hit |
| 6 | GHSA-VC34-39Q2-M6Q3 | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 7 | GHSA-48M6-486P-9J8P | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 8 | GHSA-FGFV-PV97-6CMJ | go-vikunja/vikunja | heuristic_no_hard_hit |
| 9 | GHSA-48CH-P4GQ-X46X | go-vikunja/vikunja | heuristic_no_hard_hit |
| 10 | GHSA-7C4J-2M43-2MGH | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 11 | GHSA-36XV-JGW5-4Q75 | nestjs/nest | heuristic_no_hard_hit |
| 12 | GHSA-PF4J-PF3W-95F9 | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 13 | GHSA-J99G-7RQW-Q9JG | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 14 | GHSA-264V-M8FM-76JM | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 15 | GHSA-79QW-G77V-2VFH | inspektor-gadget/inspektor-gadget | heuristic_no_hard_hit |
| 16 | GHSA-V479-VF79-MG83 | go-vikunja/vikunja | heuristic_no_hard_hit |
| 17 | GHSA-9GCG-W975-3RJH | istio/istio | heuristic_no_hard_hit |
| 18 | GHSA-6973-8887-87FF | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 19 | GHSA-8JVC-MCX6-R4CG | go-vikunja/vikunja | heuristic_no_hard_hit |
| 20 | GHSA-2VQ4-854F-5C72 | go-vikunja/vikunja | heuristic_no_hard_hit |
| 21 | GHSA-HJ5C-MHH2-G7JQ | go-vikunja/vikunja | heuristic_no_hard_hit |
| 22 | GHSA-96Q5-XM3P-7M84 | go-vikunja/vikunja | heuristic_no_hard_hit |
| 23 | GHSA-H9CC-W26M-J342 | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 24 | GHSA-VGHX-352F-93JM | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 25 | GHSA-799F-29JM-GR6C | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 26 | GHSA-27W2-87XV-37C6 | nimiq/core-rs-albatross | heuristic_no_hard_hit |
| 27 | GHSA-Q49M-57VM-C8CC | kata-containers/kata-containers | heuristic_no_hard_hit |
| 28 | GHSA-RR59-XXVX-96QR | kata-containers/kata-containers | heuristic_no_hard_hit |
| 29 | GHSA-C3M2-JQMQ-PVP3 | goauthentik/authentik | heuristic_no_hard_hit |
| 30 | GHSA-QRPW-GJVH-X5GM | nautobot/nautobot | heuristic_no_hard_hit |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim.
