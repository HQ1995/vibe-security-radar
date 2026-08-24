# Canonical84 source-tier identity QA

Verdict first: packet_status is PARTIAL. Canonical strict count remains 84 at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Canonical84 source-tier status is HOLD pending leader action. This packet does not admit cases, mutate canonical84, or support a greater-than-200 claim.

Conservation: counted rows 84. PASS 1. FAIL 0. UNKNOWN 20. BLOCKED 63. First-party repo advisory HTTP 200: 19. HTTP 404: 2. Rate-limited unfetched: 63. Negative controls 1 and out of count.

A GitHub advisory-database, OSV, or global advisory JSON object is routing only. First-party claim evidence is the repository security advisory API object for the same GHSA ID. Shared fix SHAs do not merge identities. Prior PASS labels are not inherited. Missing or rate-limited content is UNKNOWN or BLOCKED, not PASS.

Literal named-fix SHA inequality versus canonical minimum_fix_set is not a topology FAIL. Those rows are UNKNOWN with exact_fix_topology_unresolved unless ancestor, member, or blob-equivalent closure and a mechanism mismatch are proved. Source-tier QA does not infer a topology FAIL from SHA inequality.

Negative control GHSA-47Q7-97XP-M272 is out of count. Current advisory-database JSON has a config-write summary and hook-token details/fix; this packet detects that as routing-object inconsistency. Newcaller20 facts are a pinned secondary artifact for this overlapping ID only; those verdicts are not trusted.

## PASS counted rows

- GHSA-4564-PVR2-QQ4H

## Non-PASS counted rows

- GHSA-243V-5F97-VFQ3 UNKNOWN MISSING_REPO_ADVISORY github_repo_advisory_api_http_404
- GHSA-2GFJ-FR43-4735 UNKNOWN MISSING_REPO_ADVISORY github_repo_advisory_api_http_404
- GHSA-3RP5-JJMW-4WV2 UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-3WXW-XV34-2FRG UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-46Q5-G3J9-WX5C UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-539M-9XH6-Q6RR UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-56C3-VFP2-5QQJ UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-5C6W-WWFQ-7QQM UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-5RV5-XJ5J-3484 UNKNOWN github_repo_security_advisory exact_fix_topology_unresolved,fix_unconfirmed_fail_closed
- GHSA-5XXX-QHH7-9287 UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-68V4-HMWV-F43H UNKNOWN github_repo_security_advisory alias_missing_on_repo_advisory,exact_fix_topology_unresolved,fix_unconfirmed_fail_closed
- GHSA-6MWV-4MRM-5P3M UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-6P9M-Q3JP-47H4 UNKNOWN github_repo_security_advisory vulnerable_range_unconfirmed,fix_unconfirmed_fail_closed
- GHSA-6Q7J-XR26-3H2C UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-76RV-2R9V-C5M6 UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-7F6V-3GX7-27Q8 UNKNOWN github_repo_security_advisory vulnerable_range_unconfirmed,fix_unconfirmed_fail_closed
- GHSA-7GH7-258J-4MPQ UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-7P8R-X3MC-P8W7 UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-83XP-526H-J3WW UNKNOWN github_repo_security_advisory fix_unconfirmed_fail_closed
- GHSA-877V-W3F5-3PCQ BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-8JPQ-5H99-FF5R UNKNOWN github_repo_security_advisory vulnerable_range_unconfirmed,fix_unconfirmed_fail_closed
- GHSA-8WC8-HF36-MJH9 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-97RM-XJ73-33JH BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-9F72-QCPW-2HXC BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-9HFR-GW99-8RHX BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-C4GH-RV8H-Q9VW BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-C4HM-4H84-2CF3 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-C6HR-W26Q-C636 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-CWP8-RM8G-Q5C9 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-FMFG-9G7C-3VQ7 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-FPMV-5WGW-QHHR BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-FVVP-RJ8G-C7GC BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-G39V-CVJH-8FPF BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-G3XQ-3GMV-QQ8G BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-G8P2-7WF7-98MQ BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-GH4H-34GR-87R7 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-GW85-XP4Q-5GP9 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-HC36-C89J-5F4J BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-HM7V-JRHM-FMFX BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-J4XF-96QF-RX69 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-JM78-9FVV-MHGR BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-JV46-XFWM-36J7 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-M4WX-M65X-GHRR BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-MF5G-6R6F-GHHM BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-MV93-W799-CJ2W BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-PF93-J98V-25PV BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-PFVM-W89X-94JW BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-PV2J-RGHR-V5R9 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-PWF7-47C3-MFHX BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-Q6QC-XP4Q-RJQ5 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-Q6RR-FM2G-G5X8 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-Q855-8RH5-JFGQ BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-Q9PG-JJ6X-J9P6 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-QPMQ-6WJC-W28Q BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-R48C-V28R-PF6V BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-R9MR-M37C-5FR3 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-RG8M-3943-VM6Q BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-RQP8-Q22P-5J9Q BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-RV2Q-F2H5-6XMG BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-RV39-79C4-7459 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-VC8F-X9PP-WF5P BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-VCV2-R9JH-99M5 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-VJ3G-5PX3-GR46 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-VVFR-G83F-8QCV BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-VVGP-4C28-M3JM BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-W28W-GP39-M4P6 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-WPXJ-VHFP-HHVM BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-WV46-V6XC-2QHF BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-WXHM-2MQ7-7697 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-X22M-J5QQ-J49M BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-X9QH-W4C4-54F9 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-XW8C-RRVX-F7XQ BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-8882-FRVV-92W4 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-J5QP-P44G-2M49 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-2944-57XV-2682 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-5C7W-4WM3-85VW BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-93Q6-WWJH-JC6H BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-X4HG-HFWF-P9MW BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-322X-V876-G883 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-PMCH-G965-GRMR BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-QF5V-M7P4-95RP BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-425G-FJHQ-5H92 BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited
- GHSA-HC8V-WWC9-VGXM BLOCKED RATE_LIMITED github_repo_advisory_api_rate_limited

## Unfetched or non-200 counted rows

- GHSA-243V-5F97-VFQ3
- GHSA-2GFJ-FR43-4735
- GHSA-877V-W3F5-3PCQ
- GHSA-8WC8-HF36-MJH9
- GHSA-97RM-XJ73-33JH
- GHSA-9F72-QCPW-2HXC
- GHSA-9HFR-GW99-8RHX
- GHSA-C4GH-RV8H-Q9VW
- GHSA-C4HM-4H84-2CF3
- GHSA-C6HR-W26Q-C636
- GHSA-CWP8-RM8G-Q5C9
- GHSA-FMFG-9G7C-3VQ7
- GHSA-FPMV-5WGW-QHHR
- GHSA-FVVP-RJ8G-C7GC
- GHSA-G39V-CVJH-8FPF
- GHSA-G3XQ-3GMV-QQ8G
- GHSA-G8P2-7WF7-98MQ
- GHSA-GH4H-34GR-87R7
- GHSA-GW85-XP4Q-5GP9
- GHSA-HC36-C89J-5F4J
- GHSA-HM7V-JRHM-FMFX
- GHSA-J4XF-96QF-RX69
- GHSA-JM78-9FVV-MHGR
- GHSA-JV46-XFWM-36J7
- GHSA-M4WX-M65X-GHRR
- GHSA-MF5G-6R6F-GHHM
- GHSA-MV93-W799-CJ2W
- GHSA-PF93-J98V-25PV
- GHSA-PFVM-W89X-94JW
- GHSA-PV2J-RGHR-V5R9
- GHSA-PWF7-47C3-MFHX
- GHSA-Q6QC-XP4Q-RJQ5
- GHSA-Q6RR-FM2G-G5X8
- GHSA-Q855-8RH5-JFGQ
- GHSA-Q9PG-JJ6X-J9P6
- GHSA-QPMQ-6WJC-W28Q
- GHSA-R48C-V28R-PF6V
- GHSA-R9MR-M37C-5FR3
- GHSA-RG8M-3943-VM6Q
- GHSA-RQP8-Q22P-5J9Q
- GHSA-RV2Q-F2H5-6XMG
- GHSA-RV39-79C4-7459
- GHSA-VC8F-X9PP-WF5P
- GHSA-VCV2-R9JH-99M5
- GHSA-VJ3G-5PX3-GR46
- GHSA-VVFR-G83F-8QCV
- GHSA-VVGP-4C28-M3JM
- GHSA-W28W-GP39-M4P6
- GHSA-WPXJ-VHFP-HHVM
- GHSA-WV46-V6XC-2QHF
- GHSA-WXHM-2MQ7-7697
- GHSA-X22M-J5QQ-J49M
- GHSA-X9QH-W4C4-54F9
- GHSA-XW8C-RRVX-F7XQ
- GHSA-8882-FRVV-92W4
- GHSA-J5QP-P44G-2M49
- GHSA-2944-57XV-2682
- GHSA-5C7W-4WM3-85VW
- GHSA-93Q6-WWJH-JC6H
- GHSA-X4HG-HFWF-P9MW
- GHSA-322X-V876-G883
- GHSA-PMCH-G965-GRMR
- GHSA-QF5V-M7P4-95RP
- GHSA-425G-FJHQ-5H92
- GHSA-HC8V-WWC9-VGXM

Replay does not re-fetch. Raw pages were hashed then removed from `/tmp/ghsa200-canonical84-sourcetier-qa`.
