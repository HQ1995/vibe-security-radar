# Unreviewed forward-map adjudication: unr-adj-slice-4.jsonl

Verdict-first: **0 countable**. All 25 assigned rows are `FALSE_POSITIVE` (class `wrong_edge`): no candidate AI commit authors the advisory's named vulnerable hunk. No PASS proposals for leader replay.

## Method
- Read each unreviewed advisory JSON from the local advisory-database clone (`advisories/unreviewed/`, `github_reviewed=false`).
- Fetched and read the candidate AI commit diffs via git smart-HTTP into the sweep pool (no GitHub API, no blame/SZZ).
- Compared the advisory's named vulnerable function/file against the candidate commit diffs.
- 24/25 rows are open5gs: both candidates are Co-Authored-By Claude Opus 4.6 PFCP changes in `lib/pfcp/handler.c`; each advisory names a DoS function in a different subsystem.
- 1/25 is publishpress/publishpress-future (Stored XSS): candidates are workflow-editor changes, not the shortcode controller.

## Result

| ord | case_id | repository | verdict | class | vulnerable surface | AI-commit surface |
|---:|---|---|---|---|---|---|
| 1 | GHSA-3HJC-876W-6WXX | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/amf/nudm-handler.c::ogs_id_get_value | lib/pfcp/handler.c |
| 2 | GHSA-677F-37JM-2XG5 | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/amf/nudm-handler.c::amf_nudm_sdm_handle_provisioned | lib/pfcp/handler.c |
| 3 | GHSA-6F86-7RCF-HH89 | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/amf/nsmf-handler.c::amf_nsmf_pdusession_handle_update_sm_context | lib/pfcp/handler.c |
| 4 | GHSA-7338-FR45-62XC | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/amf/gmm-handler.c::gmm_handle_service_request | lib/pfcp/handler.c |
| 5 | GHSA-C646-H573-22RF | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/udr/nudr-handler.c::udr_nudr_dr_handle_subscription_context | lib/pfcp/handler.c |
| 6 | GHSA-R5PF-5MF2-WW5V | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | lib/dbi/subscription.c::ogs_dbi_subscription_data | lib/pfcp/handler.c |
| 7 | GHSA-C78F-M7PG-C3P7 | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/udm/nudr-handler.c::udm_nudr_dr_handle_subscription_authentication | lib/pfcp/handler.c |
| 8 | GHSA-6C8X-4GC8-74GG | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/udm/udm-sm.c::udm_state_operational | lib/pfcp/handler.c |
| 9 | GHSA-J7CF-VFQ9-RHMH | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/udm/nudm-handler.c::udm_nudm_uecm_handle_amf_registration_update | lib/pfcp/handler.c |
| 10 | GHSA-P9XC-CPHQ-3Q9H | publishpress/publishpress-future | FALSE_POSITIVE | wrong_edge | src/Modules/Expirator/Controllers/ShortcodeController.php::[futureaction] wrapper attribute (Stored XSS) | workflow-editor JSX assets + src/Modules/Workflows/* (InteractiveDelay step) + services.php |
| 11 | GHSA-FXH4-4QXC-CQ82 | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | lib/sbi/message.c::ogs_sbi_discovery_option_add_snssais | lib/pfcp/handler.c |
| 12 | GHSA-GHX3-PGMG-H9FC | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | lib/sbi/message.c::ogs_sbi_discovery_option_add_service_names | lib/pfcp/handler.c |
| 13 | GHSA-M782-CQ9R-W5VF | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | lib/sbi/conv.c::ogs_sbi_parse_plmn_list | lib/pfcp/handler.c |
| 14 | GHSA-W88M-GRX2-XWVR | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | lib/sbi/nghttp2-server.c::ogs_sbi_stream_find_by_id | lib/pfcp/handler.c |
| 15 | GHSA-X7C4-PM53-48H6 | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/nssf/nnssf-handler.c::nssf_nnrf_nsselection_handle_get_from_amf_or_vnssf | lib/pfcp/handler.c |
| 16 | GHSA-RR89-WX3J-43CC | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/upf/gtp-path.c::_gtpv1_u_recv_cb | lib/pfcp/handler.c |
| 17 | GHSA-Q4GR-3X5P-634J | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | PCF::pcf_sess_sbi_discover_and_send (sm-policies endpoint; file not named) | lib/pfcp/handler.c |
| 18 | GHSA-X82J-9GMV-PV8W | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/pcf/context.c::pcf_sess_set_ipv6prefix | lib/pfcp/handler.c |
| 19 | GHSA-XM8G-256C-HJQJ | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/pcf/nbsf-handler.c::pcf_nbsf_management_handle_register | lib/pfcp/handler.c |
| 20 | GHSA-5QQ8-GCHC-F3PV | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | lib/proto/types.c::ogs_pcc_rule_install_flow_from_media | lib/pfcp/handler.c |
| 21 | GHSA-9V4P-7HGJ-VMRQ | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/pcf/sm-sm.c::pcf_npcf_smpolicycontrol_handle_delete | lib/pfcp/handler.c |
| 22 | GHSA-F9QH-RWP4-48X6 | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/smf/npcf-handler.c::update_authorized_pcc_rule_and_qos | lib/pfcp/handler.c |
| 23 | GHSA-JJ2P-W4F3-JMGM | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/smf/npcf-handler.c::update_authorized_pcc_rule_and_qos | lib/pfcp/handler.c |
| 24 | GHSA-PWCX-2R94-W92M | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/smf/n4-build.c::smf_n4_build_qos_flow_to_modify_list | lib/pfcp/handler.c |
| 25 | GHSA-QHRX-45M5-GRGP | open5gs/open5gs | FALSE_POSITIVE | wrong_edge | src/smf/npcf-handler.c::update_authorized_pcc_rule_and_qos | lib/pfcp/handler.c |

## Gate summary
Every row: `identity_gate=PASS` (advisory names repo + mechanism + identity, `github_reviewed=false`), `ai_hunk_gate=FAIL` (candidate diffs read; they touch a different file than the vulnerable hunk), `topology_gate=PASS` (no authorship transfer), `but_for_gate=FAIL` (removing the AI commit does not remove the named mechanism), `fix_reversal_gate=UNKNOWN` and `release_gate=UNKNOWN` (no first-party fix/version available locally), `uniqueness_gate=PASS`.

## Evidence
- Advisory DB: `/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database` @ `6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86`
- open5gs pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/open5gs__open5gs`; candidates c42d7b7d9b930b5b421b02c5ad3625129e78ac60, d28e2f7f49f084bed6020440b0b54a784fbce56a
- publishpress pool: `/home/hanqing/.cache/ghsa200-sweep-fetch/publishpress__publishpress-future`; candidates 2c24c427fac46f38b04f8b2eb1b29064c9ac72fb, db996ac21af74fefb480b7920123a3e34558f1bd

Candidate open5gs diffs (both read in full):
- `c42d7b7` "pfcp: add defensive resets for FAR/URR optional fields in Create handlers" - `lib/pfcp/handler.c` only (reset presence-driven FAR/URR fields).
- `d28e2f7` "pfcp: use find_or_add in Create FAR/QER/URR handlers and make Remove idempotent" - `lib/pfcp/handler.c` only (find_or_add + idempotent Remove).
Neither touches `nudm-handler.c`, `nsmf-handler.c`, `gmm-handler.c`, `nudr-handler.c`, `udm-*.c`, `lib/sbi/*`, `lib/dbi/*`, `lib/proto/*`, `nnssf-handler.c`, `gtp-path.c`, `pcf/*`, or `smf/*` - the files named by the 24 open5gs advisories.

Candidate publishpress diffs (both read in full):
- `2c24c42` "Add a new step for interactive delay (#1349)" - workflow-editor JSX assets + `src/Modules/Workflows/*` + `services.php` (no `ShortcodeController.php`).
- `db996ac` "Prevent removal of the last option in custom options component" - `assets/jsx/workflow-editor/components/data-fields/custom-options/index.jsx` only.
Neither touches `src/Modules/Expirator/Controllers/ShortcodeController.php`, the `[futureaction]` wrapper-attribute hunk named by the advisory.
