# unreviewed adjacent slice 5 — AI-introduces-mechanism adjudication

## Verdict

Proposed admissions: 0 / 25. Every row is FALSE_POSITIVE (wrong_edge): no candidate AI commit introduces the advisory-named mechanism. 24 of 25 rows share two open5gs PFCP commits; the 25th is omec-project/amf.

## Decisive finding

- open5gs (24 rows): the only candidate AI commits are `c42d7b7d` ("pfcp: add defensive resets for FAR/URR optional fields in Create handlers") and `d28e2f7f` ("pfcp: use find_or_add in Create FAR/QER/URR handlers and make Remove idempotent"), both touching only `lib/pfcp/handler.c` (PFCP N4 FAR/QER/URR Create/Remove). Every named mechanism lives in a different subsystem/file: SMF (`src/smf/nsmf-handler.c`, `src/smf/gsm-build.c`, `src/smf/gsm-handler.c`, NAS), NRF/SBI (`lib/sbi/conv.c`, `lib/sbi/nnrf-handler.c`, `lib/sbi/message.c`, `lib/sbi/context.c`, `lib/sbi/client.c`, `lib/sbi/nghttp2-server.c`, `lib/core/ogs-timer.c`), AUSF (`src/ausf/nausf-handler.c`), and AMF (`src/amf/gmm-sm.c`). Zero file overlap with `lib/pfcp/handler.c`.
- omec-project/amf (1 row, CVE-2026-9298, "PathSwitchRequest Handler memory corruption"): candidates are `27b187fc` (gmm/handler.go RegistrationRequest snapshot — a nil-crash fix) and `bb77df56` (N3IWF-ID sctplb bridge; its ngap/handler.go hunk only changes `HandleInitialUEMessage` REDIRECT_MSG N3IwfId). Neither authors the PathSwitchRequest hunk.

The AI hunk gate fails because the AI commit does not author the vulnerable hunk; but-for fails because removing the AI change does not shrink the mechanism; fix-reversal fails because the AI change is not on the mechanism reversal path. Release containment stays UNKNOWN for every row (unreviewed objects have affected=[] and supply no fixed artifact).

## Gate distribution (25 rows)

| gate | PASS | FAIL | UNKNOWN |
|---|---|---|---|
| identity_gate | 25 | 0 | 0 |
| ai_hunk_gate | 0 | 25 | 0 |
| topology_gate | 25 | 0 | 0 |
| but_for_gate | 0 | 25 | 0 |
| fix_reversal_gate | 0 | 25 | 0 |
| release_gate | 0 | 0 | 25 |
| uniqueness_gate | 25 | 0 | 0 |

identity/topology/uniqueness PASS is a proposal-level local determination (case/alias absent from foundation.jsonl); it does not rescue a row whose AI hunk is not the mechanism.

## Per-row results

| # | GHSA | CVE | vulnerable surface | verdict |
|---|---|---|---|---|
| 1 | GHSA-6HJ2-QQXQ-44PP | CVE-2026-8252 | SMF::smf_nsmf_handle_create_data_in_hsmf (null ptr deref) | FALSE_POSITIVE (wrong_edge) |
| 2 | GHSA-7G8J-9F3M-5JCF | CVE-2026-8268 | SMF::OpenAPI_list_create | FALSE_POSITIVE (wrong_edge) |
| 3 | GHSA-CPXG-2CQW-2WJQ | CVE-2026-8266 | SMF::gsm_build_pdu_session_establishment_accept @ src/smf/gsm-build.c | FALSE_POSITIVE (wrong_edge) |
| 4 | GHSA-GMMH-VCQP-GRJC | CVE-2026-8270 | SMF::ogs_nas_parse_qos_rules | FALSE_POSITIVE (wrong_edge) |
| 5 | GHSA-GWX7-3CPR-H65F | CVE-2026-8267 | SMF::smf_nsmf_handle_created_data_in_vsmf | FALSE_POSITIVE (wrong_edge) |
| 6 | GHSA-V736-85VC-HQF4 | CVE-2026-8269 | SMF::smf_nsmf_handle_create_sm_context | FALSE_POSITIVE (wrong_edge) |
| 7 | GHSA-X779-6VCW-95P6 | CVE-2026-8288 | SMF::gsm_handle_pdu_session_modification_qos_flow_descriptions @ src/smf/gsm-handler.c | FALSE_POSITIVE (wrong_edge) |
| 8 | GHSA-4C5M-7X4H-HR3W | CVE-2026-8290 | SMF::smf_nsmf_handle_update_data_in_vsmf @ src/smf/nsmf-handler.c | FALSE_POSITIVE (wrong_edge) |
| 9 | GHSA-F67V-6P73-PVC5 | CVE-2026-8289 | SMF::smf_nsmf_handle_update_data_in_vsmf @ src/smf/nsmf-handler.c (qosFlowProfile) | FALSE_POSITIVE (wrong_edge) |
| 10 | GHSA-6673-JRVF-QRVQ | CVE-2026-8292 | NRF::yuarel_parse @ lib/sbi/conv.c (hnrf-uri) | FALSE_POSITIVE (wrong_edge) |
| 11 | GHSA-XG8C-HF2J-JJW5 | CVE-2026-8291 | NRF::ogs_nnrf_nfm_handle_nf_profile @ lib/sbi/nnrf-handler.c | FALSE_POSITIVE (wrong_edge) |
| 12 | GHSA-4R7X-PM54-QXQ9 | CVE-2026-8729 | NRF @ lib/sbi/message.c (service-names/snssais) | FALSE_POSITIVE (wrong_edge) |
| 13 | GHSA-8HVV-FJPF-3CXR | CVE-2026-8730 | NRF::ogs_sbi_nf_instance_set_id @ lib/sbi/context.c | FALSE_POSITIVE (wrong_edge) |
| 14 | GHSA-CGRM-WWH5-V7W8 | CVE-2026-8728 | NRF::ogs_sbi_discovery_option_parse_plmn_list @ lib/sbi/conv.c | FALSE_POSITIVE (wrong_edge) |
| 15 | GHSA-QQ7J-V673-3QJH | CVE-2026-8731 | NRF::ogs_sbi_client_add @ lib/sbi/client.c | FALSE_POSITIVE (wrong_edge) |
| 16 | GHSA-2WQ5-J34G-97X4 | CVE-2026-8745 | AUSF::ogs_timer_add @ src/ausf/nausf-handler.c | FALSE_POSITIVE (wrong_edge) |
| 17 | GHSA-49G8-77WH-W2GP | CVE-2026-8746 | NRF::discover_handler @ lib/sbi/nghttp2-server.c (UAF) | FALSE_POSITIVE (wrong_edge) |
| 18 | GHSA-H3W8-H79V-64CV | CVE-2026-9298 | omec-project/amf::PathSwitchRequest Handler (mem corruption) | FALSE_POSITIVE (wrong_edge) |
| 19 | GHSA-P769-7PG7-JX7M | CVE-2026-10113 | NRF Shared NF-profile Parser @ lib/sbi/nnrf-handler.c | FALSE_POSITIVE (wrong_edge) |
| 20 | GHSA-2VP2-C9X2-M79C | CVE-2026-10114 | NRF::handle_scp_info @ lib/sbi/nnrf-handler.c (OOB write) | FALSE_POSITIVE (wrong_edge) |
| 21 | GHSA-V3PH-7V5F-JMGP | CVE-2026-10115 | NRF Shared NF-profile Parser @ lib/sbi/nnrf-handler.c | FALSE_POSITIVE (wrong_edge) |
| 22 | GHSA-XQ3Q-8WC9-JGFC | CVE-2026-10116 | ue-auth Endpoint::ogs_sbi_xact_add @ lib/core/ogs-timer.c | FALSE_POSITIVE (wrong_edge) |
| 23 | GHSA-FH2X-JCF9-HJR5 | CVE-2026-10117 | ogs_pool_id_calloc @ lib/sbi/nghttp2-server.c | FALSE_POSITIVE (wrong_edge) |
| 24 | GHSA-5FC4-7Q74-93X4 | CVE-2026-10156 | nf-instances Endpoint::handle_amf_info @ lib/sbi/nnrf-handler.c | FALSE_POSITIVE (wrong_edge) |
| 25 | GHSA-94VG-M7V6-9C25 | CVE-2026-10565 | AMF NGAP Handover::gmm_state_security_mode @ src/amf/gmm-sm.c (race) | FALSE_POSITIVE (wrong_edge) |

## Candidate commits (evidence)

- `c42d7b7d` Peter Gradwell, "pfcp: add defensive resets for FAR/URR optional fields in Create handlers", `lib/pfcp/handler.c` (+17). Marker: Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>.
- `d28e2f7f` Peter Gradwell, "pfcp: use find_or_add in Create FAR/QER/URR handlers and make Remove idempotent", `lib/pfcp/handler.c` (+21/-21). Marker: Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>.
- `27b187fc` Gabriel Arrobo, "Avoid nil crash by snapshotting RegistrationRequest in mobility update (#686)", `gmm/handler.go` (+63/-27) + VERSION + test. Marker: Co-authored-by: Copilot <copilot@github.com>.
- `bb77df56` Andy Bavier, "feat(n3iwf): add N3IWF-ID support to sctplb gRPC bridge", `nas/handler.go`, `ngap/dispatcher.go`, `ngap/handler.go` (REDIRECT_MSG N3IwfId), `ngap/message/send.go`, protos, `service/amf_server.go`. Marker: Co-Authored-By: Claude <noreply@anthropic.com> + "Generated with Claude Code".

All four carry explicit AI markers, so the rejections are NOT marker-absence rejections; they are wrong-edge rejections (the AI-authored hunk is not the vulnerable hunk).

## Frozen evidence

- Contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`, sha256 cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3.
- Input: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj-slice-5.jsonl`, sha256 6d3871d856527e106d471b31516911fd22577a85b8d7e39f071ca05de8e4717e.
- Advisory database: /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database @ a42c436870111aa3f221257c9d56126a93173ccc (advisories/unreviewed/).
- Commit pool: /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>. Diffs read via git smart-HTTP fetch; no GitHub API, no blame/SZZ.

## Claim boundary

Worker PASS is a proposal only; the leader replays every proposed acceptance. Here there are zero countable proposals. identity/uniqueness PASS rests on a local negative search; unreviewed objects with affected=[] and no fixed artifact keep release_gate=UNKNOWN. No row is countable.
