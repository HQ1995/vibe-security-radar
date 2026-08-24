# DR adjudication: unr-dr-slice-1 (30 unreviewed GHSA rows)

Lane: herdr-260814-unr1-ds. Spec: DR-SPEC.md. Method: agentic diff-reading only (no blame/SZZ); exact-hunk comparison of each ai_ancestor diff against the fix_ref's vulnerable hunk. All 30 rows are FALSE_POSITIVE (class wrong_edge): the AI ancestor's diff does not introduce or materially rewrite the vulnerable hunk. Zero countable. Missing evidence is left UNKNOWN, never converted to FAIL.

## Verdict-first summary

- 0 AI_DIRECT_ROOT
- 0 AI_NEW_SURFACE_CONTRIBUTOR
- 30 FALSE_POSITIVE (wrong_edge)
- 0 UNKNOWN
- countable = 0

The decisive gate on every row is ai_hunk_gate = FAIL: the ancestor and the fix share a file (or a metadata/build file), but the ancestor's actual hunks are in a different function or concern than the vulnerable hunk. Advisories GHSA-7X49-HHJC-29RG, GHSA-8M2W-V7G5-76V3, GHSA-3397-VR69-3M3W, and GHSA-V5VQ-G74Q-P374 were published after the local advisory-database clone's last sync, so their identity gate is UNKNOWN and the mechanism was read from the fix_ref diff.

## Per-row reasoning

1. GHSA-3R49-76F3-PF2M (marcobambini/gravity) — FP. Vuln: heap overflow in gravity_vm_exec / gravity_fiber_reassign. Fix 0.9.6 adds a stack-grow guard in gravity_fiber_reassign (gravity_value.c:1423) and a max-stack check in gravity_check_stack (gravity_vm.c:260). Ancestor 0.9.5 (Claude Opus 4.6) touches the same files but at gravity_class_grow (:126), gravity_function_cpool_add (:596), bool-compare (:742), and setslot/getslot (:1837) — different hunks.

2. GHSA-3H94-X92G-H9G5 (Azuriom/Azuriom) — FP. Vuln: servers routes missing can:admin.servers middleware. Fix adds the middleware. Ancestor adds the force-password route under can:admin.users and forcePasswordChange in UserController — different route group and controller method.

3. GHSA-839R-7HHG-XHQR (litespeedtech/lsquic) — FP. Vuln: lsquic_engine_packet_in memory leak. Fix adds lsquic_mm_put_packet_in (:3296). Ancestor WebTransport support changes engine init/check settings (:323, :499) — not the packet-in path.

4. GHSA-9F77-473J-CJG2 (pspete/psPAS) — FP. Vuln: missing TLS 1.2 in Get-PASSAMLResponse. Fix modifies psPAS/Private/Get-PASSAMLResponse.ps1. Ancestor 6.0 Update 4 touches Add-PASPTARule.ps1 and PTA files — a different function.

5. GHSA-PWFC-QM9R-P6H4 (nesquena/hermes-webui) — FP. Vuln: /api/session/delete path traversal. Fix adds sid validation in handle_post (:724). Ancestor rewrites _handle_live_models (:1448) — different handler.

6. GHSA-HGGV-JXWF-W664 (samuelclay/NewsBlur) — FP. Vuln: SSRF in add_url. Fix adds utils/url_safety.py and changes apps/rss_feeds/views.py. Ancestor (Claude Opus 4.8) YouTube-host detection touches models.py / feed_fetcher.py / feed_functions.py — never views.py.

7. GHSA-7X49-HHJC-29RG (koxudaxi/datamodel-code-generator) — FP. The ai_ancestor af435d98 IS the fix PR (truthiness -> is not None for empty alias); fix_ref 545a96c5 is its merge commit. The ancestor remediates the bug, it does not introduce it.

8. GHSA-8M2W-V7G5-76V3 (esnet/iperf) — FP. Vuln: JSON_read Params size. Fix adds MAX_PARAMS_JSON_STRING check in JSON_read (:2799). Ancestor streaming-JSON adds JSONStream_Output on the output side — not JSON_read.

9. GHSA-GFW5-R5R2-FV73 (r-lib/gh) — FP. Vuln: Authorization header retained in response. Fix in R/gh_response.R (do not save request headers). Ancestor Posit Connect credentials touches R/gh_token.R — different file.

10. GHSA-HG3W-JVVC-86CF (raine/consult-llm-mcp) — FP. Vuln: execSync command injection in src/server.ts. Fix is a full Rust rewrite. Ancestor adds a model to src/llm-cost.ts / src/models.ts — not server.ts.

11. GHSA-9Q9G-RP9X-244H (windmill-labs/windmill) — FP. Vuln: missing Operator checks on create/update endpoints. Fix adds is_operator guards in create_flow / update_flow / create_script. Ancestor (Claude Opus 4.5) error-handler-mute feature touches send_error_to_workspace_handler — different hunk.

12. GHSA-RPPV-5944-CRMM (nesquena/hermes-webui) — FP. Vuln: workspace path trust boundary (api/workspace.py + api/routes.py). Ancestor workspace-panel close-button fixes touch static/boot.js + static/index.html — frontend only.

13. GHSA-34J3-4JPJ-GX6Q (nesquena/hermes-webui) — FP. Vuln: session export auth bypass. Fix adds profile checks in _handle_session_export and handle_get. Ancestor adds passkey enrollment auth gate — a different security surface.

14. GHSA-5WQV-FHMR-PJGH (nesquena/hermes-webui) — FP. Same fix/ancestor pair; vuln is /api/session cross-profile disclosure. Ancestor's passkey-enrollment gate is unrelated.

15. GHSA-MGXW-V6RH-WCV6 (nesquena/hermes-webui) — FP. Vuln: session search profile isolation. Fix scopes _handle_sessions_search to the active profile. Ancestor v0.51.268 changes handle_get orphan-probe batching — different handler.

16. GHSA-WWX5-JQ7H-RP7V (nesquena/hermes-webui) — FP. Vuln: passkey options resource exhaustion. Fix adds PasskeyRateLimitError handling to the passkey options endpoints. Ancestor v0.51.269 touches _handle_sessions_search — different endpoint.

17. GHSA-R68Q-JR9V-43RV (rafaelsouzars/orthanc-explorer-2) — FP. Vuln: XSS in StudyList.vue. Ancestor is a vite 6.4.1->6.4.2 dependency bump (package.json / package-lock.json only).

18. GHSA-34J2-GCWP-VRV5 (tinyhumansai/openhuman) — FP. Vuln: shell allowlist bypass (find -execdir/-okdir and env-prefix). Fix adds has_dangerous_env_prefix and blocks -execdir/-okdir. Ancestor autonomy-budget change only rewrites a rate-limit error string (:1794) — unrelated.

19. GHSA-3397-VR69-3M3W (AstrBotDevs/AstrBot) — FP. Vuln: persona tool boundary. Fix filters req.func_tool by persona_allowed_tools. Ancestor (Copilot Autofix + gemini-code-assist) media-reference handling touches video attachment and quote-caption hunks — unrelated.

20. GHSA-V5VQ-G74Q-P374 (AstrBotDevs/AstrBot) — FP. Same fix/ancestor pair as row 19.

21. GHSA-9GJP-PJ3G-87PQ (ImageMagick/ImageMagick) — FP. Vuln: memory leak in LoadOpenCLDeviceBenchmark. Both the slice's fix_ref ("Moved permissions block in the workflows") and the ancestor ("Bump actions/download-artifact") are CI workflow changes; neither touches MagickCore. The slice's fix_ref appears misrouted against the advisory's named fix (7.1.2-13).

22. GHSA-9MCW-G6WH-83HP (itsjustcurtis/MenyooSP) — FP. Vuln: path traversal in file save/folder/create/rename. Fix adds IsSafePath guards. Ancestor "Display drawable names" adds display helpers and gizmo/entity-editing code — not the file-management hunks.

23. GHSA-WXV8-W48J-R2F4 (python/cpython) — FP. Vuln: Expat hash-flooding entropy. Fix uses XML_SetHashSalt16Bytes. Ancestor fixes CharacterDataHandler integer overflow — a different pyexpat.c hunk.

24. GHSA-Q5CV-5VF6-95GP (Perl/perl5) — FP. Vuln: pack_ip_mreq_source OOB read in cpan/Socket/Socket.xs. Ancestor JSON::PP CPAN update touches cpan/JSON-PP/* and Porting/Maintainers.pl — not Socket.xs.

25. GHSA-89HG-MHJP-F99Q (open5gs/open5gs) — FP. Vuln: PathSwitchRequest improper authentication. Fix preserves UE security capabilities on path switch. Ancestor adds a NULL check / Cause IE handling in ngap_handle_error_indication — a different handler.

26. GHSA-9VHJ-8H2M-3G3M (open5gs/open5gs) — FP. Vuln: ran_ue_find_by_amf_ue_ngap_id improper authorization. Fix validates RAN ownership and explicitly leaves the error-indication path unchanged. Ancestor touches only the error-indication handler.

27. GHSA-F8F8-M8XJ-9XH7 (polkit-org/polkit) — FP. Vuln: nested-XML OOB write. Fix adds a depth guard in the _start SAX handler. Ancestor multi-directory support changes the directory enumeration (directories list / ensure_all_files) — not the SAX parser.

28. GHSA-J73W-7XX9-CQ3X (facebook/mvfst) — FP. Vuln: heap buffer overflow. Fix (re-sync) touches BufUtil.h. Ancestor adds ContiguousCursor (new files + test BUCK) — a different module.

29. GHSA-688C-H9C2-FFWG (osrg/gobgp) — FP. Vuln: missing BGPHeader marker validation. Fix adds the marker check (:16017). Ancestor (Copilot) changes LsTLVUnidirectionalDelayVariation.Serialize Reserved->0 (:7836) — a different struct.

30. GHSA-M763-9MQF-95RQ (osrg/gobgp) — FP. Vuln: CapSoftwareVersion off-by-one. Fix changes data[1:len] to data[1:1+len] (:1125). Ancestor (Copilot) changes LsTLVUnidirectionalDelayVariation.Serialize (:7836) — a different struct.

## Constraints honored

- Only the owned directory was written (result.json, cases.jsonl, report.md).
- No GitHub API; diffs read from the local bare pool /home/hanqing/.cache/ghsa200-sweep-fetch via git smart-HTTP blob fetch.
- No edits outside the owned directory; no commit/push/reset/checkout.
