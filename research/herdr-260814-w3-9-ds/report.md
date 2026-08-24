# herdr-260814-w3-9-ds - unreviewed-adjudication unr-adj3-slice-9

**Verdict-first: 24/25 FALSE_POSITIVE, 1/25 NARROW (AI_DIRECT_ROOT). 0 countable, 1 proposal.**

24 rows are wrong-edge false positives: no candidate AI commit introduces the named
mechanism. One row is a real AI-introduction proposal: OpenPLC_v3 GHSA-QPRQ-675R-82H6
(CVE-2026-71268), where Devin AI commit 7ea8d717c593 added the unvalidated FILE:
directive write in compile_program. Canonical count unchanged; publication HOLD.

## Method

- Mechanisms read from the local advisory-database clone (advisories/unreviewed/...); the
  one absent advisory (OpenPLC_v3) was read from the first-party github.com/advisories page
  plus the NVD CVE description (osv.dev 404).
- Candidate diffs: disjoint rows resolved from the slice changed-file lists; the three
  overlapping candidates were fetched via git smart-HTTP (depth-1 + --deepen=1) into work/
  and their diffs read: OpenPLC 7ea8d717c593, siyuan e564ce7b1fc5, and the OpenPLC master
  openplc.py tip (to check whether the sink is patched). No GitHub API, no blame/SZZ.

## NARROW proposal (leader must verify)

- GHSA-QPRQ-675R-82H6 / CVE-2026-71268 (thiagoralves/OpenPLC_v3): compile_program parses
  FILE: directives from uploaded .st files and writes them via
  os.path.join('./core', file_path) with no file_path validation (path traversal).
  Candidate 7ea8d717c593 (Author: Devin AI <devin-ai-integration[bot]>) is the atomic commit
  that ADDS this exact sink (21 insertions). validate_file_path exists in credentials.py but
  is never invoked; master is still unpatched. ai_hunk/but_for/topology = PASS;
  fix_reversal and release = UNKNOWN (no first-party fix/release observed).

## Per-row

| # | GHSA | CVE | repo | mechanism | candidate | evidence | verdict |
|---|---|---|---|---|---|---|---|
| 1 | GHSA-M7VH-M7F4-7H43 | CVE-2026-14757 | radareorg/radare2 | libr/core/cmd_anal.inc (core_anal_bytes) | 4c849b2aaeda | changed_files | FALSE_POSITIVE |
| 2 | GHSA-QHC4-CXQ6-MG2G | CVE-2026-16489 | jsforce/jsforce | lib/registry/sfdx.js (_execCommand) | 3c0e78909a2d | changed_files | FALSE_POSITIVE |
| 3 | GHSA-QPRQ-675R-82H6 | CVE-2026-71268 | thiagoralves/OpenPLC_v3 | webserver/openplc.py (compile_program FILE: write) | 746b16bbff4c | diff_read | NARROW |
| 4 | GHSA-FW73-7P7W-P28M | CVE-2025-46149 | pytorch/pytorch | nn.Fold (inductor) | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 5 | GHSA-M7X9-2M87-MQHF | CVE-2025-46148 | pytorch/pytorch | nn.PairwiseDistance (eager) | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 6 | GHSA-V5F2-JG66-6H4H | CVE-2025-46150 | pytorch/pytorch | FractionalMaxPool2d (torch.compile) | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 7 | GHSA-8F2W-3W4C-PWJ2 | CVE-2025-55551 | pytorch/pytorch | torch.linalg.lu (LinearAlgebra.cpp) | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 8 | GHSA-H36M-9QJR-PV93 | CVE-2025-46153 | pytorch/pytorch | torch/_decomp/decompositions.py (bernoulli_p) | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 9 | GHSA-X8X6-V465-7V88 | CVE-2025-46152 | pytorch/pytorch | bitwise_right_shift (BinaryOps) | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 10 | GHSA-2QM5-PR8V-RJVP | CVE-2025-55553 | pytorch/pytorch | torch/fx/experimental/proxy_tensor.py | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 11 | GHSA-765F-85MC-5QMW | CVE-2025-55557 | pytorch/pytorch | torch.cummin inductor lowering | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 12 | GHSA-79PG-RRP8-8WQM | CVE-2025-55558 | pytorch/pytorch | Conv2d+hardshrink+view/mv inductor lowering | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 13 | GHSA-F9WH-QR6G-V2H4 | CVE-2025-55554 | pytorch/pytorch | torch.nan_to_num-.long() (UnaryOps) | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 14 | GHSA-MF74-QWPW-GJ2W | CVE-2025-55552 | pytorch/pytorch | torch.rot90 + torch.randn_like (TensorShape) | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 15 | GHSA-MXHP-68X5-J3FX | CVE-2025-55560 | pytorch/pytorch | to_sparse/to_dense inductor lowering | 019fed39aa6b | changed_files | FALSE_POSITIVE |
| 16 | GHSA-4JQP-H8F8-5FH9 | CVE-2026-2490 | rustdesk/rustdesk | Transfer file (Windows link following) | 6306f833163c | changed_files | FALSE_POSITIVE |
| 17 | GHSA-C9V6-FHFF-767P | CVE-2026-30795 | rustdesk/rustdesk | src/hbbs_http/sync.rs (heartbeat sync) | 6306f833163c | changed_files | FALSE_POSITIVE |
| 18 | GHSA-QQPP-685P-JC24 | CVE-2026-30794 | rustdesk/rustdesk | src/hbbs_http/http_client.rs (TLS retry) | 6306f833163c | changed_files | FALSE_POSITIVE |
| 19 | GHSA-V738-924G-MM67 | CVE-2026-30785 | rustdesk/rustdesk | hbb_common password security/config encryption | 6306f833163c | changed_files | FALSE_POSITIVE |
| 20 | GHSA-C7MP-5HG2-GFH8 | CVE-2026-43824 | argoproj/argo-cd | ServerSideDiff (Secret rendering) | 226178c1a599 | changed_files | FALSE_POSITIVE |
| 21 | GHSA-24R3-P3X6-CQVX | CVE-2026-56397 | siyuan-note/siyuan | Bazaar marketplace package metadata/README rendering | 915c118a67ee | diff_read | FALSE_POSITIVE |
| 22 | GHSA-9F8R-GFGQ-CJHM | CVE-2026-56395 | siyuan-note/siyuan | Bazaar marketplace package metadata/README rendering | 915c118a67ee | diff_read | FALSE_POSITIVE |
| 23 | GHSA-V4H4-747P-QJGX | CVE-2026-13483 | arc53/DocsGPT | application/security/encryption.py (encrypt_credentials) | 80d208252987 | changed_files | FALSE_POSITIVE |
| 24 | GHSA-2F23-FGRF-4R2H | CVE-2026-58304 | Samsung/escargot | Escargot interpreter/parser (OOB read/write before 779f6bed) | 2dee22f5c7b8 | changed_files | FALSE_POSITIVE |
| 25 | GHSA-7947-C2XP-C8W5 | CVE-2026-58307 | Samsung/escargot | Escargot interpreter/parser (OOB read/assertion before 2dee22f5) | 2dee22f5c7b8 | changed_files | FALSE_POSITIVE |

## Diff-read rows

- OpenPLC 7ea8d717c593 (row 3): adds (*FILE: parsing and the unvalidated ./core write -> path traversal. NARROW.
- siyuan e564ce7b1fc5 (rows 21-22): kernel/bazaar/package.go +1 (Kernels field) and plugin.go
  IsTargetSupported refactor; no Bazaar HTML rendering of package metadata. FALSE_POSITIVE.

## Conclusion

This packet admits no fully countable case. 24 rows close at ai_hunk/but_for FAIL (wrong
edge); 1 row is a NARROW AI_DIRECT_ROOT proposal (OpenPLC_v3) that needs leader closure of
fix_reversal and release. Canonical ledger untouched; publication HOLD.
