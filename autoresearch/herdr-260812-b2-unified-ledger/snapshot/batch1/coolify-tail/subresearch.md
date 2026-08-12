# Coolify-only unexamined tail: exclusion inventory and bounded adjudication

> Intermediate worker note. `report.md` is authoritative: the final inventory also includes
> `AUDIT-CONSOLIDATED-LEDGER-156` and `RESEARCH-NEEDS-REVIEW-CLOSURE` (nine current docs),
> whose later closure makes CVE-2026-34050 and CVE-2026-34149 existing PASS exclusions.

Status: **COMPLETE for this bounded shard; 0 new claim-grade positives**. Eleven non-duplicate public components (twelve AI candidate edges) were deep-reviewed. All eleven component rows are `FAIL` controls; no routing or exact-blame hit was promoted. Unassessed Coolify history remains `UNKNOWN`.

## Scope and snapshot boundary

- Snapshot time: `2026-08-12T16:25:34Z`.
- Shared checkout: `/home/hanqing/agents/ai-slop`, branch `dev`, HEAD `6c0d2084fd1240341d6d1b9f9096252490168f0b`; the intentionally dirty tree was read only.
- First-party Coolify clone: `/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify`, clean HEAD `098d3d4c253a5a79aa8d166854a1b0a202077259`; heads/tags digest `315a86ad9900551d600e2e21b96a923bc52c5b9983d4ec2af661a8d94f30e373`.
- CVEList V5 clone: clean HEAD `8ca64b5ad6b84d3cd5741b023610b8494800f174`.
- No file outside this report was written. No cache, clone, existing Coolify witness, or ledger was mutated. No build, test suite, network request, or API credential was used.
- Candidate packets, exact blame, ancestry, subjects, and model reviews are **diagnostic routing evidence only**. A negative below comes from the direct parent/candidate/fix diffs. A publication-positive would additionally need the same security mechanism and released containment; none survived that gate.

## Input hashes

| Input set | Count | SHA-256 / boundary |
|---|---:|---|
| Current Coolify-referencing docs, listed newest-first below | 7 | aggregate `a8c932646c9ee0aa3c3c497b916fd720dfe36cbb69a33d2ac24b2e270d3663aa` |
| `scripts/cohort_coolify*.py` plus Coolify case/control/fix JSON | 88 = 78 Python + 10 JSON | aggregate `4e867a4bfae343acbae94dbcad751366f20d1219bda25bf22ffbbac7b2370134` |
| `scripts/tests/test_cohort_coolify*.py` | 79 | aggregate `26f8044e648ea8c487586cc5756eb234ce8068a1e62b8503031cdc5ed158ae69` |
| Eleven first-party CNA objects used below | 11 | aggregate `7d933708d5e65e1aee8684905c59267b863eb4866648da310dd579cce12c9680` |
| `global-batch-v9-inputs/coolify/fix-roots.jsonl` | 42 rows | `693451af3305f8a7fb0e9cfda9c273dfbdcb2b953d8fb774042b9721884964ba` |
| `global-blame-v9/coolify/exact-direct-candidates.jsonl` | 48 rows | `61f4b6a58988cf1883b3bd545abc96cc05e5f69f5863173a339b7acbd824a320` |
| `global-feature-review-packets-v9/coolify/packets.jsonl` | 31 packets | `4b5f4f7d2afb6ccc0eb06346e9a349cac3b33e74b0decfb16dc6d265e7cd706f` |
| `global-batch-v9-inputs/coolify/ai-commits.jsonl` | 556 rows | `aa873c464200eda94e59e31d10e8a4d4dea47dfd995dab06624e258349fcf8fc` |
| Conservative exclusion tokens found in all docs/sources/tests | 1,748 unique hex tokens of length 8-40; 741 full 40-hex tokens | token digest `27d96857c8e7caf30d73024a0f7a9e8fca5647a9ea8fd991c60ee1a41f52ab7c`; full-SHA digest `6cc37f91e777952d2fc86e6c2214d6cc8ea3c3693de5c84e2ec797c7d5838401` |

The individual CNA hashes are recorded with each source path by the replay command below. All eleven objects are `state=PUBLISHED` and point to a `coollabsio/coolify` repository advisory and exact public fix commit. This is a frozen local snapshot, not a live API assertion.

## Newest-first exclusion inventory

### Current docs

1. `docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` (2026-08-12 11:34 local): newest summary; already counts Coolify CVE-2026-34198, CVE-2026-42204, and commit-only CVE-2026-34167, and broadly says twelve other Coolify items were excluded.
2. `docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md` (11:34): exact incomplete-remediation lineage for CVE-2026-42204 and CVE-2026-34167.
3. `docs/RESEARCH-CAUSAL-LEDGER-V2-2026-08-11.md` (18:16): supersedes the earlier strict-audit label for CVE-2026-34034; `a8aa4524 -> 096d4369` is `FAIL/refactor_preservation`, not a causal origin.
4. `docs/AUDIT-118-CAUSAL-ACCURACY-2026-08-11.md` (17:40): same Coolify Sentinel refactor counterexample and validated rows CVE-2026-34599, CVE-2026-34049, CVE-2026-42148, and CVE-2026-32718.
5. `docs/RESEARCH-NEEDS-REVIEW-BATCH2-2026-08-11.md` (07:20): unresolved CVE-2026-34167 and CVE-2026-34050 replay notes.
6. `docs/AUDIT-STRICT-LEDGER-156-2026-08-11.md` (06:23): Coolify rows 26, 38, 49, 58, 60, 61, 69, 101, 117, 120, and 150. Row 49's earlier `PASS` is superseded by item 3 above.
7. `docs/tasks/ai-routing-pilot.md` (2026-08-01): routing contract only.

Already adjudicated/excluded doc rows were not re-run:

| Component | Existing candidate -> fix | Current exclusion |
|---|---|---|
| CVE-2025-64419 | `f8e3bb54... -> f86ccfaa...` | `FAIL`: human `27c36bec...` origin; AI is in repair history. |
| CVE-2026-42147 | `564cd836... -> 297e9c41...` | `FAIL`: webhook URL rule vs S3 endpoint SSRF, wrong sink. |
| CVE-2026-34034 | `a8aa4524... -> 096d4369...` | newest verdict `FAIL/refactor_preservation`; parent already has all token shell sinks. |
| CVE-2026-34599 | `bbb2aa9a... -> f267a28c...` | existing `PASS`; no second component count for sibling edges. |
| CVE-2026-34049 | `473c3227... -> b1de75a7...` | existing `PASS`. |
| CVE-2026-34167 | `a94517f4... -> 3e0d48fa...` (carrier `2729dffb...`) | existing `AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY`; no release-level count. |
| CVE-2026-42148 | `18f30b7f... -> dc9322b1...` | existing `PASS`. |
| CVE-2026-34050 | `acff543e... -> 0fed5532...` | existing `NEEDS_REVIEW`; preserved, not silently promoted. |
| CVE-2026-34057 | `94560ea6...` / `a9f42b94... -> d486bf09...` | existing `NEEDS_REVIEW`; the different `cc96403c...` edge is assessed below. |
| CVE-2026-34149 | `473c3227... -> 99043600...` | existing `NEEDS_REVIEW`; preserved. |
| CVE-2026-32718 | `62c394d3... -> c15bcd56...` | existing `PASS`. |
| CVE-2026-34198 | `e1fe5863... ->` member `e1d4b468...`, carrier `98569e4e...` | newest strict released component; excluded. |
| CVE-2026-42204 | `c9922c30... ->` member `817128c5...`, carrier `e1aac50b...` | newest released incomplete-remediation component; excluded from new count. |

### Complete Coolify source/case inventory

The exact 88-file source inventory is the sorted output of:

```zsh
rg --files scripts | rg '^scripts/cohort_coolify[^/]*\.(py|json)$' | sort
```

It comprises the following 78 Python mechanisms/workflows (basenames shown; every path is under `scripts/`):

```text
activity_monitor_target_key_causal_witness
api_token_permission_preservation_witness
authorization_path_recovery_witness
backup_upload_validation_witness
buildtime_env_duplicate_reattribution_witness
candidate_patch_equivalence
candidate_repair_dossiers
causal_adjudication_ledger
cloud_settings_path_extension_witness
cloud_token_helper_preservation_witness
concurrent_index_migration_transaction_contract_witness
conductor_datalist_revert_attribution_witness
conductor_form_onboarding_attribution_witness
conductor_healthcheck_reset_origin_witness
conductor_trust_hosts_origin_witness
datalist_binding_origin_witness
dependency_bridge_schedule
deployment_rollback_causal_batch_witness
dev_compose_pull_policy_witness
dev_helper_action_witness
exact_delta_ai_review
exact_delta_causal_batch_witness
exact_delta_review_aggregate
exact_delta_review_packet
exact_preimage_recovery_witness
file_storage_acl_compositional_witness
fix_preimage_lineage
full_lineage_recovery_witness
git_ls_remote_incomplete_hardening_witness
github_install_maintenance_activation_witness
github_install_state_witness
github_sensitive_read_causal_witness
global_search_new_image_origin_witness
guard_helper_sink_schedule
guard_history_route_inventory
guard_history_route_recall
guard_method_history_schedule
guard_surface_history_schedule
hetzner_cloud_token_authorization_witness
hetzner_link_path_extension_witness
label_neutral_source_review_queue
lineage_recovery_witness
merge_member_causal_batch_witness
merge_member_expansion
merge_member_review_packet
merge_member_topology_overlay
modal_wire_ignore_causal_witness
noncausal_ai_candidate_witness
oauth_bulk_mutation_preservation_witness
oauth_guard_surface_witness
oauth_team_delete_path_extension_witness
onboarding_creation_path_witness
onboarding_refresh_regression_witness
onboarding_url_idor_path_extension_witness
postgresql_query_idor_path_extension_witness
preimage_batch_ai_review
preimage_exact_delta_bridge
preimage_recovery_batch_witness
private_key_hydration_preservation_witness
project_scope_hardening_witness
readonly_volume_path_normalization_witness
s3_restore_command_injection_witness
security_frontier_preservation_witness
sensitive_model_defaults_witness
sentinel_activation_carrier_witness
sentinel_command_injection_witness
sentinel_instant_save_path_witness
sentinel_restart_activation_witness
symbol_contract_method_migration_witness
token_metrics_causal_batch_witness
trust_hosts_negative_cache_origin_witness
update_compose_map_style_origin_witness
upgrade_shutdown_order_witness
upgrade_status_auth_witness
volume_parser_preservation_witness
volume_shell_hardening_witness
webhook_notification_secret_compositional_witness
wire_navigate_authorization_witness
```

The ten JSONs are:

```text
cohort_coolify_conductor_exact_delta_causal_cases.json
cohort_coolify_exact_delta_causal_batch2_cases.json
cohort_coolify_merge_member_causal_batch2_cases.json
cohort_coolify_merge_member_causal_batch3_cases.json
cohort_coolify_repair_chain_controls.json
cohort_coolify_repair_chain_fix_manifest.json
cohort_coolify_repair_frontier_controls.json
cohort_coolify_repair_frontier_fix_manifest.json
cohort_coolify_repair_frontier_folded_controls.json
cohort_coolify_repair_frontier_folded_fix_manifest.json
```

All 79 `scripts/tests/test_cohort_coolify*.py` files were included in the SHA/prefix exclusion scan. They are verification evidence for their named contract, not independent causal rows.

The four case JSONs already freeze these fourteen candidate/fix/mechanism rows; all are excluded:

| Candidate prefix -> fix prefix | Mechanism |
|---|---|
| `473c32270d72 -> 5019c8db928a` | API backup S3 session/team context |
| `473c32270d72 -> e36622fdfb60` | cancel-deployment unscoped build server |
| `bf6a109e56e2 -> 73170fdd3378` | seeded Docker Compose path concatenation |
| `edcdea78a289 -> 6557514954ac` | GHCR cleanup overbroad token permission |
| `747a48b93379 -> 14bba8ba86a2` | Sentinel runtime debug payload |
| `e055c3b10159 -> 9b060958aad7` | Hetzner runtime debug payload |
| `5463f4d4961c -> d93a13eeee23` | cloud-init syntax validation |
| `bafb9a5a8baf -> c1518ba1c0be` | webhook missing-secret identifier oracle |
| `d9762e0310c7 -> b484c0cc253f` | deployment-log hardcoded display limit |
| `a5c6f53b583c -> bc39c2caa83b` | dirty-indicator layout-shift preservation |
| `fb4f12fcb8ab -> b9ea89d52886` | Compose build-pack reactivity |
| `3fdce06b654f -> a06c1a7bf5e3` | incomplete file-mount parent-segment confinement |
| `9493398b58ac -> 5e0e6772d5aa` | deployment-log morph-hook lifecycle |
| `f2a017a0636a -> aa18c4882350` | ActivityMonitor hydration lifecycle |

The repair frontier manifests also exclude seven unique fix roots and all paired controls: `3cc416a8069eed98bb342c09700a6e5084444a94`, `096d4369e59b3db7ace2db3ca42588c41b9b6019`, `3ba4553df5657582ad720a6572d83383fe89c078`, `81a3bb0f0769e5a765e77649d002ea6acf9a667f`, `7f135e0f6d87a6065a67b78b8a9976dfd99f3a2a`, `062ad5774041fb3be71abedcff33c4315613152c`, and `5973bb4d4f3c236d76ac25cb77c22e5317d5379f`. The chain manifest additionally includes `e36622fdfb60df2bb733c37d6f0f4f7ac8b61486`.

## Deep adjudication of the non-duplicative tail

All twelve candidate commits have direct commit-level Claude attribution in the frozen 556-row AI inventory. `git merge-base --is-ancestor candidate fix` returned true for every edge. That proves topology only. The direct parent baseline and exact fix delta reject every row on mechanism.

| # | First-party component | AI candidate (direct parent) | Exact repair lineage | Parent/delta and same-mechanism assessment | Released containment | Verdict / dedup |
|---:|---|---|---|---|---|---|
| 1 | [CVE-2026-34153 / GHSA-46hp-7m8g-7622](https://github.com/coollabsio/coolify/security/advisories/GHSA-46hp-7m8g-7622) | `20b428891673...` (`6d3c996ef374...`) | direct `3fdce06b654f...` (`47668121a403...`) | Candidate only replaces Docker image digest parsing in `ApplicationsController`; parent and candidate do not add the `mount_path -> LocalFileVolume.fs_path -> shell` path. Fix validates/escapes file-storage paths in controllers/model. Same controller, different field and sink. | beta.435 -> fixed beta.471 | **FAIL_WRONG_FIELD_SHARED_CONTROLLER**. No new component. |
| 2 | [CVE-2026-42147 / GHSA-pwm4-w33c-wjf3](https://github.com/coollabsio/coolify/security/advisories/GHSA-pwm4-w33c-wjf3) | `5e90fc6b8f12...` (`e0b2424b7645...`) | direct `297e9c41e199...` (`57ea0764b8f0...`) | Strong same-field negative control: candidate trims S3 endpoint/credentials; parent already accepts and uses attacker-controlled endpoints. Fix adds `SafeWebhookUrl` plus IPv6-loopback normalization. Removing the candidate leaves unrestricted SSRF; trimming does not create the trust-boundary defect. | beta.455 -> fixed beta.474 | **FAIL_NONCAUSAL_NORMALIZATION**. Existing `564cd836...` wrong-sink edge remains FAIL. |
| 3 | [CVE-2026-42201 / GHSA-f35h-g2c2-q36v](https://github.com/coollabsio/coolify/security/advisories/GHSA-f35h-g2c2-q36v) | `3d1b9f53a0ae...` (`e39678aea584...`) | member `03313e54cc79...`, compatibility follow-up `40a9881ef238...`, carrier `bff6d853708f...` | Candidate adds Docker **network-name** regex/escaping. Repair adds DB identifier/password patterns and applies them to credential fields interpolated into Compose commands. Sharing `ValidationPatterns.php` is not a shared mechanism. | beta.471 -> fixed beta.474 | **FAIL_DIFFERENT_FIELD_SHARED_HELPER**. |
| 4 | [CVE-2026-34599 / GHSA-q9j6-xcvx-px63](https://github.com/coollabsio/coolify/security/advisories/GHSA-q9j6-xcvx-px63) | `a0884b758f4d...` (`21429a26b1df...`); control `b33962bf8202...` (`8d212bc11062...`) | security member `48ba4ece3c1b...`, later hardening members, carrier `f267a28cb2ba...` | `a0884b...` changes one early-return condition so expanded service logs auto-load; its parent already exposes mutable public `$container` and client-callable `getLogs()` shell interpolation. Deleting it leaves the exploit reachable. `b33962...` only changes an import in `User.php`. | beta.453 / beta.461 -> fixed beta.471 | **FAIL_NON_NECESSARY_LIFECYCLE** plus **FAIL_UNRELATED_CONTROL**. Existing `bbb2aa9a...` PASS owns the one component; zero increment. |
| 5 | [CVE-2026-34152 / GHSA-5qp8-9gg7-4c86](https://github.com/coollabsio/coolify/security/advisories/GHSA-5qp8-9gg7-4c86) | `d59c75c2b23d...` (`a56fde7f124f...`) | member `6f163ddf0299...`, carrier `ad95d65aca06...` | Candidate adds `injectDockerComposeBuildArgs()` and modifies the Compose-build path. The parent already has separate `run_pre_deployment_command` / `run_post_deployment_command` heredoc transport. Fix normalizes CR/LF only in those pre/post commands. | beta.453 -> fixed beta.471 | **FAIL_DIFFERENT_COMMAND_PATH**. |
| 6 | [CVE-2026-34057 / GHSA-6r3g-w7x8-54fj](https://github.com/coollabsio/coolify/security/advisories/GHSA-6r3g-w7x8-54fj) | `cc96403cbe50...` (`9a4b4280be5a...`) | direct `d486bf09ab2d...` (`0fed55320738...`) | Candidate adds password confirmation arguments and boolean returns to existing import/restore methods. Parent already has client-hydratable server/container properties and the command path. Fix adds `#[Locked]`, team-scoped server lookup, and container validation. | beta.465 -> fixed beta.471 | **FAIL_MODAL_FLOW_PRESERVATION**. Prior different candidates remain `NEEDS_REVIEW`; this edge does not resolve them. |
| 7 | [CVE-2026-59734 / GHSA-4fhp-xqqp-w7vv](https://github.com/coollabsio/coolify/security/advisories/GHSA-4fhp-xqqp-w7vv) | `837391c31b18...` (`4e896cca05a3...`) | public exact squash `0ffcee7a4dcd...` (`38df6867183d...`) | Candidate changes Docker build-cache ARG/SOURCE_COMMIT behavior and Dockerfile injection. It does not change `generate_healthcheck_commands()` or its method/host/path values. Fix validates/escapes that distinct function. | beta.450 -> fixed beta.469 | **FAIL_DIFFERENT_FUNCTION_IN_LARGE_JOB**. |
| 8 | [CVE-2026-42204 / GHSA-chg4-63hm-xv9x](https://github.com/coollabsio/coolify/security/advisories/GHSA-chg4-63hm-xv9x) | `bf503861fcb6...` (`d59c75c2b23d...`) | member `817128c5affa...`, carrier `e1aac50b745c...` | Candidate only renders build args in a **preview** getter and landed beta.453. The vulnerable permissive shell rule was introduced later by already-counted `c9922c30...` in beta.471. Repair tokenizes that rule. Candidate neither writes the rule nor executes the sink. | beta.453; affected interval begins beta.471; fixed beta.474 | **FAIL_PREVIEW_ONLY_TEMPORAL_CONTROL**. Existing incomplete-remediation component owns the count. |
| 9 | [CVE-2026-42172 / GHSA-c83f-5ph7-x8xv](https://github.com/coollabsio/coolify/security/advisories/GHSA-c83f-5ph7-x8xv) | `729c891542df...` (`22153c419d4a...`) | member `90ddbb357231...`, carrier `b1a78df58efe...` | Candidate adds a placeholder Webhook notification channel. It does not create, persist, authenticate, or expire Sanctum tokens. Repair adds token expiry and warning jobs/UI. A shared notification trait is only a file bridge. | beta.435 -> fixed beta.474 | **FAIL_DIFFERENT_SECURITY_DOMAIN**. |
| 10 | [CVE-2026-42153 / GHSA-gvc4-f276-r88p](https://github.com/coollabsio/coolify/security/advisories/GHSA-gvc4-f276-r88p) | `cbba7f0a672e...` (`9e0fa03434d3...`) | security member `64753b413640...`, carrier `b74f54302b1a...` | Candidate adds collapsible GetLogs UI and touches database view files only to change log presentation. Repair converts PostgreSQL and sibling healthchecks to CMD exec-form. No healthcheck input, command construction, or execution delta exists in the candidate. | beta.453 -> fixed beta.474 | **FAIL_LOG_UI_DIFFERENT_SINK**. |
| 11 | [CVE-2026-34034 / GHSA-rpr8-p7jc-x844](https://github.com/coollabsio/coolify/security/advisories/GHSA-rpr8-p7jc-x844) | `511415770a43...` (`0cc597390157...`) | direct `096d4369e59b...` (`6fbb5e626a82...`) | Candidate adds a `disable_application_image_retention` boolean/cast and cleanup UI. It does not touch `sentinel_token`; fix validates/escapes that token at shell sinks. Same `ServerSetting` model is not a mechanism. | beta.453 -> fixed beta.466 | **FAIL_UNRELATED_MODEL_FIELD**. Current CVE-34034 origin verdict remains the V2 refactor-preservation FAIL. |

### Counts

```json
{
  "public_components_reviewed": 11,
  "ai_candidate_edges_reviewed": 12,
  "new_claim_grade_pass": 0,
  "fail": 11,
  "unknown_within_reviewed_rows": 0,
  "already_counted_components_touched_as_controls": 3,
  "unassessed_tail": "UNKNOWN"
}
```

Rows 2, 4, and 8 are the strongest rejected controls: respectively the same attacker-controlled field but noncausal normalization, the same vulnerable method but a non-necessary lifecycle change, and a same-UI preview commit that predates the actual regression. They demonstrate why file overlap, ancestry, release overlap, and an AI trailer cannot substitute for same-mechanism reversal.

## Exact commands and primary sources

```zsh
# Complete file inventory and immutable aggregate hashes.
rg --files scripts | rg '^scripts/cohort_coolify[^/]*\.(py|json)$' | sort
rg --files scripts/tests | rg '/test_cohort_coolify[^/]*\.py$' | sort
sha256sum <ordered-files> | sha256sum

# Conservative exclusion: every candidate/fix was matched by its first 8 hex
# characters against all seven docs, 88 Coolify sources, and 79 tests.
rg -q -- "${candidate[1,8]}" <all-exclusion-files>
rg -q -- "${fix[1,8]}" <all-exclusion-files>

# Topology, direct parent, atomic/member topology, and released containment.
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify \
  merge-base --is-ancestor <candidate> <public-fix>
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify rev-parse '<candidate>^'
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify \
  log --format='%H%x09%P%x09%s' '<carrier>^1..<carrier>^2' --reverse
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify \
  tag --contains <sha> 'v4.0.0-beta.*' | sort -V | head -1

# Claim-bearing evidence: direct candidate parent delta and exact fix/member delta.
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify \
  diff '<candidate>^' <candidate> -- <advisory-paths>
git -C /home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify \
  diff '<fix-member>^' <fix-member> -- <advisory-paths>

# Frozen first-party CNA identity, affected boundary, advisory and fix references.
jq '{id:.cveMetadata.cveId,state:.cveMetadata.state,title:.containers.cna.title,
     affected:.containers.cna.affected,references:.containers.cna.references}' \
  /home/hanqing/.cache/cve-analyzer/cvelistV5/cves/2026/{34xxx,42xxx,59xxx}/CVE-*.json
```

Exact CNA paths and SHA-256:

```text
4fe3992c82324d777fd6dc8d6784e30d67c6b8ff5bbf42802477078095b927b1  cves/2026/34xxx/CVE-2026-34153.json
ce2b917fbd7747e8a0a1144a3a1aae6ff45a416a88563ca8fec53b39e781db33  cves/2026/42xxx/CVE-2026-42147.json
a69fea62174951c6cd7cc5a17d8043ede57a9a365a70636338233ef5de38ed2b  cves/2026/42xxx/CVE-2026-42201.json
2a035e1dd8d2d71839a8dd2be4425ab416de052bebf7ec7b6b78a68afff5ab15  cves/2026/34xxx/CVE-2026-34599.json
dbddd5900e3576e74f3605bfbaeb5150e62b72de9b6ff495696112813ec5fb4c  cves/2026/34xxx/CVE-2026-34152.json
f5500b7a5b53efa56494bb1e5f0480488c88404cc3cf6006e43a4cc20ea61e71  cves/2026/34xxx/CVE-2026-34057.json
ee48c5e00f003f900df268ecd1f959283099c282b3a6cf4607788659aef4f848  cves/2026/59xxx/CVE-2026-59734.json
68e9c66f7d87ff955fa8aa2c6dff241014864d89154547f43363086004857a7f  cves/2026/42xxx/CVE-2026-42204.json
e34b1824835ce02b0c0472880d9d3aeda3dad29d3fcaadd8566d0feb140f90b9  cves/2026/42xxx/CVE-2026-42172.json
5d70335a0cca4a272ce2ae0842a1881b0b11a0aa4b51973775e17f4229eb7113  cves/2026/42xxx/CVE-2026-42153.json
b6b1f71b158b0293ea7ac7be0769a18e403fffe08ce9e872f237637bc4a7ffbd  cves/2026/34xxx/CVE-2026-34034.json
```

## Claim boundary and blockers

- The eleven `FAIL` findings are strong direct-diff exclusions. They do **not** say no AI-associated Coolify vulnerability exists elsewhere.
- The 42 fix-root and 556 AI-commit inventories were not rerun. Candidate generation, exact blame, same-file overlap, and model votes remain diagnostic.
- `RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md` says “the other 12 Coolify items” were excluded but does not map those twelve to candidate SHAs. The prefix-level manifest found none of the twelve candidate SHAs assessed here in the current docs/scripts/tests, but overlap with that unnamed prose group cannot be disproved; treat that mapping as `BLOCKED`, not a new count.
- No live GitHub advisory API call was made. Advisory identity/state and released containment are bound to the clean CVEList snapshot and clean Coolify tag snapshot above. Refresh before publication if those refs may have moved.
- The broad remaining tail is `UNKNOWN`; no negative inference should be made from it.
