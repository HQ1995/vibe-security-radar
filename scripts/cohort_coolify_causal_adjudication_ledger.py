#!/usr/bin/env python3
"""Build a recall-conserving Coolify causal-edge adjudication ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

from cohort.root_adjudication import canonical_sha256


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"

EVIDENCE_ARTIFACTS = {
    "upgrade_status": {
        "path": ".ai-slop/state/cohort-v1/coolify-upgrade-status-auth-witness-20260801-v1/witness.json",
        "sha256": "c73db46a2c0d596e493e28e6434105d3cfbd89355d239b1bef963fb4a4c0abf5",
    },
    "webhook_secret": {
        "path": ".ai-slop/state/cohort-v1/coolify-webhook-notification-secret-compositional-witness-20260801-v1/witness.json",
        "sha256": "df512978d887c6bb94d49296f847196875c50a3115b765173dc65a57f4dcaa09",
    },
    "hetzner_token": {
        "path": ".ai-slop/state/cohort-v1/coolify-hetzner-cloud-token-authorization-witness-20260801-v1/witness.json",
        "sha256": "ff96a814adb9bc51a9277b0fa42acfa2d66263e1bf4d6a66e696fb2adc5792e5",
    },
    "onboarding_idor": {
        "path": ".ai-slop/state/cohort-v1/coolify-onboarding-url-idor-path-extension-witness-20260801-v1/witness.json",
        "sha256": "73c0b049ca6e5790a531afcb0d711935e042cbdab9176e0f954bc0dfaa1bc509",
    },
    "postgresql_query_idor": {
        "path": ".ai-slop/state/cohort-v1/coolify-postgresql-query-idor-path-extension-witness-20260801-v1/witness.json",
        "sha256": "b49e6f658190316bdd635275a3727aa1aea777f55ac52e367a743b58d242ce84",
    },
    "authorization_path_recovery": {
        "path": ".ai-slop/state/cohort-v1/coolify-authorization-path-recovery-witness-20260801-v1/witness.json",
        "sha256": "ef354bf0aec75381033fba8e11efca08df5cd31f85e776ebfee3c519ef19a931",
    },
    "hetzner_link_path_extension": {
        "path": ".ai-slop/state/cohort-v1/coolify-hetzner-link-path-extension-witness-20260801-v1/witness.json",
        "sha256": "ac77259b447e058d60ad8fc60eaa19eed48002f17b050a3b3a0807948153a38d",
    },
    "dev_helper_action": {
        "path": ".ai-slop/state/cohort-v1/coolify-dev-helper-action-witness-20260801-v1/witness.json",
        "sha256": "74f246129f7d36fa7fa3d41a0e254bba60c5f3a8e63de22d2aaf59c44f1b138c",
    },
    "oauth_team_delete_path_extension": {
        "path": ".ai-slop/state/cohort-v1/coolify-oauth-team-delete-path-extension-witness-20260801-v1/witness.json",
        "sha256": "d7e95d24385970753db836988ec5456fbd8df3cd6eae69aa675d489a56d8afe6",
    },
    "oauth_guard_surface": {
        "path": ".ai-slop/state/cohort-v1/coolify-oauth-guard-surface-witness-20260801-v1/witness.json",
        "sha256": "7987f7ee8c2ff7dbfdd4fcf2cf212d6f649a948f4e4d4fce51a30ff7022c08a2",
    },
    "sentinel_command_injection": {
        "path": ".ai-slop/state/cohort-v1/coolify-sentinel-command-injection-witness-20260801-v2/witness.json",
        "sha256": "1ceef5d013163618146a284b63d209fe79af2b24b7d693aeba768a54cab3356d",
    },
    "fix_preimage_lineage_recovery": {
        "path": ".ai-slop/state/cohort-v1/coolify-lineage-recovery-witness-20260801-v1/witness.json",
        "sha256": "da3fc047bad93d15b07f6be75e7553dc1ea23aed09e2d3d0f4e933a1f75df2d2",
    },
    "cloud_token_helper_preservation": {
        "path": ".ai-slop/state/cohort-v1/coolify-cloud-token-helper-preservation-witness-20260801-v1/witness.json",
        "sha256": "a00bce7427466545f12e1947d64eceae712cbf0c1ae9f2292055dadd2816aff9",
    },
    "security_frontier_preservation": {
        "path": ".ai-slop/state/cohort-v1/coolify-security-frontier-preservation-witness-20260801-v3/witness.json",
        "sha256": "e3f57705fcb2d072f73bef6fa3d07c6dcc375e71067710098b117e4a0e350148",
    },
    "full_lineage_recovery": {
        "path": ".ai-slop/state/cohort-v1/coolify-full-lineage-recovery-witness-20260801-v1/witness.json",
        "sha256": "431c2f672e09bc12d04d694a3d0530cd3485baf25821582df00cab4d352236a6",
    },
    "exact_preimage_recovery": {
        "path": ".ai-slop/state/cohort-v1/coolify-exact-preimage-recovery-witness-20260801-v1/witness.json",
        "sha256": "2f9ab9533049737368e235deb2cccda5d8d894c50804008003a6cddecefe454e",
    },
    "github_install_state": {
        "path": ".ai-slop/state/cohort-v1/coolify-github-install-state-witness-20260801-v2/witness.json",
        "sha256": "af3b68b066bb28207e3aa878089d415d3b1015bbdb682b02728c35d60745eeea",
    },
    "github_install_maintenance_activation": {
        "path": ".ai-slop/state/cohort-v1/coolify-github-install-maintenance-activation-witness-20260801-v1/witness.json",
        "sha256": "30c0284b97411cf2ff323dde40259f13158b4c9c8f7a0be3b4160558cebcdd4d",
    },
    "onboarding_refresh_regression": {
        "path": ".ai-slop/state/cohort-v1/coolify-onboarding-refresh-regression-witness-20260801-v1/witness.json",
        "sha256": "ff1455594a8c4a7132183c1b0ae71f6aa5ad987791b90d45435a32261c473583",
    },
    "sensitive_model_defaults": {
        "path": ".ai-slop/state/cohort-v1/coolify-sensitive-model-defaults-witness-20260801-v1/witness.json",
        "sha256": "d8d3f09e2c7dca94adc024bdc6cb2062562556879b36cf790e01e12ac3172e4f",
    },
    "volume_shell_hardening": {
        "path": ".ai-slop/state/cohort-v1/coolify-volume-shell-hardening-witness-20260801-v1/witness.json",
        "sha256": "c95da27ef8a766a95dd7be3106358d00c37e0559ea7305a97ab42e23482c6337",
    },
    "volume_parser_preservation": {
        "path": ".ai-slop/state/cohort-v1/coolify-volume-parser-preservation-witness-20260801-v1/witness.json",
        "sha256": "b8eaa50064213af417aac9e90c5f4a0a1f542281b3e82ad5b28ece0eadee941f",
    },
    "datalist_binding_origin": {
        "path": ".ai-slop/state/cohort-v1/coolify-datalist-binding-origin-witness-20260801-v2/witness.json",
        "sha256": "5a039e98336e282893bf3bb4b35eaa352ca3b9a8e5ba426db9b70c2b5014d3e0",
    },
    "onboarding_creation_path": {
        "path": ".ai-slop/state/cohort-v1/coolify-onboarding-creation-path-witness-20260801-v1/witness.json",
        "sha256": "380dbdad5dc8bedcc2f68bbf1ef4ea327433d3c885c81a00a37c33f1aa801460",
    },
    "oauth_bulk_mutation_preservation": {
        "path": ".ai-slop/state/cohort-v1/coolify-oauth-bulk-mutation-preservation-witness-20260801-v2/witness.json",
        "sha256": "c18727985da83e09779f92aed7ba7178b856b4e63a6e891f6540d5f6fe302388",
    },
    "private_key_hydration_preservation": {
        "path": ".ai-slop/state/cohort-v1/coolify-private-key-hydration-preservation-witness-20260801-v1/witness.json",
        "sha256": "81330c8b5546ce30cd5fbf24499236c0c8c8ada11c8a159978656ae858626141",
    },
    "wire_navigate_authorization": {
        "path": ".ai-slop/state/cohort-v1/coolify-wire-navigate-authorization-witness-20260801-v1/witness.json",
        "sha256": "dd580dcc96da25fe1cd2c4dc15a6b39bf0a9f8cc412af94c4928e574c74f605c",
    },
    "project_scope_hardening": {
        "path": ".ai-slop/state/cohort-v1/coolify-project-scope-hardening-witness-20260801-v1/witness.json",
        "sha256": "2195407e98498d6d165b9edc985c4105b82b34ae6a4297ff7e3494528d12fd72",
    },
    "sentinel_restart_activation": {
        "path": ".ai-slop/state/cohort-v1/coolify-sentinel-restart-activation-witness-20260801-v1/witness.json",
        "sha256": "a465d560e412ba927fee547f82b6652157d2cdcd8e2f9b71ac4cf2d528f3e789",
    },
    "sentinel_activation_carrier": {
        "path": ".ai-slop/state/cohort-v1/coolify-sentinel-activation-carrier-witness-20260801-v2/witness.json",
        "sha256": "f47af14e439c1882ce7bc056170607318efc5ea29542ab3a0bfec688fa446b5e",
    },
    "api_token_permission_preservation": {
        "path": ".ai-slop/state/cohort-v1/coolify-api-token-permission-preservation-witness-20260801-v1/witness.json",
        "sha256": "e83ad9da8d2746c0d8df39fb18ef1544047c7a94435839a89ecb34f025622bd9",
    },
    "cloud_settings_path_extension": {
        "path": ".ai-slop/state/cohort-v1/coolify-cloud-settings-path-extension-witness-20260801-v1/witness.json",
        "sha256": "d60e3776218b664a21eda8cc1abc89b63a80f9e0333287bbdb611c2948b67355",
    },
    "sentinel_instant_save_path": {
        "path": ".ai-slop/state/cohort-v1/coolify-sentinel-instant-save-path-witness-20260801-v1/witness.json",
        "sha256": "a4dc37fde89cf2f8dcf2afc45dd1f2c038d182402043714353acbbf4d41e367c",
    },
    "backup_upload_validation": {
        "path": ".ai-slop/state/cohort-v1/coolify-backup-upload-validation-witness-20260801-v1/witness.json",
        "sha256": "b76c9a7d02ab34d479f4acd6f903b72d86c4716c99dce285f9d558e22fbbc218",
    },
    "git_ls_remote_incomplete_hardening": {
        "path": ".ai-slop/state/cohort-v1/coolify-git-ls-remote-incomplete-hardening-witness-20260801-v1/witness.json",
        "sha256": "ade39464c7a05290bec61d19c356aadecba4a503f87122ef539765b8decfcd0d",
    },
    "s3_restore_command_injection": {
        "path": ".ai-slop/state/cohort-v1/coolify-s3-restore-command-injection-witness-20260801-v1/witness.json",
        "sha256": "f0a6a96682ac676c90e9d391a537ffb68942d1799c0d73f001de4aece0a22c37",
    },
    "preimage_recovery_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-preimage-recovery-batch-witness-20260801-v1/witness.json",
        "sha256": "00316cb4cf35fd4c290bf9bbbabf0d55943d00bd35c57a26b96737f5daa1916d",
    },
    "exact_delta_causal_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-exact-delta-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "81b3f03655320ade97de7d56f5e567420bc90f6cc8c32c56e91476dda7be6e27",
    },
    "exact_delta_causal_batch2": {
        "path": ".ai-slop/state/cohort-v1/coolify-exact-delta-causal-batch2-witness-20260801-v1/witness.json",
        "sha256": "d7ea487d29a6f0ef6976eb3db5fccebff6d96e5e58fcfc8c266646ff7864a810",
    },
    "repair_action_exact_delta_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-exact-delta-repair-action-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "e4a1ba71d631339ca8e50470a22d31609403a00c580958eb1de95952ec344b88",
    },
    "merge_repair_exact_delta_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-exact-delta-merge-repair-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "d7d43af3f390f0154332bdacd49fe72ec089e520afffec3beff10d038048808d",
    },
    "test_change_exact_delta_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-exact-delta-test-change-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "d1cffe722bbe867377ca38834bbe1753c10cd26f4346568996eeb96fb5c5993b",
    },
    "direct_fallback_exact_delta_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-exact-delta-direct-fallback-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "ca3eac2ff6c6a0e67e4ea40ed5f559355505ad8a142bcf332fc1aa97f0b10dc8",
    },
    "topology_carrier_causal_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-topology-carrier-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "0cba57e486c2f68c791dbd361e46cb3d427e5d15e136069970ae6911d09c7c3f",
    },
    "merge_member_causal_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-merge-member-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "083f763765ee4e05ea3c40fddf215f4cc1ac340ebccbae75440fbb5dabacf733",
    },
    "merge_member_causal_batch2": {
        "path": ".ai-slop/state/cohort-v1/coolify-merge-member-causal-batch-witness-20260801-v2/witness.json",
        "sha256": "3e8facf30272b318bb6309a4206c05330477c7fc2c09e8cff5de0bc6d176f64b",
    },
    "merge_member_causal_batch3": {
        "path": ".ai-slop/state/cohort-v1/coolify-merge-member-causal-batch-witness-20260801-v4/witness.json",
        "sha256": "15a14772d8c3e834fc7954e4e9e67a4496572d46b0721ba20af72195288951ad",
    },
    "conductor_trust_hosts_origin": {
        "path": ".ai-slop/state/cohort-v1/coolify-conductor-trust-hosts-origin-witness-20260801-v1/witness.json",
        "sha256": "5ae5ba571b4c599e60796c4f8030f65e988d512bf5115e0d256218e7c8653bee",
    },
    "conductor_exact_delta_causal_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-conductor-exact-delta-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "018e18f8f86864aa73fd3416894b62820aad2d47e8dd049c2ab9ff92a5115afd",
    },
    "conductor_healthcheck_reset_origin": {
        "path": ".ai-slop/state/cohort-v1/coolify-conductor-healthcheck-reset-origin-witness-20260801-v1/witness.json",
        "sha256": "4c2c6221945b092be6133d8289dbac7824c04e896109c6fde0c911a24781587d",
    },
    "github_sensitive_read_causal": {
        "path": ".ai-slop/state/cohort-v1/coolify-github-sensitive-read-causal-witness-20260801-v1/witness.json",
        "sha256": "c3802cacce6cb29af9faf5444e97cae3856b46646e28a1df2a6a47a3dff25992",
    },
    "symbol_contract_method_migration": {
        "path": ".ai-slop/state/cohort-v1/coolify-symbol-contract-method-migration-witness-20260801-v1/witness.json",
        "sha256": "452ddc54fbeff5bf91ae897eb6b0be633bcb53788f781742ff7befd326e71dbb",
    },
    "conductor_form_onboarding_attribution": {
        "path": ".ai-slop/state/cohort-v1/coolify-conductor-form-onboarding-attribution-witness-20260801-v1/witness.json",
        "sha256": "46d35eb7aecfaeec34171c637ba92df6bf7231bdc90a61eda5e11e55502367e0",
    },
    "deployment_rollback_causal_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-deployment-rollback-causal-batch-witness-20260801-v1/witness.json",
        "sha256": "56d54a23550fd0298a593ca268a2f2a1c20458e228f02d7188194b5cb1488260",
    },
    "activity_monitor_target_key": {
        "path": ".ai-slop/state/cohort-v1/coolify-activity-monitor-target-key-causal-witness-20260801-v1/witness.json",
        "sha256": "a455dccfceb0a7529231127dbf296276404e1bb30a0ded52d2eb73c9d8fcc90d",
    },
    "trust_hosts_negative_cache_origin": {
        "path": ".ai-slop/state/cohort-v1/coolify-trust-hosts-negative-cache-origin-witness-20260801-v1/witness.json",
        "sha256": "9cd0b0bbd83dbb91edb24171c7b79da0c31976090401541a829e62600065c949",
    },
    "modal_wire_ignore_causal": {
        "path": ".ai-slop/state/cohort-v1/coolify-modal-wire-ignore-causal-witness-20260801-v1/witness.json",
        "sha256": "9244ee512446eee3ae0ad643eb3cffe3faba659006e781916a80c0093d2e623e",
    },
    "update_compose_map_style_origin": {
        "path": ".ai-slop/state/cohort-v1/coolify-update-compose-map-style-origin-witness-20260803-v1/witness.json",
        "sha256": "776e796282600fbf9217df1e7e4c6934ed86f836e95271bca9b21df3cf6afb57",
    },
    "dev_compose_pull_policy": {
        "path": ".ai-slop/state/cohort-v1/coolify-dev-compose-pull-policy-witness-20260803-v1/witness.json",
        "sha256": "696c4477a2f68dc44b48252fdfb4c3f8b6fa52f030d8baacb739c210aa6154d1",
    },
    "conductor_datalist_revert_attribution": {
        "path": ".ai-slop/state/cohort-v1/coolify-conductor-datalist-revert-attribution-witness-20260801-v1/witness.json",
        "sha256": "f7e297a1361415cab8c70e69efd67ed365c2ab3c4f9f15ecdb65c7351ae46fb1",
    },
    "token_metrics_causal_batch": {
        "path": ".ai-slop/state/cohort-v1/coolify-token-metrics-causal-batch-witness-20260803-v1/witness.json",
        "sha256": "807a2b5c75f00e6761ed46a507c63fa47901c1a04dfe47b62d6e7b96264b624d",
    },
    "buildtime_env_duplicate_reattribution": {
        "path": ".ai-slop/state/cohort-v1/coolify-buildtime-env-duplicate-reattribution-witness-20260801-v1/witness.json",
        "sha256": "15c32cc8405fb9133c58f508693b89a1027a4ae7856ecf31e18162a626bbd07d",
    },
    "upgrade_shutdown_order": {
        "path": ".ai-slop/state/cohort-v1/coolify-upgrade-shutdown-order-witness-20260803-v1/witness.json",
        "sha256": "042b5e13f1231bfa289a7ba8fe8c1e09527fde1b93448289adf9945582566222",
    },
    "concurrent_index_migration_transaction_contract": {
        "path": ".ai-slop/state/cohort-v1/coolify-concurrent-index-migration-transaction-contract-witness-20260803-v1/witness.json",
        "sha256": "32f8401a16e00fd0f91839d22a3f52d88c330ccdcbc5920202bec410ea8542b6",
    },
    "global_search_new_image_origin": {
        "path": ".ai-slop/state/cohort-v1/coolify-global-search-new-image-origin-witness-20260801-v1/witness.json",
        "sha256": "f05191e10e4f12a9e1be1286fd7f201c68407835a59f67e135ed1ad90022fc45",
    },
    "readonly_volume_path_normalization": {
        "path": ".ai-slop/state/cohort-v1/coolify-readonly-volume-path-normalization-witness-20260803-v1/witness.json",
        "sha256": "ae96e3cac7b9183473b0eca0e586ec3b1abb36f4bfbf52e1fe240927abb34784",
    },
    "noncausal_candidates": {
        "path": ".ai-slop/state/cohort-v1/coolify-noncausal-ai-candidate-witness-20260801-v1/witness.json",
        "sha256": "a2a0931184de2263abe668f1853feb13a9dceae615c013aa7ac27db4ce25c560",
    },
}

CONFIRMED_EDGES = {
    (
        "b8cfc3f7c911661efae919c7b3cb9e7d8de8dcca",
        "3cc416a8069eed98bb342c09700a6e5084444a94",
    ): ("CONFIRMED_DIRECT_AI_ORIGIN", "upgrade_status", "upgrade_status_auth"),
    (
        "dc9f612df47f2c426cbcd4e80b6ace347ead6edc",
        "3cc416a8069eed98bb342c09700a6e5084444a94",
    ): (
        "CONFIRMED_AI_PRESERVATION_CONTRIBUTOR",
        "upgrade_status",
        "upgrade_status_auth",
    ),
    (
        "27879377a07a88d2070a2939b2856cd0273eac52",
        "5973bb4d4f3c236d76ac25cb77c22e5317d5379f",
    ): ("CONFIRMED_LATENT_AI_ORIGIN", "webhook_secret", "webhook_secret_exposure"),
    (
        "0303f529d310df25eece67ee6a5d01a2e8efcf9d",
        "5973bb4d4f3c236d76ac25cb77c22e5317d5379f",
    ): (
        "CONFIRMED_AI_UI_PRESERVATION_CONTRIBUTOR",
        "webhook_secret",
        "webhook_secret_exposure",
    ),
    (
        "eea372d702fae8b99574dd2e690db21634348676",
        "5973bb4d4f3c236d76ac25cb77c22e5317d5379f",
    ): (
        "CONFIRMED_AI_POLICY_WIRING_CONTRIBUTOR",
        "webhook_secret",
        "webhook_secret_exposure",
    ),
    (
        "62c394d3a1dba6aa6d4ab1456b7a7911f6b72639",
        "062ad5774041fb3be71abedcff33c4315613152c",
    ): ("CONFIRMED_DIRECT_AI_ORIGIN", "hetzner_token", "hetzner_token_authorization"),
    (
        "7a008c859ad68332de72683ddb751e40a6487c38",
        "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
    ): (
        "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "onboarding_idor",
        "ghsa_qfcc_cross_team_idor",
    ),
    (
        "679833a0a6a2799d2086e0965dade0703587c3c5",
        "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
    ): (
        "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "postgresql_query_idor",
        "ghsa_qfcc_cross_team_idor",
    ),
    (
        "a980fd460a2ef7ce7766171d034a8c645322299b",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_ORIGIN",
        "authorization_path_recovery",
        "deployment_hidden_log_export",
    ),
    (
        "78031b991ac3d1fa8579ef9256ef0e43d79a79b7",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "authorization_path_recovery",
        "shown_once_environment_value_exposure",
    ),
    (
        "67b1db925460d21351babd9896b12de2b837879b",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "hetzner_link_path_extension",
        "hetzner_power_control_authorization",
    ),
    (
        "18f30b7fabc54938a031867ad34c39a1e9c7c0d7",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "CONFIRMED_DIRECT_AI_SENSITIVE_ACTION_ORIGIN",
        "dev_helper_action",
        "livewire_sensitive_action_authorization",
    ),
    (
        "b0d50669b1b8929b3c82ee4103fb3d1f2a1b0bf1",
        "94dfd6a54ec274f525766a97892852fb275b3401",
    ): (
        "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "oauth_team_delete_path_extension",
        "team_delete_authorization",
    ),
    (
        "b0d50669b1b8929b3c82ee4103fb3d1f2a1b0bf1",
        "86b05b902aedbbb074e73bfe233b3ed006f19b39",
    ): (
        "CONFIRMED_DIRECT_AI_OAUTH_DESTRUCTIVE_PATH_EXTENSION",
        "oauth_guard_surface",
        "oauth_destination_remove_server_authorization",
    ),
    (
        "9675d74360c9057fe78682dccc263580b870904e",
        "096d4369e59b3db7ace2db3ca42588c41b9b6019",
    ): (
        "CONFIRMED_AI_UI_PRESERVATION_CONTRIBUTOR",
        "sentinel_command_injection",
        "sentinel_token_command_injection",
    ),
    (
        "a8aa4524751d1530031f6134d49474d254bbab72",
        "096d4369e59b3db7ace2db3ca42588c41b9b6019",
    ): (
        "CONFIRMED_AI_SHELL_SINK_PRESERVATION_CONTRIBUTOR",
        "sentinel_command_injection",
        "sentinel_token_command_injection",
    ),
    (
        "769d2eca35e4aa01bb5cfcf14c583007efdfd6e8",
        "5973bb4d4f3c236d76ac25cb77c22e5317d5379f",
    ): (
        "CONFIRMED_AI_UI_PRESERVATION_CONTRIBUTOR",
        "fix_preimage_lineage_recovery",
        "webhook_secret_exposure",
    ),
    (
        "ef0a1241b0e8ac64252a108e468d492b84573b56",
        "062ad5774041fb3be71abedcff33c4315613152c",
    ): (
        "CONFIRMED_AI_REACHABILITY_PATH_EXTENSION",
        "fix_preimage_lineage_recovery",
        "hetzner_token_authorization",
    ),
    (
        "62c394d3a1dba6aa6d4ab1456b7a7911f6b72639",
        "86b05b902aedbbb074e73bfe233b3ed006f19b39",
    ): (
        "CONFIRMED_DIRECT_AI_ROLE_AUTHORIZATION_ORIGIN",
        "fix_preimage_lineage_recovery",
        "cloud_provider_api_role_authorization",
    ),
    (
        "596b1cb76ecb1a8e3a295f25672586c49dbf71d0",
        "062ad5774041fb3be71abedcff33c4315613152c",
    ): (
        "CONFIRMED_AI_DATAFLOW_PRESERVATION_CONTRIBUTOR",
        "cloud_token_helper_preservation",
        "hetzner_token_authorization",
    ),
    (
        "596b1cb76ecb1a8e3a295f25672586c49dbf71d0",
        "86b05b902aedbbb074e73bfe233b3ed006f19b39",
    ): (
        "CONFIRMED_AI_MUTATION_PATH_PRESERVATION_CONTRIBUTOR",
        "cloud_token_helper_preservation",
        "cloud_provider_api_role_authorization",
    ),
    (
        "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
        "a1c30cb0e70b84e075d1c444362e7b198ad459e3",
    ): (
        "CONFIRMED_AI_GIT_REF_DATAFLOW_PRESERVATION_CONTRIBUTOR",
        "security_frontier_preservation",
        "git_ref_command_injection",
    ),
    (
        "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
        "23f9156c7306b221101f1ebbe4d3c6b5e2522acd",
    ): (
        "CONFIRMED_AI_SHELL_INPUT_DATAFLOW_PRESERVATION_CONTRIBUTOR",
        "security_frontier_preservation",
        "application_setting_command_injection",
    ),
    (
        "8714d9bd0332a29275750f2f58fab043df2d677a",
        "23f9156c7306b221101f1ebbe4d3c6b5e2522acd",
    ): (
        "CONFIRMED_AI_PATH_NORMALIZATION_PRESERVATION_CONTRIBUTOR",
        "security_frontier_preservation",
        "application_setting_command_injection",
    ),
    (
        "1499135409818334b18002af916d8b12babce712",
        "23f9156c7306b221101f1ebbe4d3c6b5e2522acd",
    ): (
        "CONFIRMED_AI_INCOMPLETE_PATH_VALIDATION_CONTRIBUTOR",
        "security_frontier_preservation",
        "application_setting_command_injection",
    ),
    (
        "dae680317385f2a495b0ae2b1687d2ce8f555256",
        "23f9156c7306b221101f1ebbe4d3c6b5e2522acd",
    ): (
        "CONFIRMED_AI_POST_EXECUTION_PATH_RESTORE_CONTRIBUTOR",
        "security_frontier_preservation",
        "application_setting_command_injection",
    ),
    (
        "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
        "410a9a6195a2b939d4a429f6c464ff56e61177f8",
    ): (
        "CONFIRMED_AI_VOLUME_INPUT_DATAFLOW_PRESERVATION_CONTRIBUTOR",
        "security_frontier_preservation",
        "persistent_volume_command_injection",
    ),
    (
        "59111e8cf35824b691790cc018d76d2c5a331793",
        "f44ace3965167a62a4e7169c87f7b1edcfa9ba72",
    ): (
        "CONFIRMED_AI_INCOMPLETE_RESOURCE_PAIRING_FIX",
        "security_frontier_preservation",
        "destination_network_server_pairing",
    ),
    (
        "cb1f571eb4b36da153d559246534f75683117299",
        "97868c32640a9875f1f6f0e4d215d2ad6655e65a",
    ): (
        "CONFIRMED_AI_OVERRESTRICTIVE_ENV_DEFAULT_VALIDATION",
        "full_lineage_recovery",
        "docker_compose_volume_validation_underacceptance",
    ),
    (
        "cb1f571eb4b36da153d559246534f75683117299",
        "468d5fe7d77dfe1f1f34770a81e45062c272c92d",
    ): (
        "CONFIRMED_AI_OVERRESTRICTIVE_ENV_PATH_VALIDATION",
        "full_lineage_recovery",
        "docker_compose_volume_validation_underacceptance",
    ),
    (
        "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
        "468d5fe7d77dfe1f1f34770a81e45062c272c92d",
    ): (
        "CONFIRMED_AI_NULLABLE_COMPOSE_CONTRACT_REGRESSION",
        "full_lineage_recovery",
        "livewire_stack_form_nullable_contract",
    ),
    (
        "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
        "30c0b37689801707c791d2f725773bfb14072bb2",
    ): (
        "CONFIRMED_AI_HEALTHCHECK_INPUT_DATAFLOW_PRESERVATION_CONTRIBUTOR",
        "full_lineage_recovery",
        "healthcheck_command_injection",
    ),
    (
        "7a008c859ad68332de72683ddb751e40a6487c38",
        "188c86ca45801c7ea2c4a8022b9ed90d73c1068e",
    ): (
        "CONFIRMED_AI_BROAD_SSH_KEY_SELECTION_PRESERVATION_CONTRIBUTOR",
        "full_lineage_recovery",
        "onboarding_ssh_key_scope",
    ),
    (
        "1094ab7a46452ac0e42e60e5c1e705df6484f95f",
        "2eeb2b94ec3385fcd066cf43e9c8c108be7cdeea",
    ): (
        "CONFIRMED_AI_GLOBAL_DOCKER_COMPOSE_REWRITE_REGRESSION",
        "exact_preimage_recovery",
        "docker_compose_custom_command_rewrite_scope",
    ),
    (
        "f8e3bb54a3cb48da842351cc75490c8a20134807",
        "f86ccfaa9af572a5487da8ea46b0a125a4854cf6",
    ): (
        "CONFIRMED_AI_GLOBAL_DOCKER_COMPOSE_REWRITE_REGRESSION",
        "exact_preimage_recovery",
        "docker_compose_custom_command_rewrite_scope",
    ),
    (
        "bf0040597194e3a9b835b7a800b735f65bc2c34c",
        "893093fad3cb6a54fa28be7da6991654460153fa",
    ): (
        "CONFIRMED_AI_UNBOUNDED_GIT_SHA_REGEX_REGRESSION",
        "exact_preimage_recovery",
        "git_ls_remote_sha_extraction",
    ),
    (
        "5a7408a919e1128e75f23c2598926814685928f6",
        "858b1906ec34e76950262e18135c0ecc5d22eb15",
    ): (
        "CONFIRMED_AI_INCOMPLETE_GITHUB_INSTALL_STATE_BINDING",
        "github_install_state",
        "github_app_install_callback_state_binding",
    ),
    (
        "158d54712f4ed212750f0b1da6d98d761bd97454",
        "5a7408a919e1128e75f23c2598926814685928f6",
    ): (
        "CONFIRMED_AI_MAINTENANCE_STATE_REACHABILITY_EXTENSION",
        "github_install_maintenance_activation",
        "github_app_install_callback_state_binding",
    ),
    (
        "7a008c859ad68332de72683ddb751e40a6487c38",
        "04625591eaafac64db412b21b0f4c4c0f82fc8ad",
    ): (
        "CONFIRMED_AI_INCOMPLETE_ONBOARDING_URL_STATE_RESTORATION",
        "onboarding_refresh_regression",
        "onboarding_project_refresh_state",
    ),
    (
        "27879377a07a88d2070a2939b2856cd0273eac52",
        "81a3bb0f0769e5a765e77649d002ea6acf9a667f",
    ): (
        "CONFIRMED_AI_SENSITIVE_MODEL_DEFAULT_SERIALIZATION_ORIGIN",
        "sensitive_model_defaults",
        "api_sensitive_model_default_serialization",
    ),
    (
        "7061eacfa506f92a8868c531fa52533e3563adc6",
        "81a3bb0f0769e5a765e77649d002ea6acf9a667f",
    ): (
        "CONFIRMED_AI_SENSITIVE_MODEL_DEFAULT_SERIALIZATION_ORIGIN",
        "sensitive_model_defaults",
        "api_sensitive_model_default_serialization",
    ),
    (
        "9f46586d4aaa93f2b526d67833ba70ef58b9893e",
        "81a3bb0f0769e5a765e77649d002ea6acf9a667f",
    ): (
        "CONFIRMED_AI_INCOMPLETE_TELEGRAM_FIELD_SCHEMA_SYNC",
        "sensitive_model_defaults",
        "telegram_docker_cleanup_thread_id_encryption",
    ),
    (
        "d2064dd4998694cda2eabd00149f7c4d1e94c699",
        "410a9a6195a2b939d4a429f6c464ff56e61177f8",
    ): (
        "CONFIRMED_AI_INCOMPLETE_VOLUME_SHELL_HARDENING",
        "volume_shell_hardening",
        "compose_preview_volume_network_cleanup_shell_escape",
    ),
    (
        "a219f2e80e42c14d5d59a3e6816fcb91b771e4a9",
        "468d5fe7d77dfe1f1f34770a81e45062c272c92d",
    ): (
        "CONFIRMED_AI_CANONICAL_VOLUME_VALIDATION_PRESERVATION_CONTRIBUTOR",
        "volume_parser_preservation",
        "docker_compose_volume_validation_underacceptance",
    ),
    (
        "6297ac6c88a712b8e867d6442ea81aa7abc8cb73",
        "188c86ca45801c7ea2c4a8022b9ed90d73c1068e",
    ): (
        "CONFIRMED_AI_SINGLE_SELECT_DATALIST_BINDING_ORIGIN",
        "datalist_binding_origin",
        "form_datalist_single_select_reactivity",
    ),
    (
        "04625591eaafac64db412b21b0f4c4c0f82fc8ad",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "CONFIRMED_AI_ONBOARDING_RESOURCE_CREATION_PATH_EXTENSION",
        "onboarding_creation_path",
        "onboarding_resource_creation_authorization",
    ),
    (
        "b1a68df65caef6df06c9495a817ff4c340a44d39",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "CONFIRMED_AI_OAUTH_BULK_MUTATION_PRESERVATION_CONTRIBUTOR",
        "oauth_bulk_mutation_preservation",
        "oauth_bulk_settings_mutation_authorization",
    ),
    (
        "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
        "f7427fdea03ccd0da20ddce590c6eb6fd2119fd9",
    ): (
        "CONFIRMED_AI_PRIVATE_KEY_HYDRATION_PRESERVATION_CONTRIBUTOR",
        "private_key_hydration_preservation",
        "private_key_secret_view_authorization",
    ),
    (
        "e709e2c131aeebb9a1121437ce5e1ec4c2fc2f0b",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "wire_navigate_authorization",
        "instance_wire_navigate_setting_authorization",
    ),
    (
        "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
        "3ba4553df5657582ad720a6572d83383fe89c078",
    ): (
        "CONFIRMED_AI_TEAM_SCOPE_NULL_HANDLING_REGRESSION",
        "project_scope_hardening",
        "onboarding_team_scoped_project_null_transition",
    ),
    (
        "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
        "a478ac66eb7037837c178d64006f83a13eca12d2",
    ): (
        "CONFIRMED_AI_INCOMPLETE_RESOURCE_SCOPE_HARDENING",
        "project_scope_hardening",
        "resource_creation_destination_team_scope",
    ),
    (
        "728f261316f2af904f755756d687a722d2967223",
        "096d4369e59b3db7ace2db3ca42588c41b9b6019",
    ): (
        "CONFIRMED_AI_SHELL_TRIGGER_ACTIVATION_CONTRIBUTOR",
        "sentinel_activation_carrier",
        "sentinel_setting_updated_restart_command_injection",
    ),
    (
        "90ddbb357231ca3808f277eb87a63c8f650417e6",
        "7f135e0f6d87a6065a67b78b8a9976dfd99f3a2a",
    ): (
        "CONFIRMED_AI_TOKEN_ISSUANCE_SINK_PRESERVATION_CONTRIBUTOR",
        "api_token_permission_preservation",
        "api_token_mutable_permission_issuance",
    ),
    (
        "acff543e09ae5c7f8da78e5a092ebb1e57f24dc0",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "CONFIRMED_DIRECT_AI_CLOUD_SETTINGS_AUTHORIZATION_PATH_EXTENSION",
        "cloud_settings_path_extension",
        "cloud_instance_settings_updates_authorization",
    ),
    (
        "f995426fb32d810577dad5d46f275cc4a6e5c38d",
        "096d4369e59b3db7ace2db3ca42588c41b9b6019",
    ): (
        "CONFIRMED_DIRECT_AI_SHELL_TRIGGER_PATH_EXTENSION",
        "sentinel_instant_save_path",
        "sentinel_instant_save_restart_command_injection",
    ),
    (
        "af0a8badb3cd9f470cb55c5f714263f63425d40b",
        "2d63d51237c34db29cc9d8dacd81400483f0eb27",
    ): (
        "CONFIRMED_AI_INCOMPLETE_BACKUP_UPLOAD_FILE_TYPE_VALIDATION",
        "backup_upload_validation",
        "database_backup_upload_validation",
    ),
    (
        "b81baff4b178b8264a9ae4ab704f7902c841fa1b",
        "8f8c90b7ae8da113c63315c2e5b6f1bf81da1964",
    ): (
        "CONFIRMED_AI_INCOMPLETE_GIT_LS_REMOTE_BRANCH_COVERAGE",
        "git_ls_remote_incomplete_hardening",
        "git_ls_remote_deployment_type_coverage",
    ),
    (
        "b81baff4b178b8264a9ae4ab704f7902c841fa1b",
        "992b922df35b6f7d57be8c664a3d51b1207854cd",
    ): (
        "CONFIRMED_AI_INCOMPLETE_NESTED_SHELL_ESCAPING",
        "git_ls_remote_incomplete_hardening",
        "nested_execute_in_docker_shell_quoting",
    ),
    (
        "8f8c90b7ae8da113c63315c2e5b6f1bf81da1964",
        "992b922df35b6f7d57be8c664a3d51b1207854cd",
    ): (
        "CONFIRMED_AI_INCOMPLETE_NESTED_SHELL_ESCAPING",
        "git_ls_remote_incomplete_hardening",
        "nested_execute_in_docker_shell_quoting",
    ),
    (
        "94560ea6c7a841840638e7c73a4b5d6da2afe713",
        "9113ed714f46d836bbc6389287f40dc4e2064f9f",
    ): (
        "CONFIRMED_AI_INCOMPLETE_S3_RESTORE_SHELL_HARDENING",
        "s3_restore_command_injection",
        "s3_restore_bucket_path_command_injection",
    ),
    (
        "336fa0c7143a8ceca319dc1e7b6f12ca2b923708",
        "fb2d477e48764d7dd9139db13ef26f7eb7809221",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_AUTHORIZATION_REPAIR",
        "preimage_recovery_batch",
        "team_policy_target_team_context",
    ),
    (
        "90ddbb357231ca3808f277eb87a63c8f650417e6",
        "3911a0305c0177c5bb77659883b3c59709004570",
    ): (
        "CONFIRMED_DIRECT_AI_FUNCTIONAL_REGRESSION",
        "preimage_recovery_batch",
        "api_token_expiration_warning_persistence",
    ),
    (
        "0fce7fa9481aa1bcca06d767075684a11e032c79",
        "c7f014017b753a53e33a4eb7d2950f7302d971b5",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_SECURITY_HARDENING",
        "preimage_recovery_batch",
        "outbound_url_multi_address_validation",
    ),
    (
        "564cd8368bb8b4485b3981060dace37645b20f52",
        "c7f014017b753a53e33a4eb7d2950f7302d971b5",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_SECURITY_HARDENING",
        "preimage_recovery_batch",
        "webhook_dns_resolution_validation",
    ),
    (
        "413dee5d8c97edefd4b359831d6db766b1235c9c",
        "0b8c75f8edb12bc9084c1b6cd844643d7ae95701",
    ): (
        "CONFIRMED_DIRECT_AI_VULNERABLE_SINK_ORIGIN",
        "preimage_recovery_batch",
        "webhook_runtime_url_validation",
    ),
    (
        "945cce95870b2f18b13f8f509677ad3823d2b97f",
        "c8a332a3bc935064dcbb2f7703b1edeb2becfaae",
    ): (
        "CONFIRMED_DIRECT_AI_FUNCTIONAL_REGRESSION",
        "preimage_recovery_batch",
        "orphan_cleanup_placeholder_server_filter",
    ),
    (
        "cdf6b5f1611369762406290fa05d11e60206630a",
        "c6c7ec1c317883fc0967f911ac4d6d47f83ab069",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_INPUT_VALIDATION",
        "preimage_recovery_batch",
        "preview_compose_domain_validation",
    ),
    (
        "62c394d3a1dba6aa6d4ab1456b7a7911f6b72639",
        "a8000ac2ad2fa0882223b8360028e21e9aaa6ad4",
    ): (
        "CONFIRMED_DIRECT_AI_MISSING_INPUT_CONSTRAINT",
        "preimage_recovery_batch",
        "hetzner_public_ip_protocol_validation",
    ),
    (
        "62c394d3a1dba6aa6d4ab1456b7a7911f6b72639",
        "4d836888964ee5a1bea7089d3fe6c886012f0bff",
    ): (
        "CONFIRMED_DIRECT_AI_EXCEPTION_DISCLOSURE_ORIGIN",
        "preimage_recovery_batch",
        "hetzner_api_exception_disclosure",
    ),
    (
        "f81640e316f3864bb0e40236c971d95e9aa9b04e",
        "498b189286c0c2dacacf9d90f9a3e7d8d9d6b4d1",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_STATUS_REPAIR",
        "exact_delta_causal_batch",
        "excluded_container_default_status",
    ),
    (
        "498b189286c0c2dacacf9d90f9a3e7d8d9d6b4d1",
        "e3746a4b887441169a86dde955ff3324f5f9c273",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_STATUS_REPAIR",
        "exact_delta_causal_batch",
        "unknown_container_health_preservation",
    ),
    (
        "c1518ba1c0be36da42b6cef06df4b042f5733b01",
        "809d9b21fa9609de2ce9b49bb838c079598da876",
    ): (
        "CONFIRMED_DIRECT_AI_CASE_SENSITIVITY_REGRESSION",
        "exact_delta_causal_batch",
        "manual_webhook_repository_casefold",
    ),
    (
        "4ed7a4238a500427ac53684331ffc752e94a2805",
        "6ea563c6ac7599a8923a8288e43d780301360d8b",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_IMAGE_RETENTION",
        "exact_delta_causal_batch",
        "image_retention_runtime_images",
    ),
    (
        "4706bc23aa86ce1abdc9e7503e8ce41d1551d51c",
        "8c40cc607afa9e6c963c5b8a866f847be0a5ec05",
    ): (
        "CONFIRMED_DIRECT_AI_SERVICE_NAME_PARSING_REGRESSION",
        "exact_delta_causal_batch",
        "service_name_last_separator",
    ),
    (
        "e4810a28d28b5e223a4d8193fef82eb3ae06cf41",
        "b00d8902f4a74a5f2c4c9bc75aea9b0411b20261",
    ): (
        "CONFIRMED_DIRECT_AI_DUPLICATE_NOTIFICATION_REGRESSION",
        "exact_delta_causal_batch",
        "duplicate_proxy_restart_notifications",
    ),
    (
        "5d73b76a44198dfbc8533010a348a1703793094d",
        "cb0f2301f5200daee834498bb5196fafc12daabc",
    ): (
        "CONFIRMED_DIRECT_AI_NULL_VERSION_CACHE_REGRESSION",
        "exact_delta_causal_batch",
        "null_versions_cache_assignment",
    ),
    (
        "d9774d29684987deb2b9a7f4a2af135af329a722",
        "cd10796612bdff7993995afa0d978d070341e7a1",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_DOWNGRADE_PREVENTION",
        "exact_delta_causal_batch",
        "running_version_downgrade_guard",
    ),
    (
        "97550f40669fe3c82dace16dbe875905bf2e1058",
        "b602fef4dbcead34ed68556039c737d22eaf5c12",
    ): (
        "CONFIRMED_DIRECT_AI_TECHNICAL_DETAIL_DISCLOSURE",
        "exact_delta_causal_batch",
        "deployment_technical_detail_disclosure",
    ),
    (
        "7069236714055571f6d90a56a513e368683919d7",
        "e01b8a057e6437cf2a2bafe61db67943acc7bb39",
    ): (
        "CONFIRMED_DIRECT_AI_PROVISIONING_STATE_REGRESSION",
        "exact_delta_causal_batch",
        "hetzner_pending_ip_retention",
    ),
    (
        "c42fb813470487425645a9ff01f74ba866f1443f",
        "2fc870c6eb0818969fd6ce63bc8b357501199c60",
    ): (
        "CONFIRMED_DIRECT_AI_INEFFECTIVE_DEBOUNCE_GUARD",
        "exact_delta_causal_batch",
        "proxy_restart_debounce_guard",
    ),
    (
        "0f54c194d7a3ec63c41d707202f53b57e4abe7d7",
        "b5416859e5b5147831fafcad2fe848b6049eb728",
    ): (
        "CONFIRMED_DIRECT_AI_INVALID_SECRET_CONFIGURATION",
        "exact_delta_causal_batch",
        "garage_rpc_secret_length",
    ),
    (
        "2cf915aed813c666fadb43bc8e2376c460ffcaf9",
        "2743229cc49c342311f5daa55221f170bbcf70dc",
    ): (
        "CONFIRMED_DIRECT_AI_TEAM_CONTEXT_NULL_REGRESSION",
        "exact_delta_causal_batch",
        "user_team_null_context",
    ),
    (
        "01635e8b80ae368c8fe89ca486bffa6f9932b08d",
        "246e3cd8a2861f8d981f5f917819deb4fb6c6d35",
    ): (
        "CONFIRMED_DIRECT_AI_SUDO_PREFIX_CLASSIFICATION_REGRESSION",
        "exact_delta_causal_batch",
        "sudo_keyword_prefix_collision",
    ),
    (
        "5b9146d8df7ab15c874c5aa49f3c23d6b5cdf54d",
        "9b060958aad7a02ef15dc6d8503e411b25ca523f",
    ): (
        "CONFIRMED_DIRECT_AI_RUNTIME_DEBUG_INSTRUMENTATION",
        "exact_delta_causal_batch",
        "ray_parser_debug_hooks",
    ),
    (
        "dc15bee980ed823960b3ce97e6ed21191ab79e28",
        "9b060958aad7a02ef15dc6d8503e411b25ca523f",
    ): (
        "CONFIRMED_DIRECT_AI_RUNTIME_DEBUG_INSTRUMENTATION",
        "exact_delta_causal_batch",
        "ray_webhook_debug_hooks",
    ),
    (
        "d2d9c1b2bcaccaaba826bb06816ea5dd7679088e",
        "14bba8ba86a2a50ce7d986066ba2befe23f1d7ef",
    ): (
        "CONFIRMED_DIRECT_AI_RUNTIME_DEBUG_INSTRUMENTATION",
        "exact_delta_causal_batch",
        "sentinel_status_debug_logging",
    ),
    (
        "70fb4c6869ed9e72ed62b9e409f29819d42632b9",
        "ac9eca3c051e15a52e1ab5f655d3011a21c9b112",
    ): (
        "CONFIRMED_DIRECT_AI_EXITED_HEALTH_STATUS_REGRESSION",
        "exact_delta_causal_batch",
        "exited_container_health_suffix",
    ),
    (
        "42f916dce235bbff4d49d0a1362608c036092e4d",
        "a2e5b2d67d8cc05fd60a2d97e098ccc401562a25",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_TERMINAL_STATE_GUARD",
        "exact_delta_causal_batch",
        "finished_deployment_terminal_state",
    ),
    (
        "53d1ad48cddb52cb94e6179575af7647d5ff5fc4",
        "a3df33a4e06c1df38e51c9ec81951402e0a6914a",
    ): (
        "CONFIRMED_DIRECT_AI_MIGRATION_ORDER_REGRESSION",
        "exact_delta_causal_batch",
        "webhook_settings_migration_order",
    ),
    (
        "b47181c790010971ac78c3603a60b662006bf81f",
        "56a0143a25af3d2a040753637987c08a65bb3f09",
    ): (
        "CONFIRMED_DIRECT_AI_DUPLICATE_JOB_DISPATCH",
        "repair_action_exact_delta_batch",
        "sentinel_storage_check_duplication",
    ),
    (
        "5324ac3bd93f6255ee04da05324917cd63d51b48",
        "32929a9fe7ef67c5279bc54bf63312d30e4feec3",
    ): (
        "CONFIRMED_DIRECT_AI_NONREACTIVE_ACTIVITY_MONITOR",
        "repair_action_exact_delta_batch",
        "s3_activity_monitor_nonreactive_rendering",
    ),
    (
        "fcc52f943c1d103acef4f45b10252556134310d1",
        "c758de9e7c859f4cb8ecb2665888a782bfd281a2",
    ): (
        "CONFIRMED_DIRECT_AI_ACTIVITY_MONITOR_RENDER_REGRESSION",
        "repair_action_exact_delta_batch",
        "s3_activity_monitor_missing_dom",
    ),
    (
        "f8146f5a5931326ac31858e4ae2b64831bcc2d09",
        "d9762e0310c7ca712a119572c1f3bdf87bf99b25",
    ): (
        "CONFIRMED_DIRECT_AI_LOG_FOLLOW_REGRESSION",
        "repair_action_exact_delta_batch",
        "deployment_log_follow_scroll_disable",
    ),
    (
        "32929a9fe7ef67c5279bc54bf63312d30e4feec3",
        "f2a017a0636ade05626b20f5357fe520a3b1bc0c",
    ): (
        "CONFIRMED_DIRECT_AI_ACTIVITY_MONITOR_DISPATCH_REGRESSION",
        "repair_action_exact_delta_batch",
        "activity_monitor_dispatch_binding_regression",
    ),
    (
        "d640911bb94e7ee4353fbf5d116af5204258fa12",
        "e4cc5c117836ac3dc103e80b921738781c8e5ff8",
    ): (
        "CONFIRMED_DIRECT_AI_SPURIOUS_SUCCESS_NOTIFICATION",
        "repair_action_exact_delta_batch",
        "bulk_update_spurious_success_notification",
    ),
    (
        "e256e765e74a0d506c96e768b9246efb1ec7d80c",
        "36573ecbf0e822984eb01f5541eac77c84d5440e",
    ): (
        "CONFIRMED_DIRECT_AI_MIGRATION_PROPERTY_TYPE_ERROR",
        "repair_action_exact_delta_batch",
        "postgres_migration_property_type_error",
    ),
    (
        "ce12c94709f2a74a1b7e276deb23fb4df951dc3e",
        "033433f553bc964ec9ce3e8d834ad7dd7b95dddd",
    ): (
        "CONFIRMED_DIRECT_AI_DATABASE_IDENTIFICATION_REGRESSION",
        "repair_action_exact_delta_batch",
        "migrated_service_database_misclassification",
    ),
    (
        "c892a8ce4419ca8a8f83539d9d385df6750401bb",
        "2f2ab6d775c500f28742e9a8e121f9a59ef220dc",
    ): (
        "CONFIRMED_DIRECT_AI_MODAL_WIDTH_REGRESSION",
        "repair_action_exact_delta_batch",
        "github_app_callout_modal_overflow",
    ),
    (
        "208f0eac997a516398d20509dc25aac226241234",
        "58d510042b24319f6608e0fdbcf81d021cc87cbc",
    ): (
        "CONFIRMED_DIRECT_AI_ENVIRONMENT_VALUE_OVERWRITE",
        "repair_action_exact_delta_batch",
        "service_parser_environment_value_overwrite",
    ),
    (
        "8a4303cc026737fcd16a54d92825556f16b0e34f",
        "a64e1b579b1b931bd45b61a6e769fdc64cdc4819",
    ): (
        "CONFIRMED_DIRECT_AI_LOG_HTML_DECODING_REGRESSION",
        "repair_action_exact_delta_batch",
        "log_viewer_html_tag_removal",
    ),
    (
        "3fc626c6da793a65a3cd3f323800fbf61cdb85d9",
        "18f30b7fabc54938a031867ad34c39a1e9c7c0d7",
    ): (
        "CONFIRMED_DIRECT_AI_EVENT_CLASS_RESOLUTION_ERROR",
        "repair_action_exact_delta_batch",
        "s3_event_double_namespace",
    ),
    (
        "6c0840d4e0cc1a9924c8b98163b38113290c2c01",
        "ad7479b1675758ac389e0f5b94b922a435e03db5",
    ): (
        "CONFIRMED_DIRECT_AI_DROPDOWN_DEFAULT_REGRESSION",
        "repair_action_exact_delta_batch",
        "cloud_init_dropdown_forced_selection",
    ),
    (
        "a514c837b6a28179589025ab765184e786a40c22",
        "598984f2914163a39f25be64233081153e814fa7",
    ): (
        "CONFIRMED_DIRECT_AI_HTML_ID_BINDING_REGRESSION",
        "repair_action_exact_delta_batch",
        "generated_html_id_wire_model_warning",
    ),
    (
        "a3df33a4e06c1df38e51c9ec81951402e0a6914a",
        "477738dd2f7f76d8964f256de4403944b5af23fb",
    ): (
        "CONFIRMED_DIRECT_AI_NON_IDEMPOTENT_MIGRATION_REPAIR",
        "repair_action_exact_delta_batch",
        "webhook_settings_non_idempotent_population",
    ),
    (
        "92326c09ea28af6abf427b32a256dbd997ad7133",
        "707bfacbcd315043b0d4194664fef08435fe0f1e",
    ): (
        "CONFIRMED_DIRECT_AI_LIGHT_MODE_VISIBILITY_REGRESSION",
        "repair_action_exact_delta_batch",
        "upgrade_progress_light_mode_visibility",
    ),
    (
        "36da7174d546b2be402b67e834f6a5c17d4987e9",
        "387a093f0485e4356bcaec3fe5ea27a8ef177ddc",
    ): (
        "CONFIRMED_DIRECT_AI_PROXY_RESTART_NAME_CONFLICT",
        "repair_action_exact_delta_batch",
        "proxy_restart_container_name_conflict",
    ),
    (
        "42f08a99fb149cf4e70976bff661b10f8ba39a45",
        "dac940807a88f5a236fbfd7923b1f1f336e3c43f",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_SHELL_ARGUMENT_HARDENING",
        "repair_action_exact_delta_batch",
        "nixpacks_environment_shell_injection",
    ),
    (
        "23fdad1d9fbab46e17610ad45b915636f0e1c38b",
        "8e273dd79956aaafe9511b57dae8513b32bed59a",
    ): (
        "CONFIRMED_DIRECT_AI_WRONG_USER_BROADCAST",
        "repair_action_exact_delta_batch",
        "s3_download_wrong_user_broadcast",
    ),
    (
        "cb0f2301f5200daee834498bb5196fafc12daabc",
        "e110e32320750aa5049a695004574ed9997e829a",
    ): (
        "CONFIRMED_DIRECT_AI_STALE_PROXY_WARNING_REGRESSION",
        "repair_action_exact_delta_batch",
        "traefik_warning_restart_refresh",
    ),
    (
        "c79b5f1e5c26f4ad0f7fd571985933e56a9d80b8",
        "118966e8102ce1b89ef97f8c2601a39112b0992a",
    ): (
        "CONFIRMED_DIRECT_AI_EMPTY_SCOPE_UI_REGRESSION",
        "repair_action_exact_delta_batch",
        "shared_environment_scope_dropdown_suppression",
    ),
    (
        "acd7106f93c4a34f175ff136ea8f80ca1502b353",
        "334fd2500fea9adb2e1ae0eb6cfef86238c9004f",
    ): (
        "CONFIRMED_DIRECT_AI_INITIAL_RENDER_HOOK_REGRESSION",
        "repair_action_exact_delta_batch",
        "runtime_log_initial_colorization",
    ),
    (
        "dca6d9f7aab40fb9e6ea24dcc3a85bea02cc33a6",
        "9408620d5f47836241a9b10516296c5311786832",
    ): (
        "CONFIRMED_DIRECT_AI_WEBSOCKET_KEEPALIVE_REGRESSION",
        "repair_action_exact_delta_batch",
        "hidden_tab_websocket_keepalive_suppression",
    ),
    (
        "bf8dcac88c1b1bf8ccbae7974c92facc99d76192",
        "922c0a9e7c03de8d4eafeb0901fe1d5a13d0750a",
    ): (
        "CONFIRMED_DIRECT_AI_LOG_RENDERING_REGRESSION",
        "merge_repair_exact_delta_batch",
        "log_domparser_flicker_and_entity_encoding",
    ),
    (
        "40b1b1319ff10a2ff0cc50b983a0700a7d1ca57a",
        "922c0a9e7c03de8d4eafeb0901fe1d5a13d0750a",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_LOG_PERFORMANCE_REPAIR",
        "merge_repair_exact_delta_batch",
        "log_performance_cache_flicker",
    ),
    (
        "863fe794a8b6aa82b761dc07e63f30866437df23",
        "27f2e32fbfa76f176d38fdc2d94e51367af4ba10",
    ): (
        "CONFIRMED_DIRECT_AI_LOG_RENDERING_PERFORMANCE_REGRESSION",
        "merge_repair_exact_delta_batch",
        "per_line_log_level_regex_freeze",
    ),
    (
        "4f2bb3b50e4c63c8f3ca2679127c9b33fcf2ba1b",
        "27f2e32fbfa76f176d38fdc2d94e51367af4ba10",
    ): (
        "CONFIRMED_DIRECT_AI_AUTOSCROLL_PERFORMANCE_REGRESSION",
        "merge_repair_exact_delta_batch",
        "deployment_log_interval_layout_thrash",
    ),
    (
        "1b4de183234ea07d93bc5be2c9ff09815d3add11",
        "27f2e32fbfa76f176d38fdc2d94e51367af4ba10",
    ): (
        "CONFIRMED_DIRECT_AI_LOG_DECODER_PERFORMANCE_REGRESSION",
        "merge_repair_exact_delta_batch",
        "iterative_domparser_log_decode",
    ),
    (
        "5cc822c9963312dd9f7bd3f5ba8b7a45d5e771e2",
        "27f2e32fbfa76f176d38fdc2d94e51367af4ba10",
    ): (
        "CONFIRMED_DIRECT_AI_LOG_SELECTION_RENDER_REGRESSION",
        "merge_repair_exact_delta_batch",
        "selection_preservation_render_trigger_freeze",
    ),
    (
        "b62eece93e381cfcdb86f0a3885826b7651edeef",
        "e0dc12678b58aeb653053ddebc035c520e859aa1",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_SERVICE_URL_REPAIR",
        "merge_repair_exact_delta_batch",
        "service_database_fqdn_parser_incomplete",
    ),
    (
        "6f163ddf02991fb8fd8bc17fdcecddc318b813c6",
        "c1d670b1e597fdb768340c01084e155241f617b4",
    ): (
        "CONFIRMED_DIRECT_AI_PREDEPLOY_COMMAND_REGRESSION",
        "merge_repair_exact_delta_batch",
        "newline_normalization_predeploy_failure",
    ),
    (
        "2335bfad8f2b543b135508a69980fcd05b5fb4e8",
        "6c030d96f2defa5aa5eee036a4edeff3be0e4224",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_MIGRATION_REPAIR",
        "merge_repair_exact_delta_batch",
        "cloud_init_migration_collision_guard",
    ),
    (
        "e930005a503e046e4971b69886b817e3ab77fd78",
        "6c030d96f2defa5aa5eee036a4edeff3be0e4224",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_MIGRATION_REPAIR",
        "merge_repair_exact_delta_batch",
        "webhook_settings_migration_collision_guard",
    ),
    (
        "22ef6c8c9a257b0f7bf3ef9e9458348428e226e2",
        "6c030d96f2defa5aa5eee036a4edeff3be0e4224",
    ): (
        "CONFIRMED_DIRECT_AI_MISPLACED_MIGRATION_FIELD_REPAIR",
        "merge_repair_exact_delta_batch",
        "server_patch_webhook_field_population_misplacement",
    ),
    (
        "aea201fcba0cc89f09f1ef8555ab00de275752ab",
        "58af19b378aba750c6214ab47eb903cc40525615",
    ): (
        "CONFIRMED_DIRECT_AI_AUTHORIZATION_GUARD_REMOVAL",
        "merge_repair_exact_delta_batch",
        "subscriber_authorization_guard_removal",
    ),
    (
        "a94517f452e225046e01c08385d6a7aedf085c7d",
        "2729dffb3e30167c1ffd642357b7e0bb99b7d180",
    ): (
        "CONFIRMED_DIRECT_AI_FAIL_OPEN_ACTIVITY_AUTHORIZATION",
        "merge_repair_exact_delta_batch",
        "legacy_activity_missing_team_fail_open",
    ),
    (
        "6d47d24169d28fae525dfb55895ab20cfb591039",
        "633b1803e11370e876343ad41b12c548c59e898a",
    ): (
        "CONFIRMED_DIRECT_AI_FALSE_CONTAINER_EXIT_REGRESSION",
        "merge_repair_exact_delta_batch",
        "failed_docker_query_false_exit",
    ),
    (
        "75d8ebe80338d9b2dce962542e2beca8e4cca6d0",
        "aaa540421fbd99a23dd2442340aee6076e4f638e",
    ): (
        "CONFIRMED_DIRECT_AI_RESTART_LIMIT_STATE_RESET",
        "test_change_exact_delta_batch",
        "manual_stop_restart_limit_state_reset",
    ),
    (
        "b00d8902f4a74a5f2c4c9bc75aea9b0411b20261",
        "340e42aefd307bbbac5e0cb969b7427ccfc7da17",
    ): (
        "CONFIRMED_DIRECT_AI_DELAYED_PROXY_RESTART_STATUS",
        "test_change_exact_delta_batch",
        "delayed_proxy_restarting_status",
    ),
    (
        "05bd57ed5142d98aca37c6513d466f8abfdcd695",
        "e4bf8ab3374e1b7052a1b2e87e7c9e080f111daa",
    ): (
        "CONFIRMED_DIRECT_AI_CLOUD_INIT_SAVE_UI_REGRESSION",
        "direct_fallback_exact_delta_batch",
        "cloud_init_save_checkbox_disabled",
    ),
    (
        "0c46da0a23708205917e5eb830459882a60bdc0e",
        "1f7888f515da8d67ebad655c35e38ed544cc0543",
    ): (
        "CONFIRMED_DIRECT_AI_UPGRADE_SSH_DISCONNECT_REGRESSION",
        "direct_fallback_exact_delta_batch",
        "upgrade_main_container_ssh_disconnect",
    ),
    (
        "4507d99460982f2a2516a5b7551360c371f0e575",
        "ff7b27be61217742524bf4f5161da068e59fce55",
    ): (
        "CONFIRMED_DIRECT_AI_SYMLINK_DELETION_SAFETY_GAP",
        "direct_fallback_exact_delta_batch",
        "worktree_absolute_path_symlink_deletion",
    ),
    (
        "c6316272003917fa233c7ab1f00b774a74bf205e",
        "ff7b27be61217742524bf4f5161da068e59fce55",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_DELETION_PATH_GUARD",
        "direct_fallback_exact_delta_batch",
        "worktree_incomplete_dangerous_path_guard",
    ),
    (
        "6b9c633fe744ab2aa47a3a6341bae775628c8268",
        "7bb14d1d9cf6ce1d50e212f64ba7f001ac62acae",
    ): (
        "CONFIRMED_DIRECT_AI_LIVE_LOG_UPDATE_REGRESSION",
        "direct_fallback_exact_delta_batch",
        "log_selection_blocks_live_updates",
    ),
    (
        "6d16f521430c050539f1859919c72cd5e68f7ddc",
        "d0195538093905bba9f35cfb4c2d638fdc7f7caf",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_RATE_LIMIT_RESPONSE",
        "direct_fallback_exact_delta_batch",
        "deployment_queue_429_missing_retry_after",
    ),
    (
        "ecada60c78cbabda5e56fdc030f43c7e42a5c48b",
        "12766695c43201b8d3825776ae9c8216712e11e1",
    ): (
        "CONFIRMED_DIRECT_AI_FIXED_VIEWPORT_HEIGHT_REGRESSION",
        "direct_fallback_exact_delta_batch",
        "compose_editor_fixed_height_regression",
    ),
    (
        "fe27a99db2de9bda1ae459ad2abd3e3b14eb70fd",
        "0c317db536ddbd3bfd853ea30936a65c18aff65f",
    ): (
        "CONFIRMED_DIRECT_AI_ACCIDENTAL_MIGRATION",
        "direct_fallback_exact_delta_batch",
        "accidental_github_runner_migration",
    ),
    (
        "f8e3bb54a3cb48da842351cc75490c8a20134807",
        "37c3cd9f4e88259ba64118afb2a40322ca84809f",
    ): (
        "CONFIRMED_CARRIER_AI_INCOMPLETE_DOCKER_COMPOSE_FLAG_REPAIR",
        "topology_carrier_causal_batch",
        "docker_compose_custom_command_flag_injection",
    ),
    (
        "1094ab7a46452ac0e42e60e5c1e705df6484f95f",
        "274c37e33380e1003707d7b930ec9d6bf5b0a980",
    ): (
        "CONFIRMED_CARRIER_AI_INCOMPLETE_DOCKER_COMPOSE_FLAG_REPAIR",
        "topology_carrier_causal_batch",
        "docker_compose_custom_command_flag_injection",
    ),
    (
        "c7fc0a271cbcc299a7c6391d5c2ee022f9f1a8e2",
        "329708791e2491748d8e3e17d5e6a33cbfd79e90",
    ): (
        "CONFIRMED_CARRIER_AI_MISSING_REQUIRED_JOB_ARGUMENT",
        "topology_carrier_causal_batch",
        "traefik_restart_job_missing_versions_argument",
    ),
    (
        "d3e7d979f6d6d98fe943e161397df4b9cf57beb7",
        "49ab9b2278a041d7e8d06dcf02034284c7e2f7dd",
    ): (
        "CONFIRMED_CARRIER_AI_MISSING_REQUIRED_JOB_ARGUMENT",
        "topology_carrier_causal_batch",
        "traefik_restart_job_missing_versions_argument",
    ),
    (
        "0540b2eae567b344661f26f4c154be77b1efc20f",
        "171732dbcfeac3f433191b5f8134e1edb9e5614c",
    ): (
        "CONFIRMED_CARRIER_AI_UNSCOPED_RELATION_DELETE",
        "topology_carrier_causal_batch",
        "application_env_cleanup_unscoped_or_where",
    ),
    (
        "36d2c024980558fdb6c10d66a123bde769dbb96b",
        "171732dbcfeac3f433191b5f8134e1edb9e5614c",
    ): (
        "CONFIRMED_CARRIER_AI_UNSCOPED_RELATION_DELETE",
        "topology_carrier_causal_batch",
        "application_env_cleanup_unscoped_or_where",
    ),
    (
        "36f8a58c281e461cf75750f6cf57ae5afd52a3ba",
        "59e9d16190417ad786ae33786d36558216f79dd1",
    ): (
        "CONFIRMED_CARRIER_AI_UNSCOPED_RELATION_DELETE",
        "topology_carrier_causal_batch",
        "application_env_cleanup_unscoped_or_where",
    ),
    (
        "8d280b4aac3f6e0b6ec1de37335a1440043e1933",
        "5b79844a3a11ee35ada53e71e85874a5d6a2137d",
    ): (
        "CONFIRMED_DIRECT_AI_DOCKER_VERSION_COMPATIBILITY_REGRESSION",
        "merge_member_causal_batch",
        "docker_27_stop_timeout_flag_compatibility",
    ),
    (
        "c65ad2e65580307ff641d6d20f83608acfb98f35",
        "66e81d6d9654e10f81ff278ad7cf4135b6b9c00e",
    ): (
        "CONFIRMED_DIRECT_AI_STATUS_SEMANTICS_REGRESSION",
        "merge_member_causal_batch",
        "subresource_restarting_status_preservation",
    ),
    (
        "a956e11b3e408a9b5c8b9843525fd069a01712f0",
        "5b9146d8df7ab15c874c5aa49f3c23d6b5cdf54d",
    ): (
        "CONFIRMED_DIRECT_AI_RAW_CONFIGURATION_MUTATION_REGRESSION",
        "merge_member_causal_batch",
        "docker_compose_raw_user_input_preservation",
    ),
    (
        "c25272de8d4f8f7a789e50c17d8eb8557440412a",
        "d27d697b37865d0416a8fad49a4c193370fcd12a",
    ): (
        "CONFIRMED_DIRECT_AI_FAILURE_OBSERVABILITY_REGRESSION",
        "merge_member_causal_batch",
        "name_cleanup_backup_failure_observability",
    ),
    (
        "d9762e0310c7ca712a119572c1f3bdf87bf99b25",
        "b484c0cc253ff9845fda130671004f5451fea84f",
    ): (
        "CONFIRMED_DIRECT_AI_LOG_DISPLAY_TRUNCATION_REGRESSION",
        "merge_member_causal_batch2",
        "deployment_log_hardcoded_display_limit",
    ),
    (
        "a5c6f53b583c93b1871ac1099632d47d157a0341",
        "bc39c2caa83b511b5fead29e2b40827e2471a8fb",
    ): (
        "CONFIRMED_AI_LAYOUT_SHIFT_PRESERVATION_CONTRIBUTOR",
        "merge_member_causal_batch2",
        "dirty_indicator_border_layout_shift_preservation",
    ),
    (
        "fb4f12fcb8ab1568dc3f34a56238b273830326fa",
        "b9ea89d52886af4204f0f152e163e6e1b8bf032d",
    ): (
        "CONFIRMED_DIRECT_AI_NONREACTIVE_UI_PATH_EXTENSION",
        "merge_member_causal_batch2",
        "compose_control_build_pack_reactivity",
    ),
    (
        "3fdce06b654fa3b7b4be59c0faaab6b4546c78de",
        "a06c1a7bf5e30eb779d8e7bce01b6e4b1f78b624",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_PATH_TRAVERSAL_HARDENING",
        "merge_member_causal_batch2",
        "file_mount_parent_segment_confinement",
    ),
    (
        "9493398b58ac39fc74d44d6bbae44336c93274e1",
        "5e0e6772d5aa8f355bd71cafccb2cfffa81bbe45",
    ): (
        "CONFIRMED_DIRECT_AI_GLOBAL_LIFECYCLE_HOOK_REGRESSION",
        "merge_member_causal_batch3",
        "deployment_log_morph_hook_navigation_lifecycle",
    ),
    (
        "f2a017a0636ade05626b20f5357fe520a3b1bc0c",
        "aa18c4882350875a8f1069e0e1530f34f132d797",
    ): (
        "CONFIRMED_AI_LIFECYCLE_HOOK_REMOVAL_COMPOSITIONAL_CONTRIBUTOR",
        "merge_member_causal_batch3",
        "activity_monitor_hydration_lifecycle",
    ),
    (
        "747a48b9337947a85e5b4a4b123ea405d676b5b0",
        "14bba8ba86a2a50ce7d986066ba2befe23f1d7ef",
    ): (
        "CONFIRMED_DIRECT_AI_RUNTIME_DEBUG_INSTRUMENTATION",
        "exact_delta_causal_batch2",
        "sentinel_status_runtime_debug_payload",
    ),
    (
        "e055c3b101593f2f36d53138349e5e364598f7d6",
        "9b060958aad7a02ef15dc6d8503e411b25ca523f",
    ): (
        "CONFIRMED_DIRECT_AI_RUNTIME_DEBUG_INSTRUMENTATION",
        "exact_delta_causal_batch2",
        "hetzner_create_server_ray_payload",
    ),
    (
        "5463f4d4961cfccab6ddbc9fa341c74d151261a0",
        "d93a13eeee237783b2c181b4ac20e1efc3517e98",
    ): (
        "CONFIRMED_DIRECT_AI_INVALID_CONFIGURATION_ACCEPTANCE",
        "exact_delta_causal_batch2",
        "cloud_init_script_syntax_validation",
    ),
    (
        "bafb9a5a8baf8518a5b9c1cda59f158f5e726436",
        "c1518ba1c0be36da42b6cef06df4b042f5733b01",
    ): (
        "CONFIRMED_DIRECT_AI_UNAUTHENTICATED_IDENTIFIER_DISCLOSURE",
        "exact_delta_causal_batch2",
        "manual_webhook_missing_secret_identifier_oracle",
    ),
    (
        "e1fe58639756cf7b232458eddd6978e4ed0031f5",
        "e1d4b4682efc898ba5aa3751b2da2072f89c7e24",
    ): (
        "CONFIRMED_DIRECT_AI_ORIGIN",
        "conductor_trust_hosts_origin",
        "trust_hosts_cold_cache_validation_bypass",
    ),
    (
        "473c32270d72252ee6753afc35c3ea4360d169e0",
        "5019c8db928afd34c0c9d17c5d20019fa053c344",
    ): (
        "CONFIRMED_DIRECT_AI_API_TEAM_CONTEXT_REGRESSION",
        "conductor_exact_delta_causal_batch",
        "api_backup_s3_session_team_context",
    ),
    (
        "473c32270d72252ee6753afc35c3ea4360d169e0",
        "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
    ): (
        "CONFIRMED_DIRECT_AI_CROSS_TEAM_SERVER_LOOKUP",
        "conductor_exact_delta_causal_batch",
        "api_cancel_deployment_unscoped_build_server",
    ),
    (
        "bf6a109e56e2928b2a39ec01d3483e50ddab644b",
        "73170fdd33783337a91b27191f126cbd5c61faed",
    ): (
        "CONFIRMED_DIRECT_AI_INVALID_SEEDED_COMPOSE_PATH",
        "conductor_exact_delta_causal_batch",
        "docker_compose_seed_path_concatenation",
    ),
    (
        "edcdea78a289bdc467ea22002cb59821d502a76b",
        "6557514954ac36ebd95f5eb704acee887ee9e61f",
    ): (
        "CONFIRMED_DIRECT_AI_OVERBROAD_CI_TOKEN_PERMISSION",
        "conductor_exact_delta_causal_batch",
        "ghcr_cleanup_unnecessary_contents_read",
    ),
    (
        "51bada187192d8a21aae7a7709bb0409da473ff1",
        "670c9dab0dceecdda6ac1858e2a4b65317ac8088",
    ): (
        "CONFIRMED_DIRECT_AI_COMPOSITIONAL_ORIGIN",
        "conductor_healthcheck_reset_origin",
        "commented_healthcheck_blocks_removal_reset",
    ),
    (
        "802569bf636b8172385981e8a52e312745f826cc",
        "6871160623ae5a42a3b1581de4ca4bccf78f0603",
    ): (
        "CONFIRMED_DIRECT_AI_GITHUB_SENSITIVE_READ_SUPPRESSION",
        "github_sensitive_read_causal",
        "github_apps_list_ignored_read_sensitive_capability",
    ),
    (
        "e2c254a5a8518c8dd9d31df60c9009fad119226d",
        "4fc0c946daf3a858bfe0e14999b0432b1f38b4a3",
    ): (
        "CONFIRMED_DIRECT_AI_SYMBOL_CONTRACT_BREAK",
        "symbol_contract_method_migration",
        "edit_domain_partial_sync_method_migration",
    ),
    (
        "837a0f4545f4b0bb68ecd222af21be50a4f4530f",
        "a5c6f53b583c93b1871ac1099632d47d157a0341",
    ): (
        "CONFIRMED_AI_MERGE_COMPOSITIONAL_ORIGIN",
        "conductor_form_onboarding_attribution",
        "unbound_form_dirty_indicator_merge_composition",
    ),
    (
        "e2c254a5a8518c8dd9d31df60c9009fad119226d",
        "7c14cd24dc923a997dec733d5038a306f1cac36a",
    ): (
        "CONFIRMED_DIRECT_AI_CROSS_FILE_BINDING_CONTRACT_REGRESSION",
        "conductor_form_onboarding_attribution",
        "livewire_fqdn_binding_contract_mismatch",
    ),
    (
        "04625591eaafac64db412b21b0f4c4c0f82fc8ad",
        "2e71ef4f1111421a67dabfb506387c938b320b80",
    ): (
        "CONFIRMED_DIRECT_AI_ONBOARDING_MODAL_REDIRECT_REGRESSION",
        "conductor_form_onboarding_attribution",
        "hetzner_onboarding_modal_standard_redirect",
    ),
    (
        "885fb20445c48eb3ba0f6ff3905d5a0e1d5cc681",
        "bb6dfe9f8c3a8d32b447f93845d647f52d8297c1",
    ): (
        "CONFIRMED_DIRECT_AI_ROLLBACK_IMAGE_IDENTITY_REGRESSION",
        "deployment_rollback_causal_batch",
        "rollback_image_tag_omits_build_config_hash",
    ),
    (
        "885fb20445c48eb3ba0f6ff3905d5a0e1d5cc681",
        "b227619cbf010954a99375405fbcc7a06132746e",
    ): (
        "CONFIRMED_DIRECT_AI_ROLLBACK_SNAPSHOT_SYMLINK_OVERWRITE",
        "deployment_rollback_causal_batch",
        "rollback_snapshot_legacy_env_symlink_overwrite",
    ),
    (
        "885fb20445c48eb3ba0f6ff3905d5a0e1d5cc681",
        "45f931ecc8bc0979bc67925744f8b35076c5fc72",
    ): (
        "CONFIRMED_DIRECT_AI_ROLLBACK_REBUILD_STATE_LOSS",
        "deployment_rollback_causal_batch",
        "rollback_rebuild_missing_historical_environment_snapshot",
    ),
    (
        "a5dafe785b1487197bbbbede2c3dee7bf5886393",
        "226de3514606192c1d6cc66326033dc20ae8f2c4",
    ): (
        "CONFIRMED_DIRECT_AI_EVENT_TARGET_ALIAS_REGRESSION",
        "activity_monitor_target_key",
        "activity_monitor_dispatch_targets_instance_key_as_component_name",
    ),
    (
        "922884e6d3e913883000f8e4bfe1a979daad3aca",
        "5ce0670ca4ee5744da5b8d5e5248df8b95c79f83",
    ): (
        "CONFIRMED_DIRECT_AI_INCOMPLETE_CACHE_ORIGIN",
        "trust_hosts_negative_cache_origin",
        "trust_hosts_null_negative_cache_requery",
    ),
    (
        "28fc3feab00d99bade5d4beeef959b8df011667e",
        "974a8bdf647c0aea240469b979856a868c0499e6",
    ): (
        "CONFIRMED_DIRECT_AI_MODAL_ISOLATION_REGRESSION",
        "modal_wire_ignore_causal",
        "modal_wire_ignore_isolation_removal",
    ),
    (
        "56f32d0f87609d48c4f9f8d766c96c183bcd60f9",
        "a5ce1db8715d62b437cb3104af5ca6427f28a47b",
    ): (
        "CONFIRMED_DIRECT_AI_UPDATE_COMPOSE_MAP_STYLE_UNDERACCEPTANCE",
        "update_compose_map_style_origin",
        "update_compose_map_style_environment_underacceptance",
    ),
    (
        "251a10f5bb5659b7ef32431795ec7531d0c4cb4f",
        "031d40440d56792e9ae2abe096c177867cee8ffc",
    ): (
        "CONFIRMED_AI_DEV_COLD_START_IMAGE_PULL_REGRESSION",
        "dev_compose_pull_policy",
        "dev_compose_external_image_pull_policy_never",
    ),
    (
        "596b1cb76ecb1a8e3a295f25672586c49dbf71d0",
        "56394ba093ca82d99f9847edfbbaafe55d34a140",
    ): (
        "CONFIRMED_DIRECT_AI_TOKEN_ERROR_CONTRACT_DISCARD",
        "token_metrics_causal_batch",
        "cloud_token_validation_error_contract_discard",
    ),
    (
        "f199b6bfc4be1afc11b8a2a3bdc8878dc85e4daf",
        "0e9dbc362574d24316642adfc0364512902b2674",
    ): (
        "CONFIRMED_DIRECT_AI_METRICS_COLLECTION_CONTRACT_REGRESSION",
        "token_metrics_causal_batch",
        "server_cpu_metrics_collection_contract_regression",
    ),
    (
        "f3ccacb2da6da8b502bcb472bfb0bc6a7c776068",
        "f4dbae180536f897185c7933f1904e8b9d39efff",
    ): (
        "CONFIRMED_AI_UPGRADE_DEPENDENCY_INVERTED_SHUTDOWN_ORDER",
        "upgrade_shutdown_order",
        "upgrade_dependency_inverted_shutdown_order",
    ),
    (
        "9c2ef0aa21e2c5a9809d9748253e6b134dfe2019",
        "e256e765e74a0d506c96e768b9246efb1ec7d80c",
    ): (
        "CONFIRMED_DIRECT_AI_MIGRATION_TRANSACTION_PROPERTY_TYPE_CONTRACT_BREAK",
        "concurrent_index_migration_transaction_contract",
        "laravel_migration_within_transaction_property_type_invariance",
    ),
    (
        "f152ec00ada70757da38e0b789f049b14d813e33",
        "9bc33d65abd022884ddc6d0e3c463ad4032bb144",
    ): (
        "CONFIRMED_AI_TO_AI_INCOMPLETE_REPAIR",
        "readonly_volume_path_normalization",
        "local_file_volume_leading_slash_normalization_omission",
    ),
}

PATCH_EQUIVALENT_ALIAS_EDGES = {
    (
        "e04b9cd07c11b79d4fcd62d8dca441d8571e4086",
        "096d4369e59b3db7ace2db3ca42588c41b9b6019",
    ): (
        "PATCH_EQUIVALENT_ALIAS_NO_INDEPENDENT_MAINLINE_PATH_CONTRIBUTION",
        "sentinel_activation_carrier",
        (
            "728f261316f2af904f755756d687a722d2967223",
            "096d4369e59b3db7ace2db3ca42588c41b9b6019",
        ),
    ),
}

REJECTED_EDGES = {
    (
        "cb1f571eb4b36da153d559246534f75683117299",
        "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
    ): (
        "REJECTED_UNCHANGED_CONTEXT_NOT_CAUSAL_DELTA",
        "noncausal_candidates",
    ),
    (
        "cb1f571eb4b36da153d559246534f75683117299",
        "3ba4553df5657582ad720a6572d83383fe89c078",
    ): (
        "REJECTED_UNCHANGED_CONTEXT_NOT_CAUSAL_DELTA",
        "noncausal_candidates",
    ),
    (
        "66cff9d9b84def9cf3a600ef637a51a8c35d9a2a",
        "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
    ): (
        "REJECTED_EQUIVALENT_UI_ALIAS_TO_PREEXISTING_SECURITY_PATH",
        "noncausal_candidates",
    ),
    (
        "b0d50669b1b8929b3c82ee4103fb3d1f2a1b0bf1",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    ): (
        "REJECTED_PREEXISTING_EQUIVALENT_INSTANCE_ADMIN_GATE",
        "oauth_guard_surface",
    ),
    (
        "2a8f02ed58509ff4619517411a0b00cec9971c1f",
        "a5c6f53b583c93b1871ac1099632d47d157a0341",
    ): (
        "REJECTED_WRONG_ORIGIN_MERGE_COMPOSITION",
        "conductor_form_onboarding_attribution",
    ),
    (
        "2a8f02ed58509ff4619517411a0b00cec9971c1f",
        "a3c80c9778d2c4b744afafb8d88dc47f51c448aa",
    ): (
        "REJECTED_INTERVENING_UNOBSERVED_AI_ORIGIN",
        "conductor_form_onboarding_attribution",
    ),
    (
        "2a8f02ed58509ff4619517411a0b00cec9971c1f",
        "7c14cd24dc923a997dec733d5038a306f1cac36a",
    ): (
        "REJECTED_WRONG_ORIGIN_INTERVENING_AI_CONTRACT_REFACTOR",
        "conductor_form_onboarding_attribution",
    ),
    (
        "ac653ddcbc15019e9617e719bf687f10f25a80f2",
        "2e71ef4f1111421a67dabfb506387c938b320b80",
    ): (
        "REJECTED_PREEXISTING_ONBOARDING_MODAL_CONTEXT",
        "conductor_form_onboarding_attribution",
    ),
    (
        "84559a0e7d71c05be9a123a96cf589d0719500c7",
        "62d99b0b8bab570a79e5740f459bb94eb3238203",
    ): (
        "REJECTED_NO_DEMONSTRATED_DEFECT_IN_CANDIDATE_DELTA",
        "conductor_datalist_revert_attribution",
    ),
    (
        "41afa9568d5ed2dcf56b42791ee941dbf1931fbf",
        "be2b01786ac08b69f40646d4dac4f168b04e5197",
    ): (
        "REJECTED_NONCAUSAL_EXACT_OVERLAP_INTERVENING_ORIGIN",
        "buildtime_env_duplicate_reattribution",
    ),
    (
        "2ce3052378f1dd451b6e79a9179c0a9eebb1549d",
        "66cff9d9b84def9cf3a600ef637a51a8c35d9a2a",
    ): (
        "REJECTED_FORMATTING_REVERSAL_WRONG_ORIGIN",
        "global_search_new_image_origin",
    ),
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument(
        "--route-dir",
        type=Path,
        action="append",
        required=True,
        help="model route directory; repeat to union independent passes",
    )
    parser.add_argument(
        "--candidate-inventory",
        type=Path,
        action="append",
        default=[],
        help="lossless retained candidate JSONL; repeat to union inventories",
    )
    parser.add_argument(
        "--compressed-census-dir",
        type=Path,
        help=(
            "lossless AI-descendant census whose direct pairs remain bitset-"
            "compressed instead of being expanded into the edge ledger"
        ),
    )
    parser.add_argument(
        "--topology-closure-dir",
        type=Path,
        help=(
            "lossless full topology closure whose strict-ancestor and "
            "graph-incomparable candidate pairs remain bitset-compressed"
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object in {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("row is not an object")
                rows.append(value)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _verify_commit(repository: Path, sha: str) -> None:
    completed = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "-e", f"{sha}^{{commit}}"],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise SystemExit(f"missing commit {sha} in {repository}")


def _is_ancestor(repository: Path, candidate: str, fix: str) -> bool:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            candidate,
            fix,
        ],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode not in {0, 1}:
        raise SystemExit(f"cannot check ancestry {candidate}..{fix}")
    return completed.returncode == 0


def _carrier_edge_proofs(
    payload: Mapping[str, object],
    *,
    evidence_id: str,
    target: Path,
) -> dict[tuple[str, str], dict[str, str]]:
    if payload.get("artifact_kind") != "coolify_topology_carrier_causal_batch_witness":
        return {}
    raw_confirmed = payload.get("confirmed_edges")
    raw_cases = payload.get("case_results")
    if not isinstance(raw_confirmed, list) or not isinstance(raw_cases, list):
        raise SystemExit(f"carrier evidence is malformed: {target}")
    confirmed: set[tuple[str, str]] = set()
    for row in raw_confirmed:
        if not isinstance(row, Mapping):
            raise SystemExit(f"carrier evidence has a non-object edge: {target}")
        edge = (str(row.get("candidate_sha") or ""), str(row.get("fix_sha") or ""))
        if any(len(sha) != 40 for sha in edge) or edge in confirmed:
            raise SystemExit(f"carrier evidence has an invalid edge: {target}")
        confirmed.add(edge)
    proofs: dict[tuple[str, str], dict[str, str]] = {}
    required_checks = (
        "candidate_and_fix_are_graph_incomparable",
        "candidate_and_carrier_share_focal_patch_behavior",
        "carrier_strictly_precedes_fix",
        "patch_id_inspection_complete",
        "stable_patch_id_recomputed",
    )
    for row in raw_cases:
        if not isinstance(row, Mapping) or row.get("passed") is not True:
            raise SystemExit(f"carrier evidence has a failed case: {target}")
        candidate_sha = str(row.get("candidate_sha") or "")
        fix_sha = str(row.get("fix_sha") or "")
        carrier_sha = str(row.get("carrier_sha") or "")
        edge = (candidate_sha, fix_sha)
        checks = row.get("checks")
        if (
            edge not in confirmed
            or len(carrier_sha) != 40
            or edge in proofs
            or not isinstance(checks, Mapping)
            or any(checks.get(check) is not True for check in required_checks)
        ):
            raise SystemExit(f"carrier evidence proof is incomplete: {target}")
        proofs[edge] = {
            "evidence_id": evidence_id,
            "carrier_sha": carrier_sha,
        }
    if set(proofs) != confirmed:
        raise SystemExit(
            f"carrier evidence does not cover every confirmed edge: {target}"
        )
    return proofs


def _verify_evidence(
    workspace_root: Path,
) -> tuple[
    dict[str, dict[str, object]],
    dict[tuple[str, str], dict[str, str]],
]:
    verified: dict[str, dict[str, object]] = {}
    carrier_proofs: dict[tuple[str, str], dict[str, str]] = {}
    for evidence_id, spec in EVIDENCE_ARTIFACTS.items():
        target = workspace_root / str(spec["path"])
        actual_sha256 = _sha256(target)
        if actual_sha256 != spec["sha256"]:
            raise SystemExit(f"evidence digest mismatch: {target}")
        payload = _load_json(target)
        if payload.get("witness_passed") is not True:
            raise SystemExit(f"evidence witness did not pass: {target}")
        artifact_carrier_proofs = _carrier_edge_proofs(
            payload,
            evidence_id=evidence_id,
            target=target,
        )
        overlap = set(carrier_proofs) & set(artifact_carrier_proofs)
        if overlap:
            raise SystemExit(f"duplicate carrier edge proof: {sorted(overlap)[0]}")
        carrier_proofs.update(artifact_carrier_proofs)
        verified[evidence_id] = {
            "path": str(spec["path"]),
            "sha256": actual_sha256,
            "artifact_kind": payload.get("artifact_kind"),
            "witness_passed": True,
            "nonancestral_carrier_edge_count": len(artifact_carrier_proofs),
        }
    return verified, carrier_proofs


def _route_source(route_dir: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    spec_path = route_dir / "spec.json"
    execution_path = route_dir / "execution.json"
    routes_path = route_dir / "routes.jsonl"
    spec = _load_json(spec_path)
    execution = _load_json(execution_path)
    routes = _load_jsonl(routes_path)
    if execution.get("all_candidates_retained") is not True:
        raise SystemExit(f"route source is not recall-conserving: {route_dir}")
    if execution.get("inventory_count") != len(routes):
        raise SystemExit(f"route row count mismatch: {route_dir}")
    return (
        {
            "directory": str(route_dir),
            "model": execution.get("model"),
            "reasoning_effort": execution.get("reasoning_effort"),
            "inventory_count": len(routes),
            "routes_sha256": _sha256(routes_path),
            "execution_sha256": _sha256(execution_path),
            "spec_sha256": _sha256(spec_path),
            "selected_candidate_unit_count": spec.get("selected_candidate_unit_count"),
            "all_candidates_retained": True,
        },
        routes,
    )


def _inventory_source(
    inventory_path: Path,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    rows = _load_jsonl(inventory_path)
    normalized: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        candidate_sha = str(row.get("candidate_sha") or row.get("sha") or "")
        fix_sha = str(row.get("fix_sha") or "")
        if len(candidate_sha) != 40 or len(fix_sha) != 40:
            raise SystemExit(
                f"candidate inventory has malformed edge: {inventory_path}"
            )
        if row.get("retained") is not True:
            raise SystemExit(f"candidate inventory dropped an edge: {inventory_path}")
        edge = (candidate_sha, fix_sha)
        if edge in seen:
            raise SystemExit(f"candidate inventory has duplicate edge: {edge}")
        seen.add(edge)
        normalized.append(
            {
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "model": None,
                "disposition": "INVENTORY_RETAINED",
                "causality": None,
                "reason": "lossless candidate inventory membership",
                "input_priority_rank": row.get("priority_rank"),
                "retained": True,
                "source_kind": "candidate_inventory",
            }
        )
    return (
        {
            "path": str(inventory_path),
            "inventory_count": len(normalized),
            "inventory_sha256": _sha256(inventory_path),
            "all_candidates_retained": True,
        },
        normalized,
    )


def _compressed_census_source(
    census_dir: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    summary_path = census_dir / "summary.json"
    index_path = census_dir / "ancestor_index.json"
    commits_path = census_dir / "all_commits.jsonl"
    summary = _load_json(summary_path)
    ancestor_index = _load_json(index_path)
    rows = _load_jsonl(commits_path)
    if summary.get("artifact_kind") != "ai_descendant_repair_census":
        raise SystemExit(f"compressed census summary is malformed: {census_dir}")
    if ancestor_index.get("artifact_kind") != "observed_ai_ancestor_bitset_index":
        raise SystemExit(f"compressed census index is malformed: {census_dir}")
    if summary.get("repository_identity") != REPOSITORY_IDENTITY:
        raise SystemExit(f"compressed census repository mismatch: {census_dir}")
    if ancestor_index.get("repository_identity") != REPOSITORY_IDENTITY:
        raise SystemExit(f"compressed census index repository mismatch: {census_dir}")

    ai_shas_raw = ancestor_index.get("ai_shas")
    if not isinstance(ai_shas_raw, list):
        raise SystemExit(f"compressed census AI index is malformed: {census_dir}")
    ai_shas = [str(value) for value in ai_shas_raw]
    if (
        any(len(sha) != 40 for sha in ai_shas)
        or ai_shas != sorted(set(ai_shas))
        or ancestor_index.get("bit_order")
        != "least_significant_bit_is_ai_shas_index_zero"
    ):
        raise SystemExit(f"compressed census AI index is invalid: {census_dir}")
    bitset_width = ancestor_index.get("bitset_hex_width")
    if bitset_width != (len(ai_shas) + 3) // 4:
        raise SystemExit(f"compressed census bitset width mismatch: {census_dir}")

    route_counts: Counter[str] = Counter()
    fix_bits: dict[str, int] = {}
    seen_commits: set[str] = set()
    pair_count = 0
    for row in rows:
        sha = str(row.get("sha") or "")
        route = str(row.get("route") or "")
        if len(sha) != 40 or sha in seen_commits:
            raise SystemExit(f"compressed census commit rows are invalid: {census_dir}")
        seen_commits.add(sha)
        route_counts[route] += 1
        strict_count = row.get("strict_ai_ancestor_count")
        if not isinstance(strict_count, int) or strict_count < 0:
            raise SystemExit(f"compressed census ancestor count is invalid: {sha}")
        if route == "direct_ai_ancestry":
            encoded = row.get("ai_ancestor_bitset_hex")
            if not isinstance(encoded, str) or len(encoded) != bitset_width:
                raise SystemExit(f"compressed census bitset is invalid: {sha}")
            try:
                bits = int(encoded, 16)
            except ValueError as exc:
                raise SystemExit(f"compressed census bitset is invalid: {sha}") from exc
            if bits.bit_count() != strict_count or bits >> len(ai_shas):
                raise SystemExit(f"compressed census bitset count mismatch: {sha}")
            fix_bits[sha] = bits
            pair_count += strict_count
        elif strict_count != 0 or "ai_ancestor_bitset_hex" in row:
            raise SystemExit(f"compressed census route/bitset mismatch: {sha}")

    expected_routes = summary.get("all_commit_route_counts")
    required_true = (
        "all_commits_retained_once",
        "all_direct_ancestry_pairs_losslessly_represented",
        "all_parent_fixes_retained",
        "all_manifest_roots_scheduled_once",
    )
    if (
        len(rows) != summary.get("all_ref_commit_count")
        or len(ai_shas) != summary.get("observed_ai_commit_count")
        or len(fix_bits) != summary.get("direct_ancestry_root_count")
        or pair_count != summary.get("direct_ancestry_pair_count")
        or dict(sorted(route_counts.items())) != expected_routes
        or any(summary.get(field) is not True for field in required_true)
        or summary.get("hard_root_deletes") != 0
        or summary.get("model_labels_used_for_membership") != 0
        or canonical_sha256(rows) != summary.get("all_commit_rows_sha256")
        or canonical_sha256(ancestor_index) != summary.get("ancestor_index_sha256")
        or canonical_sha256(ai_shas) != ancestor_index.get("ai_shas_sha256")
    ):
        raise SystemExit(f"compressed census conservation failed: {census_dir}")

    source = {
        "directory": str(census_dir),
        "summary_sha256": _sha256(summary_path),
        "ancestor_index_sha256": _sha256(index_path),
        "all_commits_sha256": _sha256(commits_path),
        "all_ref_commit_count": len(rows),
        "observed_ai_commit_count": len(ai_shas),
        "direct_ancestry_root_count": len(fix_bits),
        "compressed_direct_pair_count": pair_count,
        "nonancestral_topology_fallback_commit_count": route_counts.get(
            "nonancestral_topology_fallback", 0
        ),
        "all_direct_pairs_retained": True,
        "hard_delete_count": 0,
    }
    membership = {
        "ai_index": {sha: index for index, sha in enumerate(ai_shas)},
        "fix_bits": fix_bits,
        "pair_count": pair_count,
    }
    return source, membership


def _compressed_census_contains(
    membership: Mapping[str, object], candidate_sha: str, fix_sha: str
) -> bool:
    ai_index = membership.get("ai_index")
    fix_bits = membership.get("fix_bits")
    if not isinstance(ai_index, Mapping) or not isinstance(fix_bits, Mapping):
        raise ValueError("compressed census membership is malformed")
    index = ai_index.get(candidate_sha)
    bits = fix_bits.get(fix_sha)
    return (
        isinstance(index, int) and isinstance(bits, int) and bool(bits & (1 << index))
    )


def _compressed_topology_closure_source(
    closure_dir: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    summary_path = closure_dir / "summary.json"
    index_path = closure_dir / "ai_index.json"
    partition_path = closure_dir / "pair_partition.jsonl"
    summary = _load_json(summary_path)
    ai_index_payload = _load_json(index_path)
    rows = _load_jsonl(partition_path)
    if summary.get("artifact_kind") != "observed_ai_full_topology_pair_closure":
        raise SystemExit(f"topology closure summary is malformed: {closure_dir}")
    if ai_index_payload.get("artifact_kind") != (
        "observed_ai_topology_pair_bitset_index"
    ):
        raise SystemExit(f"topology closure index is malformed: {closure_dir}")
    if summary.get("repository_identity") != REPOSITORY_IDENTITY or (
        ai_index_payload.get("repository_identity") != REPOSITORY_IDENTITY
    ):
        raise SystemExit(f"topology closure repository mismatch: {closure_dir}")
    raw_ai_shas = ai_index_payload.get("ai_shas")
    if not isinstance(raw_ai_shas, list):
        raise SystemExit(f"topology closure AI index is malformed: {closure_dir}")
    ai_shas = [str(value) for value in raw_ai_shas]
    width = (len(ai_shas) + 3) // 4
    if (
        ai_shas != sorted(set(ai_shas))
        or any(len(sha) != 40 for sha in ai_shas)
        or ai_index_payload.get("bit_order")
        != "least_significant_bit_is_ai_shas_index_zero"
        or ai_index_payload.get("bitset_hex_width") != width
        or canonical_sha256(ai_shas) != ai_index_payload.get("ai_shas_sha256")
    ):
        raise SystemExit(f"topology closure AI index is invalid: {closure_dir}")
    artifacts = summary.get("output_artifacts")
    if not isinstance(artifacts, Mapping):
        raise SystemExit(f"topology closure artifacts are malformed: {closure_dir}")
    partition_artifact = artifacts.get("pair_partition")
    index_artifact = artifacts.get("ai_index")
    if (
        not isinstance(partition_artifact, Mapping)
        or partition_artifact.get("sha256") != _sha256(partition_path)
        or not isinstance(index_artifact, Mapping)
        or index_artifact.get("sha256") != _sha256(index_path)
    ):
        raise SystemExit(f"topology closure artifact digest mismatch: {closure_dir}")

    all_bits = (1 << len(ai_shas)) - 1
    fix_bits: dict[str, int] = {}
    route_counts: Counter[str] = Counter()
    direct_count = residual_count = fix_before_count = identity_count = 0
    seen: set[str] = set()
    fields = (
        ("strict_ai_ancestor", "strict_ai_ancestor_count"),
        ("fix_precedes_ai", "fix_precedes_ai_count"),
        ("identity", "identity_pair_count"),
        ("incomparable_residual", "incomparable_residual_count"),
    )
    for row in rows:
        sha = str(row.get("sha") or "")
        if len(sha) != 40 or sha in seen:
            raise SystemExit(f"topology closure commit rows are invalid: {closure_dir}")
        seen.add(sha)
        route_counts[str(row.get("route") or "")] += 1
        decoded: dict[str, int] = {}
        for prefix, count_field in fields:
            encoded = row.get(f"{prefix}_bitset_hex")
            count = row.get(count_field)
            if (
                not isinstance(encoded, str)
                or len(encoded) != width
                or not isinstance(count, int)
            ):
                raise SystemExit(f"topology closure bitset is invalid: {sha}")
            try:
                bits = int(encoded, 16)
            except ValueError as exc:
                raise SystemExit(f"topology closure bitset is invalid: {sha}") from exc
            if bits.bit_count() != count or bits >> len(ai_shas):
                raise SystemExit(f"topology closure bitset count mismatch: {sha}")
            decoded[prefix] = bits
        strict = decoded["strict_ai_ancestor"]
        fix_before = decoded["fix_precedes_ai"]
        identity = decoded["identity"]
        residual = decoded["incomparable_residual"]
        if (
            strict & (fix_before | identity | residual)
            or fix_before & (identity | residual)
            or identity & residual
            or (strict | fix_before | identity | residual) != all_bits
        ):
            raise SystemExit(f"topology closure partition overlap at {sha}")
        retained = strict | residual
        if retained:
            fix_bits[sha] = retained
        direct_count += strict.bit_count()
        residual_count += residual.bit_count()
        fix_before_count += fix_before.bit_count()
        identity_count += identity.bit_count()

    full_count = len(rows) * len(ai_shas)
    if (
        len(rows) != summary.get("all_ref_commit_count")
        or len(ai_shas) != summary.get("observed_ai_commit_count")
        or full_count != summary.get("full_cartesian_pair_count")
        or direct_count != summary.get("strict_ai_ancestor_pair_count")
        or residual_count != summary.get("incomparable_residual_pair_count")
        or fix_before_count != summary.get("fix_strictly_precedes_ai_pair_count")
        or identity_count != summary.get("identity_pair_count")
        or direct_count + residual_count + fix_before_count + identity_count
        != full_count
        or summary.get("pair_partition_conserved") is not True
        or summary.get("direct_pair_count_matches_census") is not True
        or summary.get("hard_heuristic_filter_count") != 0
        or summary.get("model_labels_used_for_membership") != 0
    ):
        raise SystemExit(f"topology closure conservation failed: {closure_dir}")
    candidate_pair_count = direct_count + residual_count
    source = {
        "directory": str(closure_dir),
        "summary_sha256": _sha256(summary_path),
        "ai_index_sha256": _sha256(index_path),
        "pair_partition_sha256": _sha256(partition_path),
        "all_ref_commit_count": len(rows),
        "observed_ai_commit_count": len(ai_shas),
        "compressed_candidate_pair_count": candidate_pair_count,
        "compressed_direct_pair_count": direct_count,
        "compressed_incomparable_residual_pair_count": residual_count,
        "proof_excluded_pair_count": fix_before_count + identity_count,
        "nonancestral_topology_fallback_commit_count": route_counts.get(
            "nonancestral_topology_fallback", 0
        ),
        "all_candidate_pairs_retained": True,
        "hard_delete_count": 0,
    }
    membership = {
        "ai_index": {sha: index for index, sha in enumerate(ai_shas)},
        "fix_bits": fix_bits,
        "pair_count": candidate_pair_count,
    }
    return source, membership


def _observation(row: Mapping[str, object], source_index: int) -> dict[str, object]:
    return {
        "source_index": source_index,
        "source_kind": row.get("source_kind", "model_route"),
        "model": row.get("model"),
        "disposition": row.get("disposition"),
        "causality": row.get("causality"),
        "reason": row.get("reason"),
        "input_priority_rank": row.get("input_priority_rank"),
        "retained": row.get("retained"),
    }


def _aggregate_edges(
    route_rows: Iterable[tuple[int, Mapping[str, object]]],
    confirmed_edges: Mapping[tuple[str, str], tuple[str, str, str]],
    rejected_edges: Mapping[tuple[str, str], tuple[str, str]],
    alias_edges: Mapping[tuple[str, str], tuple[str, str, tuple[str, str]]]
    | None = None,
) -> list[dict[str, object]]:
    alias_edges = alias_edges or {}
    observations: defaultdict[tuple[str, str], list[dict[str, object]]] = defaultdict(
        list
    )
    for source_index, row in route_rows:
        candidate_sha = str(row.get("candidate_sha", ""))
        fix_sha = str(row.get("fix_sha", ""))
        if len(candidate_sha) != 40 or len(fix_sha) != 40:
            raise ValueError("route row has malformed candidate/fix edge")
        if row.get("retained") is not True:
            raise ValueError("route row dropped a candidate edge")
        observations[(candidate_sha, fix_sha)].append(_observation(row, source_index))

    all_edges = (
        set(observations)
        | set(confirmed_edges)
        | set(rejected_edges)
        | set(alias_edges)
    )
    ledger: list[dict[str, object]] = []
    for candidate_sha, fix_sha in sorted(
        all_edges, key=lambda value: (value[1], value[0])
    ):
        edge = (candidate_sha, fix_sha)
        model_observations = observations.get(edge, [])
        dispositions = {str(item.get("disposition")) for item in model_observations}
        if edge in confirmed_edges:
            adjudication, evidence_id, mechanism_group = confirmed_edges[edge]
            status = "CONFIRMED_TRUE_POSITIVE"
            evidence = evidence_id
            canonical_edge: tuple[str, str] | None = edge
        elif edge in rejected_edges:
            adjudication, evidence_id = rejected_edges[edge]
            status = "REJECTED_NONCAUSAL"
            evidence = evidence_id
            mechanism_group = None
            canonical_edge = None
        elif edge in alias_edges:
            adjudication, evidence_id, canonical_edge = alias_edges[edge]
            if canonical_edge not in confirmed_edges:
                raise ValueError(f"alias edge has no confirmed canonical edge: {edge}")
            status = "PATCH_EQUIVALENT_ALIAS"
            evidence = evidence_id
            mechanism_group = confirmed_edges[canonical_edge][2]
        elif "PROMOTE" in dispositions:
            adjudication = "PENDING_CAUSAL_REVIEW"
            status = "MODEL_PROMOTED_REVIEW_REQUIRED"
            evidence = None
            mechanism_group = None
            canonical_edge = None
        elif "BLOCKED" in dispositions:
            adjudication = "BLOCKED_SPLIT_AND_RETRY"
            status = "TRANSPORT_OR_PARSE_RETRY_REQUIRED"
            evidence = None
            mechanism_group = None
            canonical_edge = None
        else:
            adjudication = "UNADJUDICATED_RETAINED"
            status = "DEFERRED_REVIEW_BACKLOG"
            evidence = None
            mechanism_group = None
            canonical_edge = None
        ledger.append(
            {
                "repository_identity": REPOSITORY_IDENTITY,
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "status": status,
                "adjudication": adjudication,
                "evidence_id": evidence,
                "mechanism_group": mechanism_group,
                "canonical_candidate_sha": (
                    canonical_edge[0] if canonical_edge is not None else None
                ),
                "canonical_fix_sha": (
                    canonical_edge[1] if canonical_edge is not None else None
                ),
                "candidate_retained": True,
                "model_observations": model_observations,
            }
        )
    return ledger


def _build_payload(
    *,
    route_sources: list[dict[str, object]],
    ledger: list[dict[str, object]],
    evidence: Mapping[str, Mapping[str, object]],
    inventory_sources: list[dict[str, object]] | None = None,
    compressed_candidate_sources: list[dict[str, object]] | None = None,
    compressed_memberships: list[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    compressed_candidate_sources = compressed_candidate_sources or []
    compressed_memberships = compressed_memberships or []
    if len(compressed_candidate_sources) != len(compressed_memberships):
        raise ValueError("compressed candidate source/membership count mismatch")
    statuses = Counter(str(row["status"]) for row in ledger)
    confirmed = [row for row in ledger if row["status"] == "CONFIRMED_TRUE_POSITIVE"]
    rejected = [row for row in ledger if row["status"] == "REJECTED_NONCAUSAL"]
    aliases = [row for row in ledger if row["status"] == "PATCH_EQUIVALENT_ALIAS"]
    review_required = [
        row
        for row in ledger
        if row["status"]
        in {
            "MODEL_PROMOTED_REVIEW_REQUIRED",
            "TRANSPORT_OR_PARSE_RETRY_REQUIRED",
            "DEFERRED_REVIEW_BACKLOG",
        }
    ]
    compressed_pair_count = sum(
        int(
            source.get(
                "compressed_candidate_pair_count",
                source["compressed_direct_pair_count"],
            )
        )
        for source in compressed_candidate_sources
    )
    compressed_direct_pair_count = sum(
        int(source["compressed_direct_pair_count"])
        for source in compressed_candidate_sources
    )
    compressed_residual_pair_count = sum(
        int(source.get("compressed_incomparable_residual_pair_count", 0))
        for source in compressed_candidate_sources
    )
    if len(compressed_candidate_sources) > 1:
        raise ValueError("multiple compressed censuses need an explicit union proof")
    compressed_overlap_count = sum(
        any(
            _compressed_census_contains(
                membership,
                str(row["candidate_sha"]),
                str(row["fix_sha"]),
            )
            for membership in compressed_memberships
        )
        for row in ledger
    )
    finite_candidate_union_edge_count = (
        compressed_pair_count + len(ledger) - compressed_overlap_count
    )
    topology_fallback_commit_count = sum(
        int(source["nonancestral_topology_fallback_commit_count"])
        for source in compressed_candidate_sources
    )
    conservation_passed = bool(
        len(ledger) == sum(statuses.values())
        and all(row["candidate_retained"] is True for row in ledger)
        and not (set(CONFIRMED_EDGES) & set(REJECTED_EDGES))
        and not (set(CONFIRMED_EDGES) & set(PATCH_EQUIVALENT_ALIAS_EDGES))
        and not (set(REJECTED_EDGES) & set(PATCH_EQUIVALENT_ALIAS_EDGES))
        and all(
            (
                source.get("all_candidate_pairs_retained") is True
                or source.get("all_direct_pairs_retained") is True
            )
            and source.get("hard_delete_count") == 0
            for source in compressed_candidate_sources
        )
    )
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_recall_conserving_causal_adjudication_ledger",
        "repository_identity": REPOSITORY_IDENTITY,
        "route_sources": route_sources,
        "inventory_sources": inventory_sources or [],
        "compressed_candidate_sources": compressed_candidate_sources,
        "evidence_artifacts": evidence,
        "summary": {
            "finite_edge_count": len(ledger),
            "explicit_adjudication_edge_count": len(ledger),
            "compressed_candidate_pair_count": compressed_pair_count,
            "compressed_direct_ancestry_pair_count": compressed_direct_pair_count,
            "compressed_incomparable_residual_pair_count": (
                compressed_residual_pair_count
            ),
            "compressed_overlap_with_explicit_edge_count": (compressed_overlap_count),
            "finite_candidate_union_edge_count": finite_candidate_union_edge_count,
            "nonancestral_topology_fallback_commit_count": (
                topology_fallback_commit_count
            ),
            "status_counts": dict(sorted(statuses.items())),
            "confirmed_true_positive_edge_count": len(confirmed),
            "confirmed_unique_candidate_count": len(
                {str(row["candidate_sha"]) for row in confirmed}
            ),
            "confirmed_mechanism_group_count": len(
                {
                    str(row["mechanism_group"])
                    for row in confirmed
                    if row["mechanism_group"] is not None
                }
            ),
            "rejected_noncausal_edge_count": len(rejected),
            "patch_equivalent_alias_edge_count": len(aliases),
            "review_required_edge_count": len(review_required),
        },
        "review_order": [
            "MODEL_PROMOTED_REVIEW_REQUIRED",
            "TRANSPORT_OR_PARSE_RETRY_REQUIRED",
            "DEFERRED_REVIEW_BACKLOG",
        ],
        "edge_ledger": ledger,
        "conservation": {
            "finite_edge_count": len(ledger),
            "partitioned_edge_count": sum(statuses.values()),
            "candidate_retained_count": sum(
                row["candidate_retained"] is True for row in ledger
            ),
            "hard_delete_count": 0,
            "compressed_candidate_pair_count": compressed_pair_count,
            "compressed_direct_pair_count": compressed_direct_pair_count,
            "compressed_incomparable_residual_pair_count": (
                compressed_residual_pair_count
            ),
            "compressed_direct_pair_overlap_with_explicit_ledger_count": (
                compressed_overlap_count
            ),
            "finite_candidate_union_edge_count": finite_candidate_union_edge_count,
            "compressed_pair_expansion_required": False,
            "model_negative_as_ground_truth_count": 0,
            "passed": conservation_passed,
        },
        "claim_boundary": (
            "Explicit edge statuses cover the union of supplied retained candidate "
            "inventories, route artifacts, and independently witnessed edges. The "
            "compressed source losslessly retains every strict observed-AI-ancestor "
            "pair and, when supplied, every graph-incomparable residual pair without "
            "materializing the deferred rows. Strict reverse direction and identity "
            "are proof exclusions; squash, cherry-pick, copy, and cross-branch pairs "
            "remain retained. Model DEFER is a "
            "scheduling state, not a negative label. Confirmed edges are commit/fix "
            "causal members and must not be counted as distinct vulnerabilities. "
            "Patch-equivalent aliases remain explicit retained edges but point to "
            "one confirmed canonical carrier and do not inflate candidate, edge, "
            "or mechanism headline counts. "
            "Unobserved AI use and cross-repository copies remain outside this "
            "artifact."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace_root = args.workspace_root.resolve()
    repository = args.repository.resolve()
    evidence, carrier_proofs = _verify_evidence(workspace_root)

    adjudicated_edges = (
        set(CONFIRMED_EDGES) | set(REJECTED_EDGES) | set(PATCH_EQUIVALENT_ALIAS_EDGES)
    )
    for candidate_sha, fix_sha in adjudicated_edges:
        _verify_commit(repository, candidate_sha)
        _verify_commit(repository, fix_sha)
        if _is_ancestor(repository, candidate_sha, fix_sha):
            continue
        edge = (candidate_sha, fix_sha)
        proof = carrier_proofs.get(edge)
        if edge in CONFIRMED_EDGES:
            registered_evidence = CONFIRMED_EDGES[edge][1]
        elif edge in REJECTED_EDGES:
            registered_evidence = REJECTED_EDGES[edge][1]
        else:
            registered_evidence = PATCH_EQUIVALENT_ALIAS_EDGES[edge][1]
        if (
            proof is None
            or proof["evidence_id"] != registered_evidence
            or _is_ancestor(repository, fix_sha, candidate_sha)
        ):
            raise SystemExit(
                f"non-ancestral adjudicated edge lacks carrier proof: "
                f"{candidate_sha}..{fix_sha}"
            )
        carrier_sha = proof["carrier_sha"]
        _verify_commit(repository, carrier_sha)
        if carrier_sha == fix_sha or not _is_ancestor(repository, carrier_sha, fix_sha):
            raise SystemExit(
                f"invalid carrier ancestry for adjudicated edge: "
                f"{candidate_sha}..{fix_sha} via {carrier_sha}"
            )

    route_sources: list[dict[str, object]] = []
    route_rows: list[tuple[int, Mapping[str, object]]] = []
    for source_index, route_dir in enumerate(args.route_dir):
        source, rows = _route_source(route_dir.resolve())
        route_sources.append(source)
        route_rows.extend((source_index, row) for row in rows)

    inventory_sources: list[dict[str, object]] = []
    next_source_index = len(route_sources)
    for inventory_offset, inventory_path in enumerate(args.candidate_inventory):
        source, rows = _inventory_source(inventory_path.resolve())
        inventory_sources.append(source)
        source_index = next_source_index + inventory_offset
        route_rows.extend((source_index, row) for row in rows)

    compressed_candidate_sources: list[dict[str, object]] = []
    compressed_memberships: list[Mapping[str, object]] = []
    if args.compressed_census_dir is not None and args.topology_closure_dir is not None:
        raise SystemExit(
            "--compressed-census-dir and --topology-closure-dir are alternative "
            "representations of the same pair universe"
        )
    if args.compressed_census_dir is not None:
        source, membership = _compressed_census_source(
            args.compressed_census_dir.resolve()
        )
        compressed_candidate_sources.append(source)
        compressed_memberships.append(membership)
    if args.topology_closure_dir is not None:
        source, membership = _compressed_topology_closure_source(
            args.topology_closure_dir.resolve()
        )
        compressed_candidate_sources.append(source)
        compressed_memberships.append(membership)

    ledger = _aggregate_edges(
        route_rows,
        CONFIRMED_EDGES,
        REJECTED_EDGES,
        PATCH_EQUIVALENT_ALIAS_EDGES,
    )
    payload = _build_payload(
        route_sources=route_sources,
        ledger=ledger,
        evidence=evidence,
        inventory_sources=inventory_sources,
        compressed_candidate_sources=compressed_candidate_sources,
        compressed_memberships=compressed_memberships,
    )
    if payload["conservation"]["passed"] is not True:
        raise SystemExit("ledger conservation failed")
    _atomic_json(args.output, payload)
    summary = payload["summary"]
    print("Coolify causal adjudication ledger frozen")
    print(f"  finite edges : {summary['finite_edge_count']}")
    print(f"  finite union : {summary['finite_candidate_union_edge_count']}")
    print(f"  confirmed    : {summary['confirmed_true_positive_edge_count']}")
    print(f"  rejected     : {summary['rejected_noncausal_edge_count']}")
    print(f"  review queue : {summary['review_required_edge_count']}")
    print(f"  output       : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
