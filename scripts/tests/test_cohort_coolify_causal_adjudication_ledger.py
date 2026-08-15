"""Tests for the recall-conserving Coolify causal adjudication ledger."""

from __future__ import annotations

import json

import cohort_coolify_causal_adjudication_ledger as ledger


def _row(candidate: str, fix: str, disposition: str) -> dict[str, object]:
    return {
        "candidate_sha": candidate,
        "fix_sha": fix,
        "model": "test-model",
        "disposition": disposition,
        "causality": "",
        "reason": "test",
        "input_priority_rank": 1,
        "retained": True,
    }


def test_independent_witness_overrides_model_defer() -> None:
    candidate = "a" * 40
    fix = "1" * 40
    rows = ledger._aggregate_edges(
        [(0, _row(candidate, fix, "DEFER"))],
        {(candidate, fix): ("CONFIRMED_TEST", "evidence", "mechanism")},
        {},
    )

    assert len(rows) == 1
    assert rows[0]["status"] == "CONFIRMED_TRUE_POSITIVE"
    assert rows[0]["adjudication"] == "CONFIRMED_TEST"
    assert rows[0]["candidate_retained"] is True


def test_exact_negative_witness_overrides_model_promotion() -> None:
    candidate = "b" * 40
    fix = "2" * 40
    rows = ledger._aggregate_edges(
        [(0, _row(candidate, fix, "PROMOTE"))],
        {},
        {(candidate, fix): ("REJECTED_TEST", "negative_evidence")},
    )

    assert rows[0]["status"] == "REJECTED_NONCAUSAL"
    assert rows[0]["adjudication"] == "REJECTED_TEST"


def test_patch_equivalent_alias_is_retained_without_inflating_confirmation() -> None:
    canonical = ("c" * 40, "3" * 40)
    alias = ("a" * 40, canonical[1])
    rows = ledger._aggregate_edges(
        [(0, _row(*alias, "PROMOTE"))],
        {canonical: ("CONFIRMED_TEST", "carrier_evidence", "one_mechanism")},
        {},
        {
            alias: (
                "PATCH_EQUIVALENT_ALIAS_TEST",
                "carrier_evidence",
                canonical,
            )
        },
    )
    by_edge = {(str(row["candidate_sha"]), str(row["fix_sha"])): row for row in rows}

    assert by_edge[canonical]["status"] == "CONFIRMED_TRUE_POSITIVE"
    assert by_edge[alias]["status"] == "PATCH_EQUIVALENT_ALIAS"
    assert by_edge[alias]["canonical_candidate_sha"] == canonical[0]
    assert by_edge[alias]["canonical_fix_sha"] == canonical[1]
    assert by_edge[alias]["candidate_retained"] is True


def test_model_states_schedule_without_deleting() -> None:
    fix = "3" * 40
    promoted = "c" * 40
    blocked = "d" * 40
    deferred = "e" * 40
    rows = ledger._aggregate_edges(
        [
            (0, _row(promoted, fix, "DEFER")),
            (1, _row(promoted, fix, "PROMOTE")),
            (0, _row(blocked, fix, "BLOCKED")),
            (0, _row(deferred, fix, "DEFER")),
        ],
        {},
        {},
    )
    by_candidate = {row["candidate_sha"]: row for row in rows}

    assert by_candidate[promoted]["status"] == "MODEL_PROMOTED_REVIEW_REQUIRED"
    assert by_candidate[blocked]["status"] == "TRANSPORT_OR_PARSE_RETRY_REQUIRED"
    assert by_candidate[deferred]["status"] == "DEFERRED_REVIEW_BACKLOG"
    assert all(row["candidate_retained"] is True for row in rows)


def test_carrier_edge_proofs_require_complete_patch_equivalence_checks(
    tmp_path,
) -> None:
    candidate = "a" * 40
    carrier = "b" * 40
    fix = "c" * 40
    checks = {
        "candidate_and_fix_are_graph_incomparable": True,
        "candidate_and_carrier_share_focal_patch_behavior": True,
        "carrier_strictly_precedes_fix": True,
        "patch_id_inspection_complete": True,
        "stable_patch_id_recomputed": True,
    }
    payload = {
        "artifact_kind": "coolify_topology_carrier_causal_batch_witness",
        "confirmed_edges": [
            {"candidate_sha": candidate, "fix_sha": fix},
        ],
        "case_results": [
            {
                "candidate_sha": candidate,
                "carrier_sha": carrier,
                "fix_sha": fix,
                "checks": checks,
                "passed": True,
            }
        ],
    }

    proofs = ledger._carrier_edge_proofs(
        payload,
        evidence_id="carrier_test",
        target=tmp_path / "witness.json",
    )

    assert proofs[(candidate, fix)] == {
        "evidence_id": "carrier_test",
        "carrier_sha": carrier,
    }


def test_payload_partitions_every_edge_once() -> None:
    rows = [
        {
            "candidate_sha": "f" * 40,
            "fix_sha": "4" * 40,
            "status": "MODEL_PROMOTED_REVIEW_REQUIRED",
            "adjudication": "PENDING_CAUSAL_REVIEW",
            "evidence_id": None,
            "mechanism_group": None,
            "candidate_retained": True,
            "model_observations": [],
        }
    ]
    payload = ledger._build_payload(route_sources=[], ledger=rows, evidence={})

    assert payload["summary"]["finite_edge_count"] == 1
    assert payload["summary"]["review_required_edge_count"] == 1
    assert payload["conservation"]["partitioned_edge_count"] == 1
    assert payload["conservation"]["hard_delete_count"] == 0
    assert payload["conservation"]["passed"] is True


def test_lossless_candidate_inventory_normalizes_reduction_rows(tmp_path) -> None:
    candidate = "a" * 40
    fix = "1" * 40
    inventory = tmp_path / "candidates.jsonl"
    inventory.write_text(
        json.dumps(
            {
                "sha": candidate,
                "fix_sha": fix,
                "priority_rank": 7,
                "retained": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    source, rows = ledger._inventory_source(inventory)

    assert source["inventory_count"] == 1
    assert source["all_candidates_retained"] is True
    assert rows == [
        {
            "candidate_sha": candidate,
            "fix_sha": fix,
            "model": None,
            "disposition": "INVENTORY_RETAINED",
            "causality": None,
            "reason": "lossless candidate inventory membership",
            "input_priority_rank": 7,
            "retained": True,
            "source_kind": "candidate_inventory",
        }
    ]


def test_full_lineage_recovery_edges_are_registered() -> None:
    expected = {
        (
            "cb1f571eb4b36da153d559246534f75683117299",
            "97868c32640a9875f1f6f0e4d215d2ad6655e65a",
        ),
        (
            "cb1f571eb4b36da153d559246534f75683117299",
            "468d5fe7d77dfe1f1f34770a81e45062c272c92d",
        ),
        (
            "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
            "468d5fe7d77dfe1f1f34770a81e45062c272c92d",
        ),
        (
            "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
            "30c0b37689801707c791d2f725773bfb14072bb2",
        ),
        (
            "7a008c859ad68332de72683ddb751e40a6487c38",
            "188c86ca45801c7ea2c4a8022b9ed90d73c1068e",
        ),
    }

    assert expected <= set(ledger.CONFIRMED_EDGES)
    assert all(
        ledger.CONFIRMED_EDGES[edge][1] == "full_lineage_recovery" for edge in expected
    )


def test_post_execution_path_restore_edge_is_registered() -> None:
    edge = (
        "dae680317385f2a495b0ae2b1687d2ce8f555256",
        "23f9156c7306b221101f1ebbe4d3c6b5e2522acd",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "security_frontier_preservation"


def test_exact_preimage_recovery_edges_are_registered() -> None:
    expected = {
        (
            "1094ab7a46452ac0e42e60e5c1e705df6484f95f",
            "2eeb2b94ec3385fcd066cf43e9c8c108be7cdeea",
        ),
        (
            "f8e3bb54a3cb48da842351cc75490c8a20134807",
            "f86ccfaa9af572a5487da8ea46b0a125a4854cf6",
        ),
        (
            "bf0040597194e3a9b835b7a800b735f65bc2c34c",
            "893093fad3cb6a54fa28be7da6991654460153fa",
        ),
    }

    assert expected <= set(ledger.CONFIRMED_EDGES)
    assert all(
        ledger.CONFIRMED_EDGES[edge][1] == "exact_preimage_recovery"
        for edge in expected
    )


def test_github_install_state_edge_is_registered() -> None:
    edge = (
        "5a7408a919e1128e75f23c2598926814685928f6",
        "858b1906ec34e76950262e18135c0ecc5d22eb15",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "github_install_state"


def test_github_install_maintenance_activation_edge_is_registered() -> None:
    edge = (
        "158d54712f4ed212750f0b1da6d98d761bd97454",
        "5a7408a919e1128e75f23c2598926814685928f6",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "github_install_maintenance_activation"


def test_onboarding_refresh_regression_edge_is_registered() -> None:
    edge = (
        "7a008c859ad68332de72683ddb751e40a6487c38",
        "04625591eaafac64db412b21b0f4c4c0f82fc8ad",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "onboarding_refresh_regression"


def test_sensitive_model_default_edges_are_registered() -> None:
    expected = {
        (
            "27879377a07a88d2070a2939b2856cd0273eac52",
            "81a3bb0f0769e5a765e77649d002ea6acf9a667f",
        ),
        (
            "7061eacfa506f92a8868c531fa52533e3563adc6",
            "81a3bb0f0769e5a765e77649d002ea6acf9a667f",
        ),
        (
            "9f46586d4aaa93f2b526d67833ba70ef58b9893e",
            "81a3bb0f0769e5a765e77649d002ea6acf9a667f",
        ),
    }

    assert expected <= set(ledger.CONFIRMED_EDGES)
    assert all(
        ledger.CONFIRMED_EDGES[edge][1] == "sensitive_model_defaults"
        for edge in expected
    )


def test_volume_shell_hardening_edge_is_registered() -> None:
    edge = (
        "d2064dd4998694cda2eabd00149f7c4d1e94c699",
        "410a9a6195a2b939d4a429f6c464ff56e61177f8",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "volume_shell_hardening"


def test_volume_parser_preservation_edge_is_registered() -> None:
    edge = (
        "a219f2e80e42c14d5d59a3e6816fcb91b771e4a9",
        "468d5fe7d77dfe1f1f34770a81e45062c272c92d",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "volume_parser_preservation"
    assert (
        ledger.CONFIRMED_EDGES[edge][2]
        == "docker_compose_volume_validation_underacceptance"
    )


def test_datalist_binding_origin_edge_is_registered() -> None:
    edge = (
        "6297ac6c88a712b8e867d6442ea81aa7abc8cb73",
        "188c86ca45801c7ea2c4a8022b9ed90d73c1068e",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "datalist_binding_origin"
    assert ledger.CONFIRMED_EDGES[edge][2] == "form_datalist_single_select_reactivity"


def test_onboarding_creation_path_edge_is_registered() -> None:
    edge = (
        "04625591eaafac64db412b21b0f4c4c0f82fc8ad",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "onboarding_creation_path"
    assert (
        ledger.CONFIRMED_EDGES[edge][2] == "onboarding_resource_creation_authorization"
    )


def test_oauth_bulk_mutation_preservation_edge_is_registered() -> None:
    edge = (
        "b1a68df65caef6df06c9495a817ff4c340a44d39",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "oauth_bulk_mutation_preservation"
    assert (
        ledger.CONFIRMED_EDGES[edge][2] == "oauth_bulk_settings_mutation_authorization"
    )


def test_private_key_hydration_preservation_edge_is_registered() -> None:
    edge = (
        "f77ad4cbd9ee82d3015e36ab8d23121f1a8143dd",
        "f7427fdea03ccd0da20ddce590c6eb6fd2119fd9",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "private_key_hydration_preservation"
    assert ledger.CONFIRMED_EDGES[edge][2] == "private_key_secret_view_authorization"


def test_backup_upload_validation_edge_is_registered() -> None:
    edge = (
        "af0a8badb3cd9f470cb55c5f714263f63425d40b",
        "2d63d51237c34db29cc9d8dacd81400483f0eb27",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge] == (
        "CONFIRMED_AI_INCOMPLETE_BACKUP_UPLOAD_FILE_TYPE_VALIDATION",
        "backup_upload_validation",
        "database_backup_upload_validation",
    )


def test_git_ls_remote_incomplete_hardening_edges_are_registered() -> None:
    branch_coverage = (
        "b81baff4b178b8264a9ae4ab704f7902c841fa1b",
        "8f8c90b7ae8da113c63315c2e5b6f1bf81da1964",
    )
    nested_shell = {
        (
            "b81baff4b178b8264a9ae4ab704f7902c841fa1b",
            "992b922df35b6f7d57be8c664a3d51b1207854cd",
        ),
        (
            "8f8c90b7ae8da113c63315c2e5b6f1bf81da1964",
            "992b922df35b6f7d57be8c664a3d51b1207854cd",
        ),
    }

    assert ledger.CONFIRMED_EDGES[branch_coverage] == (
        "CONFIRMED_AI_INCOMPLETE_GIT_LS_REMOTE_BRANCH_COVERAGE",
        "git_ls_remote_incomplete_hardening",
        "git_ls_remote_deployment_type_coverage",
    )
    assert all(
        ledger.CONFIRMED_EDGES[edge]
        == (
            "CONFIRMED_AI_INCOMPLETE_NESTED_SHELL_ESCAPING",
            "git_ls_remote_incomplete_hardening",
            "nested_execute_in_docker_shell_quoting",
        )
        for edge in nested_shell
    )


def test_s3_restore_command_injection_edge_is_registered() -> None:
    edge = (
        "94560ea6c7a841840638e7c73a4b5d6da2afe713",
        "9113ed714f46d836bbc6389287f40dc4e2064f9f",
    )

    assert ledger.CONFIRMED_EDGES[edge] == (
        "CONFIRMED_AI_INCOMPLETE_S3_RESTORE_SHELL_HARDENING",
        "s3_restore_command_injection",
        "s3_restore_bucket_path_command_injection",
    )


def test_preimage_recovery_batch_edges_are_registered() -> None:
    expected = {
        (
            "336fa0c7143a8ceca319dc1e7b6f12ca2b923708",
            "fb2d477e48764d7dd9139db13ef26f7eb7809221",
        ): "team_policy_target_team_context",
        (
            "90ddbb357231ca3808f277eb87a63c8f650417e6",
            "3911a0305c0177c5bb77659883b3c59709004570",
        ): "api_token_expiration_warning_persistence",
        (
            "0fce7fa9481aa1bcca06d767075684a11e032c79",
            "c7f014017b753a53e33a4eb7d2950f7302d971b5",
        ): "outbound_url_multi_address_validation",
        (
            "564cd8368bb8b4485b3981060dace37645b20f52",
            "c7f014017b753a53e33a4eb7d2950f7302d971b5",
        ): "webhook_dns_resolution_validation",
        (
            "413dee5d8c97edefd4b359831d6db766b1235c9c",
            "0b8c75f8edb12bc9084c1b6cd844643d7ae95701",
        ): "webhook_runtime_url_validation",
        (
            "945cce95870b2f18b13f8f509677ad3823d2b97f",
            "c8a332a3bc935064dcbb2f7703b1edeb2becfaae",
        ): "orphan_cleanup_placeholder_server_filter",
        (
            "cdf6b5f1611369762406290fa05d11e60206630a",
            "c6c7ec1c317883fc0967f911ac4d6d47f83ab069",
        ): "preview_compose_domain_validation",
        (
            "62c394d3a1dba6aa6d4ab1456b7a7911f6b72639",
            "a8000ac2ad2fa0882223b8360028e21e9aaa6ad4",
        ): "hetzner_public_ip_protocol_validation",
        (
            "62c394d3a1dba6aa6d4ab1456b7a7911f6b72639",
            "4d836888964ee5a1bea7089d3fe6c886012f0bff",
        ): "hetzner_api_exception_disclosure",
    }

    assert expected.keys() <= ledger.CONFIRMED_EDGES.keys()
    assert all(
        ledger.CONFIRMED_EDGES[edge][1] == "preimage_recovery_batch"
        and ledger.CONFIRMED_EDGES[edge][2] == mechanism
        for edge, mechanism in expected.items()
    )


def test_exact_delta_causal_batch_edges_are_registered() -> None:
    expected = {
        (
            "f81640e316f3864bb0e40236c971d95e9aa9b04e",
            "498b189286c0c2dacacf9d90f9a3e7d8d9d6b4d1",
        ): "excluded_container_default_status",
        (
            "498b189286c0c2dacacf9d90f9a3e7d8d9d6b4d1",
            "e3746a4b887441169a86dde955ff3324f5f9c273",
        ): "unknown_container_health_preservation",
        (
            "c1518ba1c0be36da42b6cef06df4b042f5733b01",
            "809d9b21fa9609de2ce9b49bb838c079598da876",
        ): "manual_webhook_repository_casefold",
        (
            "4ed7a4238a500427ac53684331ffc752e94a2805",
            "6ea563c6ac7599a8923a8288e43d780301360d8b",
        ): "image_retention_runtime_images",
        (
            "4706bc23aa86ce1abdc9e7503e8ce41d1551d51c",
            "8c40cc607afa9e6c963c5b8a866f847be0a5ec05",
        ): "service_name_last_separator",
        (
            "e4810a28d28b5e223a4d8193fef82eb3ae06cf41",
            "b00d8902f4a74a5f2c4c9bc75aea9b0411b20261",
        ): "duplicate_proxy_restart_notifications",
        (
            "5d73b76a44198dfbc8533010a348a1703793094d",
            "cb0f2301f5200daee834498bb5196fafc12daabc",
        ): "null_versions_cache_assignment",
        (
            "d9774d29684987deb2b9a7f4a2af135af329a722",
            "cd10796612bdff7993995afa0d978d070341e7a1",
        ): "running_version_downgrade_guard",
        (
            "97550f40669fe3c82dace16dbe875905bf2e1058",
            "b602fef4dbcead34ed68556039c737d22eaf5c12",
        ): "deployment_technical_detail_disclosure",
        (
            "7069236714055571f6d90a56a513e368683919d7",
            "e01b8a057e6437cf2a2bafe61db67943acc7bb39",
        ): "hetzner_pending_ip_retention",
        (
            "c42fb813470487425645a9ff01f74ba866f1443f",
            "2fc870c6eb0818969fd6ce63bc8b357501199c60",
        ): "proxy_restart_debounce_guard",
        (
            "0f54c194d7a3ec63c41d707202f53b57e4abe7d7",
            "b5416859e5b5147831fafcad2fe848b6049eb728",
        ): "garage_rpc_secret_length",
        (
            "2cf915aed813c666fadb43bc8e2376c460ffcaf9",
            "2743229cc49c342311f5daa55221f170bbcf70dc",
        ): "user_team_null_context",
        (
            "01635e8b80ae368c8fe89ca486bffa6f9932b08d",
            "246e3cd8a2861f8d981f5f917819deb4fb6c6d35",
        ): "sudo_keyword_prefix_collision",
        (
            "5b9146d8df7ab15c874c5aa49f3c23d6b5cdf54d",
            "9b060958aad7a02ef15dc6d8503e411b25ca523f",
        ): "ray_parser_debug_hooks",
        (
            "dc15bee980ed823960b3ce97e6ed21191ab79e28",
            "9b060958aad7a02ef15dc6d8503e411b25ca523f",
        ): "ray_webhook_debug_hooks",
        (
            "d2d9c1b2bcaccaaba826bb06816ea5dd7679088e",
            "14bba8ba86a2a50ce7d986066ba2befe23f1d7ef",
        ): "sentinel_status_debug_logging",
        (
            "70fb4c6869ed9e72ed62b9e409f29819d42632b9",
            "ac9eca3c051e15a52e1ab5f655d3011a21c9b112",
        ): "exited_container_health_suffix",
        (
            "42f916dce235bbff4d49d0a1362608c036092e4d",
            "a2e5b2d67d8cc05fd60a2d97e098ccc401562a25",
        ): "finished_deployment_terminal_state",
        (
            "53d1ad48cddb52cb94e6179575af7647d5ff5fc4",
            "a3df33a4e06c1df38e51c9ec81951402e0a6914a",
        ): "webhook_settings_migration_order",
    }

    assert expected.keys() <= ledger.CONFIRMED_EDGES.keys()
    assert all(
        ledger.CONFIRMED_EDGES[edge][1] == "exact_delta_causal_batch"
        and ledger.CONFIRMED_EDGES[edge][2] == mechanism
        for edge, mechanism in expected.items()
    )


def test_exact_delta_causal_batch2_edges_are_registered() -> None:
    batch = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "exact_delta_causal_batch2"
    }

    assert len(batch) == 4
    assert {value[2] for value in batch.values()} == {
        "sentinel_status_runtime_debug_payload",
        "hetzner_create_server_ray_payload",
        "cloud_init_script_syntax_validation",
        "manual_webhook_missing_secret_identifier_oracle",
    }


def test_repair_action_exact_delta_batch_edges_are_registered() -> None:
    batch = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "repair_action_exact_delta_batch"
    }
    expected = {
        (
            "b47181c790010971ac78c3603a60b662006bf81f",
            "56a0143a25af3d2a040753637987c08a65bb3f09",
        ): "sentinel_storage_check_duplication",
        (
            "42f08a99fb149cf4e70976bff661b10f8ba39a45",
            "dac940807a88f5a236fbfd7923b1f1f336e3c43f",
        ): "nixpacks_environment_shell_injection",
        (
            "dca6d9f7aab40fb9e6ea24dcc3a85bea02cc33a6",
            "9408620d5f47836241a9b10516296c5311786832",
        ): "hidden_tab_websocket_keepalive_suppression",
    }

    assert len(batch) == 23
    assert len({value[2] for value in batch.values()}) == 23
    assert all(batch[edge][2] == mechanism for edge, mechanism in expected.items())


def test_merge_and_test_change_exact_delta_batches_are_registered() -> None:
    merge_batch = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "merge_repair_exact_delta_batch"
    }
    test_batch = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "test_change_exact_delta_batch"
    }

    assert len(merge_batch) == 14
    assert len({value[2] for value in merge_batch.values()}) == 14
    assert len(test_batch) == 2
    assert {value[2] for value in test_batch.values()} == {
        "manual_stop_restart_limit_state_reset",
        "delayed_proxy_restarting_status",
    }


def test_direct_fallback_exact_delta_batch_is_registered() -> None:
    batch = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "direct_fallback_exact_delta_batch"
    }

    assert len(batch) == 8
    assert len({value[2] for value in batch.values()}) == 8
    assert {
        "upgrade_main_container_ssh_disconnect",
        "log_selection_blocks_live_updates",
        "accidental_github_runner_migration",
    } <= {value[2] for value in batch.values()}


def test_topology_carrier_and_merge_member_batches_are_registered() -> None:
    carrier_batch = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "topology_carrier_causal_batch"
    }
    merge_member_batch = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "merge_member_causal_batch"
    }
    merge_member_batch2 = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "merge_member_causal_batch2"
    }
    merge_member_batch3 = {
        edge: value
        for edge, value in ledger.CONFIRMED_EDGES.items()
        if value[1] == "merge_member_causal_batch3"
    }

    assert len(carrier_batch) == 7
    assert {value[2] for value in carrier_batch.values()} == {
        "docker_compose_custom_command_flag_injection",
        "traefik_restart_job_missing_versions_argument",
        "application_env_cleanup_unscoped_or_where",
    }
    assert len(merge_member_batch) == 4
    assert len({value[2] for value in merge_member_batch.values()}) == 4
    assert {
        "docker_27_stop_timeout_flag_compatibility",
        "subresource_restarting_status_preservation",
        "docker_compose_raw_user_input_preservation",
        "name_cleanup_backup_failure_observability",
    } == {value[2] for value in merge_member_batch.values()}
    assert len(merge_member_batch2) == 4
    assert {
        "deployment_log_hardcoded_display_limit",
        "dirty_indicator_border_layout_shift_preservation",
        "compose_control_build_pack_reactivity",
        "file_mount_parent_segment_confinement",
    } == {value[2] for value in merge_member_batch2.values()}
    assert len(merge_member_batch3) == 2
    assert {
        "deployment_log_morph_hook_navigation_lifecycle",
        "activity_monitor_hydration_lifecycle",
    } == {value[2] for value in merge_member_batch3.values()}


def test_compressed_census_preserves_pair_membership_without_expansion(
    tmp_path,
) -> None:
    ai_a = "a" * 40
    ai_b = "b" * 40
    fix_one = "1" * 40
    fix_two = "2" * 40
    rows = [
        {
            "sha": fix_one,
            "route": "direct_ai_ancestry",
            "strict_ai_ancestor_count": 1,
            "ai_ancestor_bitset_hex": "1",
        },
        {
            "sha": fix_two,
            "route": "direct_ai_ancestry",
            "strict_ai_ancestor_count": 2,
            "ai_ancestor_bitset_hex": "3",
        },
    ]
    ancestor_index = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_ancestor_bitset_index",
        "repository_identity": ledger.REPOSITORY_IDENTITY,
        "bit_order": "least_significant_bit_is_ai_shas_index_zero",
        "bitset_hex_width": 1,
        "ai_shas": [ai_a, ai_b],
        "ai_shas_sha256": ledger.canonical_sha256([ai_a, ai_b]),
    }
    summary = {
        "schema_version": 1,
        "artifact_kind": "ai_descendant_repair_census",
        "repository_identity": ledger.REPOSITORY_IDENTITY,
        "all_ref_commit_count": 2,
        "observed_ai_commit_count": 2,
        "direct_ancestry_root_count": 2,
        "direct_ancestry_pair_count": 3,
        "all_commit_route_counts": {"direct_ai_ancestry": 2},
        "all_commits_retained_once": True,
        "all_direct_ancestry_pairs_losslessly_represented": True,
        "all_parent_fixes_retained": True,
        "all_manifest_roots_scheduled_once": True,
        "hard_root_deletes": 0,
        "model_labels_used_for_membership": 0,
        "all_commit_rows_sha256": ledger.canonical_sha256(rows),
        "ancestor_index_sha256": ledger.canonical_sha256(ancestor_index),
    }
    (tmp_path / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (tmp_path / "ancestor_index.json").write_text(
        json.dumps(ancestor_index), encoding="utf-8"
    )
    (tmp_path / "all_commits.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    source, membership = ledger._compressed_census_source(tmp_path)

    assert source["compressed_direct_pair_count"] == 3
    assert ledger._compressed_census_contains(membership, ai_a, fix_one)
    assert not ledger._compressed_census_contains(membership, ai_b, fix_one)
    assert ledger._compressed_census_contains(membership, ai_b, fix_two)

    explicit_rows = [
        {
            "candidate_sha": ai_a,
            "fix_sha": fix_one,
            "status": "CONFIRMED_TRUE_POSITIVE",
            "adjudication": "CONFIRMED_TEST",
            "evidence_id": "test",
            "mechanism_group": "test",
            "candidate_retained": True,
            "model_observations": [],
        },
        {
            "candidate_sha": "c" * 40,
            "fix_sha": "3" * 40,
            "status": "DEFERRED_REVIEW_BACKLOG",
            "adjudication": "UNADJUDICATED_RETAINED",
            "evidence_id": None,
            "mechanism_group": None,
            "candidate_retained": True,
            "model_observations": [],
        },
    ]
    payload = ledger._build_payload(
        route_sources=[],
        ledger=explicit_rows,
        evidence={},
        compressed_candidate_sources=[source],
        compressed_memberships=[membership],
    )

    assert payload["summary"]["compressed_direct_ancestry_pair_count"] == 3
    assert payload["summary"]["compressed_overlap_with_explicit_edge_count"] == 1
    assert payload["summary"]["finite_candidate_union_edge_count"] == 4
    assert payload["conservation"]["passed"] is True


def test_topology_closure_adds_incomparable_pairs_without_expansion(tmp_path) -> None:
    ai_a = "a" * 40
    ai_b = "b" * 40
    fix = "1" * 40
    index = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_topology_pair_bitset_index",
        "repository_identity": ledger.REPOSITORY_IDENTITY,
        "bit_order": "least_significant_bit_is_ai_shas_index_zero",
        "bitset_hex_width": 1,
        "ai_shas": [ai_a, ai_b],
        "ai_shas_sha256": ledger.canonical_sha256([ai_a, ai_b]),
    }
    rows = [
        {
            "sha": fix,
            "route": "direct_ai_ancestry",
            "strict_ai_ancestor_count": 1,
            "strict_ai_ancestor_bitset_hex": "1",
            "fix_precedes_ai_count": 0,
            "fix_precedes_ai_bitset_hex": "0",
            "identity_pair_count": 0,
            "identity_bitset_hex": "0",
            "incomparable_residual_count": 1,
            "incomparable_residual_bitset_hex": "2",
        }
    ]
    (tmp_path / "ai_index.json").write_text(json.dumps(index), encoding="utf-8")
    (tmp_path / "pair_partition.jsonl").write_text(
        json.dumps(rows[0]) + "\n", encoding="utf-8"
    )
    summary = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_full_topology_pair_closure",
        "repository_identity": ledger.REPOSITORY_IDENTITY,
        "all_ref_commit_count": 1,
        "observed_ai_commit_count": 2,
        "full_cartesian_pair_count": 2,
        "strict_ai_ancestor_pair_count": 1,
        "fix_strictly_precedes_ai_pair_count": 0,
        "identity_pair_count": 0,
        "incomparable_residual_pair_count": 1,
        "pair_partition_conserved": True,
        "direct_pair_count_matches_census": True,
        "hard_heuristic_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "output_artifacts": {
            "ai_index": {
                "sha256": ledger._sha256(tmp_path / "ai_index.json"),
            },
            "pair_partition": {
                "sha256": ledger._sha256(tmp_path / "pair_partition.jsonl"),
            },
        },
    }
    (tmp_path / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    source, membership = ledger._compressed_topology_closure_source(tmp_path)

    assert source["compressed_candidate_pair_count"] == 2
    assert source["compressed_direct_pair_count"] == 1
    assert source["compressed_incomparable_residual_pair_count"] == 1
    assert ledger._compressed_census_contains(membership, ai_a, fix)
    assert ledger._compressed_census_contains(membership, ai_b, fix)
    payload = ledger._build_payload(
        route_sources=[],
        ledger=[],
        evidence={},
        compressed_candidate_sources=[source],
        compressed_memberships=[membership],
    )
    assert payload["summary"]["compressed_candidate_pair_count"] == 2
    assert payload["summary"]["compressed_direct_ancestry_pair_count"] == 1
    assert payload["summary"]["compressed_incomparable_residual_pair_count"] == 1
    assert payload["summary"]["finite_candidate_union_edge_count"] == 2
    assert payload["conservation"]["passed"] is True


def test_wire_navigate_authorization_edge_is_registered() -> None:
    edge = (
        "e709e2c131aeebb9a1121437ce5e1ec4c2fc2f0b",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "wire_navigate_authorization"


def test_project_scope_hardening_edges_are_registered() -> None:
    expected = {
        (
            "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
            "3ba4553df5657582ad720a6572d83383fe89c078",
        ),
        (
            "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
            "a478ac66eb7037837c178d64006f83a13eca12d2",
        ),
    }

    assert expected <= set(ledger.CONFIRMED_EDGES)
    assert all(
        ledger.CONFIRMED_EDGES[edge][1] == "project_scope_hardening"
        for edge in expected
    )


def test_sentinel_restart_activation_carrier_and_alias_are_registered() -> None:
    canonical_edge = (
        "728f261316f2af904f755756d687a722d2967223",
        "096d4369e59b3db7ace2db3ca42588c41b9b6019",
    )
    alias_edge = (
        "e04b9cd07c11b79d4fcd62d8dca441d8571e4086",
        "096d4369e59b3db7ace2db3ca42588c41b9b6019",
    )

    assert ledger.CONFIRMED_EDGES[canonical_edge][1] == "sentinel_activation_carrier"
    assert ledger.PATCH_EQUIVALENT_ALIAS_EDGES[alias_edge] == (
        "PATCH_EQUIVALENT_ALIAS_NO_INDEPENDENT_MAINLINE_PATH_CONTRIBUTION",
        "sentinel_activation_carrier",
        canonical_edge,
    )


def test_api_token_permission_preservation_edge_is_registered() -> None:
    edge = (
        "90ddbb357231ca3808f277eb87a63c8f650417e6",
        "7f135e0f6d87a6065a67b78b8a9976dfd99f3a2a",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "api_token_permission_preservation"


def test_cloud_settings_path_extension_edge_is_registered() -> None:
    edge = (
        "acff543e09ae5c7f8da78e5a092ebb1e57f24dc0",
        "b878dc8102c5bbcd4b20435c46c37e04d90f9c6e",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "cloud_settings_path_extension"


def test_sentinel_instant_save_path_edge_is_registered() -> None:
    edge = (
        "f995426fb32d810577dad5d46f275cc4a6e5c38d",
        "096d4369e59b3db7ace2db3ca42588c41b9b6019",
    )

    assert edge in ledger.CONFIRMED_EDGES
    assert ledger.CONFIRMED_EDGES[edge][1] == "sentinel_instant_save_path"


def test_conductor_trust_hosts_origin_edge_is_registered() -> None:
    edge = (
        "e1fe58639756cf7b232458eddd6978e4ed0031f5",
        "e1d4b4682efc898ba5aa3751b2da2072f89c7e24",
    )

    assert ledger.CONFIRMED_EDGES[edge] == (
        "CONFIRMED_DIRECT_AI_ORIGIN",
        "conductor_trust_hosts_origin",
        "trust_hosts_cold_cache_validation_bypass",
    )


def test_conductor_exact_delta_causal_edges_are_registered() -> None:
    expected = {
        (
            "473c32270d72252ee6753afc35c3ea4360d169e0",
            "5019c8db928afd34c0c9d17c5d20019fa053c344",
        ): (
            "CONFIRMED_DIRECT_AI_API_TEAM_CONTEXT_REGRESSION",
            "api_backup_s3_session_team_context",
        ),
        (
            "473c32270d72252ee6753afc35c3ea4360d169e0",
            "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486",
        ): (
            "CONFIRMED_DIRECT_AI_CROSS_TEAM_SERVER_LOOKUP",
            "api_cancel_deployment_unscoped_build_server",
        ),
        (
            "bf6a109e56e2928b2a39ec01d3483e50ddab644b",
            "73170fdd33783337a91b27191f126cbd5c61faed",
        ): (
            "CONFIRMED_DIRECT_AI_INVALID_SEEDED_COMPOSE_PATH",
            "docker_compose_seed_path_concatenation",
        ),
        (
            "edcdea78a289bdc467ea22002cb59821d502a76b",
            "6557514954ac36ebd95f5eb704acee887ee9e61f",
        ): (
            "CONFIRMED_DIRECT_AI_OVERBROAD_CI_TOKEN_PERMISSION",
            "ghcr_cleanup_unnecessary_contents_read",
        ),
    }

    for edge, (adjudication, mechanism) in expected.items():
        assert ledger.CONFIRMED_EDGES[edge] == (
            adjudication,
            "conductor_exact_delta_causal_batch",
            mechanism,
        )


def test_new_deterministic_causal_edges_are_registered() -> None:
    expected = {
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
    }

    assert all(
        ledger.CONFIRMED_EDGES[edge] == value for edge, value in expected.items()
    )


def test_form_onboarding_wrong_origin_edges_are_rejected_but_retained() -> None:
    expected = {
        (
            "2a8f02ed58509ff4619517411a0b00cec9971c1f",
            "a5c6f53b583c93b1871ac1099632d47d157a0341",
        ): "REJECTED_WRONG_ORIGIN_MERGE_COMPOSITION",
        (
            "2a8f02ed58509ff4619517411a0b00cec9971c1f",
            "a3c80c9778d2c4b744afafb8d88dc47f51c448aa",
        ): "REJECTED_INTERVENING_UNOBSERVED_AI_ORIGIN",
        (
            "2a8f02ed58509ff4619517411a0b00cec9971c1f",
            "7c14cd24dc923a997dec733d5038a306f1cac36a",
        ): "REJECTED_WRONG_ORIGIN_INTERVENING_AI_CONTRACT_REFACTOR",
        (
            "ac653ddcbc15019e9617e719bf687f10f25a80f2",
            "2e71ef4f1111421a67dabfb506387c938b320b80",
        ): "REJECTED_PREEXISTING_ONBOARDING_MODAL_CONTEXT",
    }

    for edge, adjudication in expected.items():
        assert ledger.REJECTED_EDGES[edge] == (
            adjudication,
            "conductor_form_onboarding_attribution",
        )


def test_conductor_datalist_wrong_origin_is_rejected_but_retained() -> None:
    edge = (
        "84559a0e7d71c05be9a123a96cf589d0719500c7",
        "62d99b0b8bab570a79e5740f459bb94eb3238203",
    )

    assert ledger.REJECTED_EDGES[edge] == (
        "REJECTED_NO_DEMONSTRATED_DEFECT_IN_CANDIDATE_DELTA",
        "conductor_datalist_revert_attribution",
    )


def test_buildtime_env_exact_overlap_is_reattributed_and_rejected() -> None:
    edge = (
        "41afa9568d5ed2dcf56b42791ee941dbf1931fbf",
        "be2b01786ac08b69f40646d4dac4f168b04e5197",
    )

    assert ledger.REJECTED_EDGES[edge] == (
        "REJECTED_NONCAUSAL_EXACT_OVERLAP_INTERVENING_ORIGIN",
        "buildtime_env_duplicate_reattribution",
    )


def test_global_search_formatting_reversal_is_reattributed_and_rejected() -> None:
    edge = (
        "2ce3052378f1dd451b6e79a9179c0a9eebb1549d",
        "66cff9d9b84def9cf3a600ef637a51a8c35d9a2a",
    )

    assert ledger.REJECTED_EDGES[edge] == (
        "REJECTED_FORMATTING_REVERSAL_WRONG_ORIGIN",
        "global_search_new_image_origin",
    )


def test_structural_proximity_rescue_edges_are_registered() -> None:
    expected = {
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
    }

    assert all(
        ledger.CONFIRMED_EDGES[edge] == value for edge, value in expected.items()
    )


def test_upgrade_shutdown_order_regression_is_registered() -> None:
    edge = (
        "f3ccacb2da6da8b502bcb472bfb0bc6a7c776068",
        "f4dbae180536f897185c7933f1904e8b9d39efff",
    )

    assert ledger.CONFIRMED_EDGES[edge] == (
        "CONFIRMED_AI_UPGRADE_DEPENDENCY_INVERTED_SHUTDOWN_ORDER",
        "upgrade_shutdown_order",
        "upgrade_dependency_inverted_shutdown_order",
    )


def test_migration_property_type_contract_break_is_registered() -> None:
    edge = (
        "9c2ef0aa21e2c5a9809d9748253e6b134dfe2019",
        "e256e765e74a0d506c96e768b9246efb1ec7d80c",
    )

    assert ledger.CONFIRMED_EDGES[edge] == (
        "CONFIRMED_DIRECT_AI_MIGRATION_TRANSACTION_PROPERTY_TYPE_CONTRACT_BREAK",
        "concurrent_index_migration_transaction_contract",
        "laravel_migration_within_transaction_property_type_invariance",
    )


def test_readonly_volume_incomplete_repair_is_registered() -> None:
    edge = (
        "f152ec00ada70757da38e0b789f049b14d813e33",
        "9bc33d65abd022884ddc6d0e3c463ad4032bb144",
    )

    assert ledger.CONFIRMED_EDGES[edge] == (
        "CONFIRMED_AI_TO_AI_INCOMPLETE_REPAIR",
        "readonly_volume_path_normalization",
        "local_file_volume_leading_slash_normalization_omission",
    )
