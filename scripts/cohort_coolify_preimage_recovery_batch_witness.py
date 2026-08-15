#!/usr/bin/env python3
"""Freeze exact causal witnesses recovered by the all-graph preimage overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _is_ancestor,
)


@dataclass(frozen=True)
class RepairCase:
    key: str
    candidate_sha: str
    fix_sha: str
    path: str
    adjudication: str
    mechanism_group: str
    claim: str
    candidate_added: tuple[str, ...]
    candidate_absent: tuple[str, ...]
    pre_fix_present: tuple[str, ...]
    pre_fix_absent: tuple[str, ...]
    fix_removed: tuple[str, ...]
    fix_added: tuple[str, ...]


CASES = (
    RepairCase(
        key="team_policy_target_team_context",
        candidate_sha="336fa0c7143a8ceca319dc1e7b6f12ca2b923708",
        fix_sha="fb2d477e48764d7dd9139db13ef26f7eb7809221",
        path="app/Policies/TeamPolicy.php",
        adjudication="CONFIRMED_DIRECT_AI_INCOMPLETE_AUTHORIZATION_REPAIR",
        mechanism_group="team_policy_target_team_context",
        claim=(
            "the AI repair replaced unconditional access with active-context role "
            "checks, while the follow-up binds the role check to the target team"
        ),
        candidate_added=("return $user->isAdmin() || $user->isOwner();",),
        candidate_absent=("isAdminOfTeam($team->id)",),
        pre_fix_present=("return $user->isAdmin() || $user->isOwner();",),
        pre_fix_absent=("isAdminOfTeam($team->id)",),
        fix_removed=("return $user->isAdmin() || $user->isOwner();",),
        fix_added=("return $user->isAdminOfTeam($team->id);",),
    ),
    RepairCase(
        key="api_token_expiration_warning_persistence",
        candidate_sha="90ddbb357231ca3808f277eb87a63c8f650417e6",
        fix_sha="3911a0305c0177c5bb77659883b3c59709004570",
        path="app/Jobs/ApiTokenExpirationWarningJob.php",
        adjudication="CONFIRMED_DIRECT_AI_FUNCTIONAL_REGRESSION",
        mechanism_group="api_token_expiration_warning_persistence",
        claim=(
            "the AI-created warning job used a zero-attempt rate-limit gate; the "
            "repair replaces it with an atomic persisted sent-state transition"
        ),
        candidate_added=("$maxAttempts = 0,",),
        candidate_absent=("api_token_expiration_warning_sent_at",),
        pre_fix_present=("$maxAttempts = 0,",),
        pre_fix_absent=("api_token_expiration_warning_sent_at",),
        fix_removed=("$maxAttempts = 0,",),
        fix_added=(
            "->whereNull('api_token_expiration_warning_sent_at')",
            "->update(['api_token_expiration_warning_sent_at' => $warningSentAt]);",
        ),
    ),
    RepairCase(
        key="outbound_url_multi_address_validation",
        candidate_sha="0fce7fa9481aa1bcca06d767075684a11e032c79",
        fix_sha="c7f014017b753a53e33a4eb7d2950f7302d971b5",
        path="app/Rules/SafeExternalUrl.php",
        adjudication="CONFIRMED_DIRECT_AI_INCOMPLETE_SECURITY_HARDENING",
        mechanism_group="outbound_url_multi_address_validation",
        claim=(
            "the AI validator inspected one gethostbyname result; the repair "
            "enumerates A and AAAA results and rejects any non-public address"
        ),
        candidate_added=("$ip = gethostbyname($host);",),
        candidate_absent=("dns_get_record", "foreach ($resolvedIps"),
        pre_fix_present=("$ip = gethostbyname($host);",),
        pre_fix_absent=("dns_get_record", "foreach ($resolvedIps"),
        fix_removed=("$ip = gethostbyname($host);",),
        fix_added=(
            "$records = @dns_get_record($host, DNS_A | DNS_AAAA);",
            "foreach ($resolvedIps as $resolvedIp)",
        ),
    ),
    RepairCase(
        key="webhook_dns_resolution_validation",
        candidate_sha="564cd8368bb8b4485b3981060dace37645b20f52",
        fix_sha="c7f014017b753a53e33a4eb7d2950f7302d971b5",
        path="app/Rules/SafeWebhookUrl.php",
        adjudication="CONFIRMED_DIRECT_AI_INCOMPLETE_SECURITY_HARDENING",
        mechanism_group="webhook_dns_resolution_validation",
        claim=(
            "the AI validator blocked only literal loopback/link-local IPs; the "
            "repair resolves hostnames and applies the blocked-IP check to every result"
        ),
        candidate_added=(
            "if (filter_var($host, FILTER_VALIDATE_IP) && ($this->isLoopback($host) || $this->isLinkLocal($host))) {",
        ),
        candidate_absent=("$resolvedIps = $this->resolveHost",),
        pre_fix_present=(
            "if (filter_var($hostForIpCheck, FILTER_VALIDATE_IP) && ($this->isLoopback($hostForIpCheck) || $this->isLinkLocal($hostForIpCheck))) {",
        ),
        pre_fix_absent=("$resolvedIps = $this->resolveHost",),
        fix_removed=(
            "if (filter_var($hostForIpCheck, FILTER_VALIDATE_IP) && ($this->isLoopback($hostForIpCheck) || $this->isLinkLocal($hostForIpCheck))) {",
        ),
        fix_added=("$resolvedIps = $this->resolveHost($hostForDns);",),
    ),
    RepairCase(
        key="webhook_runtime_url_validation",
        candidate_sha="413dee5d8c97edefd4b359831d6db766b1235c9c",
        fix_sha="0b8c75f8edb12bc9084c1b6cd844643d7ae95701",
        path="app/Jobs/SendWebhookJob.php",
        adjudication="CONFIRMED_DIRECT_AI_VULNERABLE_SINK_ORIGIN",
        mechanism_group="webhook_runtime_url_validation",
        claim=(
            "the AI commit created an unguarded server-side request to a stored "
            "webhook URL; the repair validates again at job execution before the sink"
        ),
        candidate_added=("Http::post($this->webhookUrl, $this->payload);",),
        candidate_absent=("new \\App\\Rules\\SafeWebhookUrl",),
        pre_fix_present=("Http::post($this->webhookUrl, $this->payload);",),
        pre_fix_absent=("new \\App\\Rules\\SafeWebhookUrl",),
        fix_removed=(),
        fix_added=("new \\App\\Rules\\SafeWebhookUrl",),
    ),
    RepairCase(
        key="orphan_cleanup_placeholder_server_filter",
        candidate_sha="945cce95870b2f18b13f8f509677ad3823d2b97f",
        fix_sha="c8a332a3bc935064dcbb2f7703b1edeb2becfaae",
        path="app/Jobs/CleanupOrphanedPreviewContainersJob.php",
        adjudication="CONFIRMED_DIRECT_AI_FUNCTIONAL_REGRESSION",
        mechanism_group="orphan_cleanup_placeholder_server_filter",
        claim=(
            "the AI-created cleanup job excluded one hard-coded placeholder IP; "
            "the repair rejects null, empty, and every declared placeholder IP"
        ),
        candidate_added=("->where('ip', '!=', '1.2.3.4');",),
        candidate_absent=("Server::PLACEHOLDER_IPS",),
        pre_fix_present=("->where('ip', '!=', '1.2.3.4');",),
        pre_fix_absent=("Server::PLACEHOLDER_IPS",),
        fix_removed=("->where('ip', '!=', '1.2.3.4');",),
        fix_added=(
            "->whereNotNull('ip')",
            "->whereNotIn('ip', Server::PLACEHOLDER_IPS);",
        ),
    ),
    RepairCase(
        key="preview_compose_domain_validation",
        candidate_sha="cdf6b5f1611369762406290fa05d11e60206630a",
        fix_sha="c6c7ec1c317883fc0967f911ac4d6d47f83ab069",
        path="app/Livewire/Project/Application/PreviewsCompose.php",
        adjudication="CONFIRMED_DIRECT_AI_INCOMPLETE_INPUT_VALIDATION",
        mechanism_group="preview_compose_domain_validation",
        claim=(
            "the AI change added comma-separated preview-domain ingestion without "
            "the shared application-domain rules; the repair validates and normalizes it"
        ),
        candidate_added=("$domain_list = explode(',', $domain_string);",),
        candidate_absent=("ValidationPatterns::validateApplicationDomains",),
        pre_fix_present=("$domain_list = explode(',', $domain_string);",),
        pre_fix_absent=("ValidationPatterns::validateApplicationDomains",),
        fix_removed=("$domain_list = explode(',', $domain_string);",),
        fix_added=(
            "ValidationPatterns::validateApplicationDomains($domain_string)",
            "$domain_list = ValidationPatterns::applicationDomainList($domain_string);",
        ),
    ),
    RepairCase(
        key="hetzner_public_ip_protocol_validation",
        candidate_sha="62c394d3a1dba6aa6d4ab1456b7a7911f6b72639",
        fix_sha="a8000ac2ad2fa0882223b8360028e21e9aaa6ad4",
        path="app/Http/Controllers/Api/HetznerController.php",
        adjudication="CONFIRMED_DIRECT_AI_MISSING_INPUT_CONSTRAINT",
        mechanism_group="hetzner_public_ip_protocol_validation",
        claim=(
            "the AI-created provisioning endpoint accepted both public-IP flags as "
            "false; the repair rejects that state before provisioning"
        ),
        candidate_added=(
            "'enable_ipv4' => 'nullable|boolean',",
            "'enable_ipv6' => 'nullable|boolean',",
        ),
        candidate_absent=("Enable at least one public IP protocol.",),
        pre_fix_present=(
            "'enable_ipv4' => 'nullable|boolean',",
            "'enable_ipv6' => 'nullable|boolean',",
        ),
        pre_fix_absent=("Enable at least one public IP protocol.",),
        fix_removed=(),
        fix_added=(
            "if (! $request->boolean('enable_ipv4') && ! $request->boolean('enable_ipv6')) {",
            "'enable_ipv4' => ['Enable at least one public IP protocol.'],",
        ),
    ),
    RepairCase(
        key="hetzner_api_exception_disclosure",
        candidate_sha="62c394d3a1dba6aa6d4ab1456b7a7911f6b72639",
        fix_sha="4d836888964ee5a1bea7089d3fe6c886012f0bff",
        path="app/Http/Controllers/Api/HetznerController.php",
        adjudication="CONFIRMED_DIRECT_AI_EXCEPTION_DISCLOSURE_ORIGIN",
        mechanism_group="hetzner_api_exception_disclosure",
        claim=(
            "the AI-created endpoints returned upstream exception messages to API "
            "clients; the repair replaces them with generic endpoint-specific errors"
        ),
        candidate_added=(
            "return response()->json(['message' => 'Failed to fetch locations: '.$e->getMessage()], 500);",
            "return response()->json(['message' => 'Failed to create server: '.$e->getMessage()], 500);",
        ),
        candidate_absent=("Failed to fetch Hetzner locations.",),
        pre_fix_present=(
            "return response()->json(['message' => 'Failed to fetch locations: '.$e->getMessage()], 500);",
            "return response()->json(['message' => 'Failed to create server: '.$e->getMessage()], 500);",
        ),
        pre_fix_absent=("Failed to fetch Hetzner locations.",),
        fix_removed=(
            "return response()->json(['message' => 'Failed to fetch locations: '.$e->getMessage()], 500);",
            "return response()->json(['message' => 'Failed to create server: '.$e->getMessage()], 500);",
        ),
        fix_added=(
            "return response()->json(['message' => 'Failed to fetch Hetzner locations.'], 500);",
            "return response()->json(['message' => 'Failed to create Hetzner server.'], 500);",
        ),
    ),
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--preimage-overlay-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        reason = completed.stderr.strip().replace("\n", " ")
        raise ValueError(f"git {arguments[0]} failed: {reason[:300]}")
    return completed.stdout


def _parent(repository: Path, sha: str) -> str:
    return _git(repository, "rev-parse", f"{sha}^1").strip()


def _blob(repository: Path, revision: str, source_path: str) -> str:
    return _git(repository, "show", f"{revision}:{source_path}")


def _diff(repository: Path, parent: str, child: str, source_path: str) -> str:
    return _git(
        repository,
        "diff",
        "--unified=0",
        "--no-color",
        parent,
        child,
        "--",
        source_path,
    )


def _changed_lines(patch: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    added = tuple(
        line[1:]
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    removed = tuple(
        line[1:]
        for line in patch.splitlines()
        if line.startswith("-") and not line.startswith("---")
    )
    return added, removed


def _contains_all(values: Iterable[str], fragments: Sequence[str]) -> bool:
    materialized = tuple(values)
    return all(any(fragment in value for value in materialized) for fragment in fragments)


def _absent_all(text: str, fragments: Sequence[str]) -> bool:
    return all(fragment not in text for fragment in fragments)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _case_proof(
    repository: Path,
    case: RepairCase,
    *,
    observed_ai_shas: set[str],
    overlay_edges: set[tuple[str, str]],
) -> dict[str, object]:
    candidate_parent = _parent(repository, case.candidate_sha)
    fix_parent = _parent(repository, case.fix_sha)
    candidate_blob = _blob(repository, case.candidate_sha, case.path)
    pre_fix_blob = _blob(repository, fix_parent, case.path)
    fixed_blob = _blob(repository, case.fix_sha, case.path)
    candidate_patch = _diff(
        repository, candidate_parent, case.candidate_sha, case.path
    )
    fix_patch = _diff(repository, fix_parent, case.fix_sha, case.path)
    candidate_added_lines, _ = _changed_lines(candidate_patch)
    fix_added_lines, fix_removed_lines = _changed_lines(fix_patch)
    checks = {
        "candidate_is_observed_ai": case.candidate_sha in observed_ai_shas,
        "edge_recovered_by_preimage_overlay": (
            case.candidate_sha,
            case.fix_sha,
        )
        in overlay_edges,
        "candidate_is_ancestor_of_fix": _is_ancestor(
            repository, case.candidate_sha, case.fix_sha
        ),
        "candidate_added_focal_state": _contains_all(
            candidate_added_lines, case.candidate_added
        ),
        "candidate_lacks_repair_state": _absent_all(
            candidate_blob, case.candidate_absent
        ),
        "focal_state_persists_to_fix_parent": _contains_all(
            (pre_fix_blob,), case.pre_fix_present
        ),
        "repair_state_absent_from_fix_parent": _absent_all(
            pre_fix_blob, case.pre_fix_absent
        ),
        "fix_removes_focal_state": _contains_all(
            fix_removed_lines, case.fix_removed
        ),
        "fix_adds_repair_state": _contains_all(fix_added_lines, case.fix_added),
    }
    return {
        "key": case.key,
        "candidate_sha": case.candidate_sha,
        "fix_sha": case.fix_sha,
        "path": case.path,
        "adjudication": case.adjudication,
        "mechanism_group": case.mechanism_group,
        "claim": case.claim,
        "candidate_parent_sha": candidate_parent,
        "fix_parent_sha": fix_parent,
        "candidate_metadata": _commit_metadata(repository, case.candidate_sha),
        "fix_metadata": _commit_metadata(repository, case.fix_sha),
        "state_digests": {
            "candidate_blob_sha256": _digest(candidate_blob),
            "fix_parent_blob_sha256": _digest(pre_fix_blob),
            "fixed_blob_sha256": _digest(fixed_blob),
            "candidate_patch_sha256": _digest(candidate_patch),
            "fix_patch_sha256": _digest(fix_patch),
        },
        "focal_fragments": {
            "candidate_added": list(case.candidate_added),
            "candidate_absent": list(case.candidate_absent),
            "pre_fix_present": list(case.pre_fix_present),
            "pre_fix_absent": list(case.pre_fix_absent),
            "fix_removed": list(case.fix_removed),
            "fix_added": list(case.fix_added),
        },
        "checks": checks,
        "passed": all(checks.values()),
    }


def build_witness(
    repository: Path,
    *,
    observed_ai_shas: set[str],
    overlay_edges: set[tuple[str, str]],
    cases: Sequence[RepairCase] = CASES,
) -> dict[str, object]:
    results = [
        _case_proof(
            repository,
            case,
            observed_ai_shas=observed_ai_shas,
            overlay_edges=overlay_edges,
        )
        for case in cases
    ]
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_preimage_recovery_exact_causal_batch_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "confirmed_edges": [
            {
                "candidate_sha": result["candidate_sha"],
                "fix_sha": result["fix_sha"],
                "adjudication": result["adjudication"],
                "mechanism_group": result["mechanism_group"],
            }
            for result in results
        ],
        "case_results": results,
        "summary": {
            "confirmed_edge_count": len(results),
            "unique_candidate_count": len(
                {str(result["candidate_sha"]) for result in results}
            ),
            "mechanism_group_count": len(
                {str(result["mechanism_group"]) for result in results}
            ),
            "failed_case_count": sum(not bool(result["passed"]) for result in results),
        },
        "witness_passed": bool(results) and all(
            result["passed"] is True for result in results
        ),
        "claim_boundary": (
            "Each confirmed edge requires observed-AI membership, exact preimage-"
            "overlay recovery, Git ancestry, an AI-added focal state, persistence to "
            "the fix parent, and an exact deleting or add-check repair delta. These "
            "are causal commit/fix mechanisms, not counts of distinct vulnerabilities."
        ),
    }


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise SystemExit(f"non-object row in {path}")
                rows.append(value)
    return rows


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    overlay_path = args.preimage_overlay_dir.resolve() / "source_owner_pairs.jsonl"
    ai_rows = _load_jsonl(ai_path)
    overlay_rows = _load_jsonl(overlay_path)
    observed_ai_shas = {str(row.get("sha") or "") for row in ai_rows}
    overlay_edges = {
        (str(row.get("candidate_sha") or ""), str(row.get("fix_sha") or ""))
        for row in overlay_rows
        if row.get("retained") is True
    }
    payload = build_witness(
        repository,
        observed_ai_shas=observed_ai_shas,
        overlay_edges=overlay_edges,
    )
    payload["source_artifacts"] = {
        "ai_commits": {
            "path": str(ai_path),
            "sha256": hashlib.sha256(ai_path.read_bytes()).hexdigest(),
        },
        "preimage_source_owner_pairs": {
            "path": str(overlay_path),
            "sha256": hashlib.sha256(overlay_path.read_bytes()).hexdigest(),
        },
    }
    if payload["witness_passed"] is not True:
        failed = [
            str(row["key"])
            for row in payload["case_results"]
            if row["passed"] is not True
        ]
        raise SystemExit(f"preimage recovery witness failed: {failed}")
    _atomic_json(args.output.resolve(), payload)
    print("Coolify preimage-recovery batch witness frozen")
    print(f"  confirmed edges : {payload['summary']['confirmed_edge_count']}")
    print(f"  unique candidates: {payload['summary']['unique_candidate_count']}")
    print(f"  mechanisms      : {payload['summary']['mechanism_group_count']}")
    print(f"  output          : {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
