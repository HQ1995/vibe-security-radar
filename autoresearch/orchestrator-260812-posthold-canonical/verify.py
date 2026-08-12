#!/usr/bin/env python3
"""Fail-closed structural and optional live verifier for the canonical ledger."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})$")
AI_MARKERS = ("[ai]", "ai-assisted", "claude", "cursor", "codex")


def load_json(path: Path):
    return json.loads(path.read_text())


def load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", str(repo), *args],
        check=check,
        text=True,
        capture_output=True,
    )


def gh_json(endpoint: str) -> dict:
    result = subprocess.run(["gh", "api", endpoint], check=True, text=True, capture_output=True)
    return json.loads(result.stdout)


def url_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def url_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def advisory_alias(repo: str, ghsa: str, cve: str) -> dict:
    advisory = gh_json(f"repos/{repo}/security-advisories/{ghsa.lower()}")
    assert advisory["state"] == "published" and advisory["withdrawn_at"] is None
    assert {item["value"].upper() for item in advisory["identifiers"]} == {ghsa, cve}
    global_advisory = gh_json(f"advisories/{ghsa.lower()}")
    assert global_advisory["withdrawn_at"] is None
    assert {item["value"].upper() for item in global_advisory["identifiers"]} == {ghsa, cve}
    return global_advisory


def compare_contains(repo: str, ancestor: str, tag: str) -> bool:
    comparison = gh_json(f"repos/{repo}/compare/{ancestor}...{tag}")
    return comparison["status"] in {"ahead", "identical"} and comparison["behind_by"] == 0


def verify_structural() -> tuple[dict, list[dict], list[dict]]:
    manifest = load_json(HERE / "source_manifest.json")
    adjudications = load_json(HERE / "adjudications.json")
    corrections = load_json(HERE / "inherited_corrections.json")
    ledger = load_jsonl(HERE / "ledger.jsonl")
    summary = load_json(HERE / "summary.json")

    for item in manifest["sources"]:
        path = ROOT / item["path"]
        assert path.is_file(), item["path"]
        assert sha256(path) == item["sha256"], item["path"]

    expected_ledger, expected_summary = build.build_outputs()
    assert (HERE / "ledger.jsonl").read_text() == expected_ledger
    assert (HERE / "summary.json").read_text() == expected_summary
    assert summary["ledger_sha256"] == sha256(HERE / "ledger.jsonl")
    assert summary["source_manifest_sha256"] == sha256(HERE / "source_manifest.json")
    assert summary["adjudications_sha256"] == sha256(HERE / "adjudications.json")
    assert summary["inherited_corrections_sha256"] == sha256(HERE / "inherited_corrections.json")

    assert len(ledger) == 271
    assert len({row["row_key"] for row in ledger}) == len(ledger)
    for row in ledger:
        assert row["row_state"] in {"PASS", "REJECT", "NARROW", "BLOCKED", "UNKNOWN", "DUPLICATE"}
        assert row["public_ids"] == sorted(set(row["public_ids"]))
        assert all(ID_RE.fullmatch(value) for value in row["public_ids"])
        assert set(row["counting"]) == {
            "canonical_instance",
            "strict_document_max",
            "broad_released_max",
            "widest_max",
        }
        assert all(isinstance(value, bool) for value in row["counting"].values())

    base_count = 213
    base = ledger[:base_count]
    additions = [row for row in ledger if row["source_layer"] == "POST_HOLD_REDTEAM" and row["record_kind"] == "COMPONENT_ROW"]
    controls = [row for row in ledger if row["record_kind"] == "POST_HOLD_ROUTE_CONTROL"]
    assert len(additions) == 28
    assert Counter(row["row_state"] for row in additions) == Counter({"PASS": 26, "NARROW": 2})
    assert len(controls) == 30
    assert Counter(row["row_state"] for row in controls) == Counter({"REJECT": 29, "UNKNOWN": 1})
    assert all(not any(row["counting"].values()) for row in controls)

    base_components = [row for row in base if row["record_kind"] == "COMPONENT_ROW" and row["counting"]["canonical_instance"]]
    base_ids = {value for row in base_components for value in row["public_ids"]}
    new_ids = [value for row in additions for value in row["public_ids"]]
    assert len(new_ids) == len(set(new_ids)) == 39
    assert not (base_ids & set(new_ids))

    fingerprints = [row["mechanism_fingerprint"] for row in additions]
    assert len(fingerprints) == len(set(fingerprints)) == 28
    source_hashes = {item["path"]: item["sha256"] for item in manifest["sources"]}
    for row in additions:
        source_ref = row["source_refs"][0]
        assert source_ref["sha256"] == source_hashes[source_ref["path"]]
        raw = next(item for item in adjudications["components"] if item["row_key"] == row["row_key"])
        assert row["mechanism_fingerprint"] == build.mechanism_fingerprint(raw)
        for sha_value in (
            row["release_evidence"]["candidate_sha"],
            row["release_evidence"]["fix_sha"],
            row["ai_provenance"]["marker_sha"],
            *row["atomic_fix_members"],
        ):
            assert SHA_RE.fullmatch(sha_value)
    for row in controls:
        source_ref = row["source_refs"][0]
        assert source_ref["sha256"] == source_hashes[source_ref["path"]]
        assert SHA_RE.fullmatch(row["candidate_fix_edges"][0]["candidate_sha"])
        assert row["state_axes"]["source_verdict"] == row["row_state"]
        assert row["state_axes"]["negative_control_outcome"] == row["row_state"]

    base_shas = {
        value
        for row in base
        for edge in row.get("candidate_fix_edges", [])
        for key, value in edge.items()
        if key.endswith("_sha") and isinstance(value, str)
    }
    new_shas = {
        value
        for row in additions
        for value in (
            row["candidate_fix_edges"][0]["candidate_sha"],
            row["candidate_fix_edges"][0].get("carrier_sha"),
            row["release_evidence"]["fix_sha"],
            *row["atomic_fix_members"],
        )
        if value
    }
    cross_layer_overlap = base_shas & new_shas
    approved_overlap = {item["sha"] for item in corrections["approved_cross_layer_sha_reuse"]}
    assert cross_layer_overlap == approved_overlap
    for item in corrections["approved_cross_layer_sha_reuse"]:
        assert set(item["row_keys"]) == {
            row["row_key"]
            for row in ledger
            if any(item["sha"] in edge.values() for edge in row.get("candidate_fix_edges", []))
        }
        reused_rows = [next(row for row in ledger if row["row_key"] == key) for key in item["row_keys"]]
        assert all(row.get("reuse_justification") for row in reused_rows)

    occurrences: dict[str, list[dict]] = defaultdict(list)
    for row in additions:
        values = {
            row["candidate_fix_edges"][0]["candidate_sha"],
            row["candidate_fix_edges"][0].get("carrier_sha"),
            row["release_evidence"]["fix_sha"],
            *row["atomic_fix_members"],
        }
        for value in values - {None}:
            occurrences[value].append(row)
    for rows in occurrences.values():
        if len(rows) > 1:
            assert all(row["reuse_justification"] for row in rows)

    canonical = [row for row in ledger if row["record_kind"] == "COMPONENT_ROW" and row["counting"]["canonical_instance"]]
    released = [row for row in canonical if row["source_tier"].endswith("_RELEASED")]
    assert len(canonical) == 211
    assert Counter(row["source_tier"] for row in canonical) == Counter(
        {"STRICT_RELEASED": 132, "INCOMPLETE_RELEASED": 67, "INCOMPLETE_COMMIT_ONLY": 11, "STRICT_COMMIT_ONLY": 1}
    )
    assert Counter(row["row_state"] for row in released) == Counter(
        {"PASS": 191, "NARROW": 4, "UNKNOWN": 1, "REJECT": 3}
    )
    public_ids = [value for row in canonical for value in row["public_ids"]]
    assert len(public_ids) == len(set(public_ids)) == 358
    control_ids = [value for row in controls for value in row["public_ids"]]
    assert len(control_ids) == len(set(control_ids))
    assert set(public_ids) & set(control_ids) == {"CVE-2026-44114", "GHSA-HXVM-XJVF-93F3"}
    hxvm = next(row for row in controls if row["row_key"] == "posthold-control:hxvm")
    hxvm_component = next(row for row in canonical if "GHSA-HXVM-XJVF-93F3" in row["public_ids"])
    assert hxvm["candidate_fix_edges"][0]["candidate_sha"] not in {
        edge["candidate_sha"] for edge in hxvm_component["candidate_fix_edges"]
    }
    batch_h_ids = {
        value
        for row in controls
        if row["row_key"].startswith("posthold-control:H")
        for value in row["public_ids"]
    }
    assert not (set(public_ids) & batch_h_ids)
    fingerprints = [build.canonical_mechanism_fingerprint(row) for row in canonical]
    assert len(fingerprints) == len(set(fingerprints)) == 211

    corrected = {item["row_key"]: item for item in corrections["corrections"]}
    assert set(corrected) == {
        "post:coolify-trust-host-cache@canonical",
        "post:filebrowser-scoped-fs@canonical",
        "post:gitea-draft-attachment@canonical",
        "post:praisonai-jwt-default@canonical",
        "strict-200-v3:alias-02fb7aeb21b9f4e1ab18fbce",
        "strict-200-v3:alias-99ee5f834a00aca5862a1926",
    }
    indexed = {row["row_key"]: row for row in ledger}
    assert indexed["post:gitea-draft-attachment@canonical"]["row_state"] == "PASS"
    assert indexed["post:praisonai-jwt-default@canonical"]["row_state"] == "PASS"
    assert indexed["post:coolify-trust-host-cache@canonical"]["row_state"] == "UNKNOWN"
    zae = indexed["strict-200-v3:alias-99ee5f834a00aca5862a1926"]
    assert zae["row_state"] == "PASS" and zae["repository"] == "zeroae/zae-limiter"
    assert zae["candidate_fix_edges"] == [
        {
            "candidate_sha": "3902c8c22868832db6d9f54046e76d5be226f607",
            "fix_sha": "9f66c42f06f3b87107ce327bede6416a582f0e60",
            "origin_kind": "direct_commit",
        }
    ]
    assert zae["atomic_fix_members"] == [
        "2d8cdd8c7c3825506e9e55def53ec0f3d18aa524",
        "abd6a8a9aa043e755e7da798dcb5eebb6f6c1d69",
        "8fba24d17cb8f7679f93a0476ce235d7e0433784",
        "94a129ae55acc3b034662045296e288279cbef2e",
        "6e64d5b2df6a4671024902c29861d93d9c2c4e16",
        "9f66c42f06f3b87107ce327bede6416a582f0e60",
    ]
    assert zae["release_evidence"]["fix_sha"] == "481ce44d818d66e31d8837bc48519660ce4c267f"
    ha_mcp = indexed["strict-200-v3:alias-02fb7aeb21b9f4e1ab18fbce"]
    assert ha_mcp["row_state"] == "PASS" and ha_mcp["repository"] == "homeassistant-ai/ha-mcp"
    assert ha_mcp["atomic_fix_members"] == ["0ca572a1452cbabc9004993d6a649afa3c0f435d"]
    assert ha_mcp["release_evidence"]["candidate_member_sha"] == ha_mcp["candidate_fix_edges"][0]["candidate_sha"]
    assert ha_mcp["release_evidence"]["fix_member_sha"] == ha_mcp["atomic_fix_members"][0]
    filebrowser = indexed["post:filebrowser-scoped-fs@canonical"]
    assert filebrowser["row_state"] == "REJECT" and not any(filebrowser["counting"].values())
    assert set(filebrowser["overlap_with"]) == {
        "post:filebrowser-delete-scope@canonical",
        "post:filebrowser-dangling-write@canonical",
    }
    assert summary["source_envelopes"] == {
        "strict_document_rows": 132,
        "broad_released_max": 199,
        "widest_max": 211,
        "final_count": None,
    }
    assert summary["status"] == "HOLD"
    assert summary["integration_ready"] is False
    return summary, additions, controls


def verify_live(additions: list[dict]) -> dict:
    checked_advisories: set[tuple[str, str]] = set()
    row_cves = {row["row_key"]: {value for value in row["public_ids"] if value.startswith("CVE-")} for row in additions}
    observed_cves: dict[str, set[str]] = defaultdict(set)

    for row in additions:
        evidence = row["release_evidence"]
        repo = Path.home() / ".cache/cve-analyzer/repos" / evidence["repo_cache"]
        assert repo.joinpath(".git").exists(), repo
        atom = row["candidate_fix_edges"][0]["candidate_sha"]
        for sha_value in {atom, evidence["candidate_sha"], evidence["fix_sha"], row["ai_provenance"]["marker_sha"], *row["atomic_fix_members"]}:
            git(repo, "cat-file", "-e", f"{sha_value}^{{commit}}")
        parents = git(repo, "rev-list", "--parents", "-n", "1", atom).stdout.split()
        assert len(parents) == 2, f"non-atomic candidate: {row['row_key']}"
        marker_message = git(repo, "show", "-s", "--format=%s%n%b", row["ai_provenance"]["marker_sha"]).stdout.lower()
        assert any(marker in marker_message for marker in AI_MARKERS), row["row_key"]
        assert git(repo, "merge-base", "--is-ancestor", evidence["candidate_sha"], evidence["vulnerable_tag"], check=False).returncode == 0
        assert git(repo, "merge-base", "--is-ancestor", evidence["fix_sha"], evidence["vulnerable_tag"], check=False).returncode == 1
        assert git(repo, "merge-base", "--is-ancestor", evidence["fix_sha"], evidence["fixed_tag"], check=False).returncode == 0

        for ghsa in (value for value in row["public_ids"] if value.startswith("GHSA-")):
            key = (row["repository"], ghsa)
            if key in checked_advisories:
                continue
            advisory = gh_json(f"repos/{row['repository']}/security-advisories/{ghsa.lower()}")
            assert advisory["ghsa_id"].upper() == ghsa
            assert advisory["state"] == "published" and advisory["withdrawn_at"] is None
            repo_ids = {item["value"].upper() for item in advisory["identifiers"]}
            observed_cves[row["row_key"]].update(value for value in repo_ids if value.startswith("CVE-"))
            if row_cves[row["row_key"]] and not (repo_ids & row_cves[row["row_key"]]):
                global_advisory = gh_json(f"advisories/{ghsa.lower()}")
                global_ids = {item["value"].upper() for item in global_advisory["identifiers"]}
                observed_cves[row["row_key"]].update(value for value in global_ids if value.startswith("CVE-"))
            checked_advisories.add(key)

    for row_key, expected in row_cves.items():
        assert observed_cves[row_key] == expected, (row_key, observed_cves[row_key], expected)
    return {
        "release_edges": len(additions),
        "published_repo_advisories": len(checked_advisories),
        "public_ids": len({value for row in additions for value in row["public_ids"]}),
    }


def tar_member(archive: bytes, suffix: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        matches = [member for member in tar.getmembers() if member.name.endswith(suffix)]
        assert len(matches) == 1, (suffix, [member.name for member in matches])
        extracted = tar.extractfile(matches[0])
        assert extracted is not None
        return extracted.read()


def verify_pypi_artifact(evidence: dict) -> None:
    observed = {}
    for label in ("vulnerable", "fixed"):
        version = evidence[f"{label}_version"]
        metadata = url_json(f"https://pypi.org/pypi/{evidence['package']}/{version}/json")
        sdists = [item for item in metadata["urls"] if item["packagetype"] == "sdist"]
        assert len(sdists) == 1
        assert sdists[0]["digests"]["sha256"] == evidence[f"{label}_sdist_sha256"]
        archive = url_bytes(sdists[0]["url"])
        assert hashlib.sha256(archive).hexdigest() == evidence[f"{label}_sdist_sha256"]
        auth_service = tar_member(archive, "/praisonai_platform/services/auth_service.py")
        assert hashlib.sha256(auth_service).hexdigest() == evidence[f"{label}_auth_service_sha256"]
        observed[label] = (archive, auth_service)

    assert b'os.environ.get("PLATFORM_ENV", "dev")' in observed["vulnerable"][1]
    assert b"from .jwt_secret import resolve_jwt_secret" in observed["fixed"][1]
    jwt_secret = tar_member(observed["fixed"][0], "/praisonai_platform/services/jwt_secret.py")
    assert hashlib.sha256(jwt_secret).hexdigest() == evidence["fixed_jwt_secret_sha256"]
    assert b'explicit_env = env.get("PLATFORM_ENV")' in jwt_secret
    assert b"ephemeral = secrets.token_urlsafe(32)" in jwt_secret


def verify_inherited_live() -> dict:
    ledger = {row["row_key"]: row for row in load_jsonl(HERE / "ledger.jsonl")}

    gitea = ledger["post:gitea-draft-attachment@canonical"]
    gitea_repo = Path.home() / ".cache/cve-analyzer/repos" / gitea["release_evidence"]["repo_cache"]
    for sha_value in (
        gitea["candidate_fix_edges"][0]["candidate_sha"],
        gitea["release_evidence"]["candidate_sha"],
    ):
        git(gitea_repo, "cat-file", "-e", f"{sha_value}^{{commit}}")
    assert "copilot" in git(
        gitea_repo, "show", "-s", "--format=%s%n%b", gitea["ai_provenance"]["marker_sha"]
    ).stdout.lower()
    assert git(
        gitea_repo,
        "merge-base",
        "--is-ancestor",
        gitea["release_evidence"]["candidate_sha"],
        gitea["release_evidence"]["vulnerable_tag"],
        check=False,
    ).returncode == 0
    assert compare_contains("go-gitea/gitea", gitea["release_evidence"]["fix_sha"], gitea["release_evidence"]["fixed_tag"])
    assert not compare_contains(
        "go-gitea/gitea", gitea["release_evidence"]["fix_sha"], gitea["release_evidence"]["last_vulnerable_tag"]
    )
    gitea_global = advisory_alias("go-gitea/gitea", "GHSA-Q9PG-JJ6X-J9P6", "CVE-2026-58432")
    assert gitea_global["vulnerabilities"][0]["first_patched_version"] == "1.27.0"

    praison = ledger["post:praisonai-jwt-default@canonical"]
    praison_repo = Path.home() / ".cache/cve-analyzer/repos" / praison["release_evidence"]["repo_cache"]
    for sha_value in (
        praison["candidate_fix_edges"][0]["candidate_sha"],
        praison["candidate_fix_edges"][0]["fix_sha"],
    ):
        git(praison_repo, "cat-file", "-e", f"{sha_value}^{{commit}}")
    assert "cursor" in git(
        praison_repo, "show", "-s", "--format=%s%n%b", praison["ai_provenance"]["marker_sha"]
    ).stdout.lower()
    praison_global = advisory_alias("MervinPraison/PraisonAI", "GHSA-F38V-77QJ-H4JQ", "CVE-2026-57148")
    assert praison_global["vulnerabilities"][0]["first_patched_version"] == "0.1.6"
    verify_pypi_artifact(praison["release_evidence"])

    filebrowser = ledger["post:filebrowser-scoped-fs@canonical"]
    original = advisory_alias("filebrowser/filebrowser", "GHSA-239W-M3H6-CH8V", "CVE-2026-54094")
    assert original["vulnerabilities"][0]["first_patched_version"] == "2.63.14"
    for ghsa, cve in (
        ("GHSA-FMM7-X4GX-8JHR", "CVE-2026-55667"),
        ("GHSA-8WC8-HF36-MJH9", "CVE-2026-55668"),
    ):
        residual = advisory_alias("filebrowser/filebrowser", ghsa, cve)
        assert residual["vulnerabilities"][0]["first_patched_version"] == "2.63.16"
    filebrowser_repo = Path.home() / ".cache/cve-analyzer/repos/filebrowser_filebrowser"
    for sha_value, tag, expected in (
        ("847d08bdd135e5c3659f2e6dea2f0cd36617af9b", "v2.63.6", 0),
        ("7c2c0a11b31b2bb214d741005a0b02b1764208b3", "v2.63.14", 0),
        ("64511ce45e3be379e965f7f4fb0929a068d5bb81", "v2.63.15", 1),
        ("64511ce45e3be379e965f7f4fb0929a068d5bb81", "v2.63.16", 0),
    ):
        assert git(filebrowser_repo, "merge-base", "--is-ancestor", sha_value, tag, check=False).returncode == expected
    assert filebrowser["row_state"] == "REJECT" and not any(filebrowser["counting"].values())

    coolify = ledger["post:coolify-trust-host-cache@canonical"]
    coolify_advisory = gh_json("repos/coollabsio/coolify/security-advisories/ghsa-cgj8-7m5q-x5gv")
    assert coolify_advisory["state"] == "published" and coolify_advisory["withdrawn_at"] is None
    assert {item["value"].upper() for item in coolify_advisory["identifiers"]} == {
        "CVE-2026-34198",
        "GHSA-CGJ8-7M5Q-X5GV",
    }
    coolify_repo = Path.home() / ".cache/cve-analyzer/repos/coollabsio_coolify"
    candidate = "e1fe58639756cf7b232458eddd6978e4ed0031f5"
    fix = "e1d4b4682efc898ba5aa3751b2da2072f89c7e24"
    subject_body = git(coolify_repo, "show", "-s", "--format=%s%n%b", candidate).stdout.strip()
    assert subject_body == "Changes auto-committed by Conductor"
    assert not any(marker in subject_body.lower() for marker in AI_MARKERS)
    assert git(coolify_repo, "merge-base", "--is-ancestor", candidate, "v4.0.0-beta.470", check=False).returncode == 0
    assert git(coolify_repo, "merge-base", "--is-ancestor", fix, "v4.0.0-beta.470", check=False).returncode == 1
    assert git(coolify_repo, "merge-base", "--is-ancestor", fix, "v4.0.0-beta.471", check=False).returncode == 0
    assert coolify["row_state"] == "UNKNOWN"

    zae = ledger["strict-200-v3:alias-99ee5f834a00aca5862a1926"]
    zae_repo = Path.home() / ".cache/cve-analyzer/repos" / zae["release_evidence"]["repo_cache"]
    zae_candidate = zae["candidate_fix_edges"][0]["candidate_sha"]
    zae_closure = zae["candidate_fix_edges"][0]["fix_sha"]
    zae_carrier = zae["release_evidence"]["fix_sha"]
    for sha_value in {zae_candidate, zae_closure, zae_carrier, *zae["atomic_fix_members"]}:
        git(zae_repo, "cat-file", "-e", f"{sha_value}^{{commit}}")
    assert len(git(zae_repo, "rev-list", "--parents", "-n", "1", zae_candidate).stdout.split()) == 1
    assert "claude opus 4.5" in git(
        zae_repo, "show", "-s", "--format=%s%n%b", zae["ai_provenance"]["marker_sha"]
    ).stdout.lower()
    assert git(zae_repo, "merge-base", "--is-ancestor", zae_candidate, "v0.10.0", check=False).returncode == 0
    for member in zae["atomic_fix_members"]:
        assert git(zae_repo, "merge-base", "--is-ancestor", member, "v0.10.0", check=False).returncode == 1
        assert git(zae_repo, "merge-base", "--is-ancestor", member, zae_closure, check=False).returncode == 0
        assert git(zae_repo, "merge-base", "--is-ancestor", member, "v0.10.1", check=False).returncode == 0
    assert git(zae_repo, "rev-parse", "v0.10.1^{commit}").stdout.strip() == zae_carrier
    old_symbols = git(
        zae_repo,
        "grep",
        "-n",
        "-E",
        r"bump_shard_count|random\.randrange|MAX_SHARD_RETRIES|_is_wcu_exhausted",
        "94a129ae55acc3b034662045296e288279cbef2e",
        "--",
        "src/zae_limiter",
        check=False,
    )
    assert old_symbols.returncode == 1 and not old_symbols.stdout
    closure_symbols = git(
        zae_repo,
        "grep",
        "-n",
        "-E",
        r"bump_shard_count|random\.randrange|MAX_SHARD_RETRIES|_is_wcu_exhausted",
        zae_closure,
        "--",
        "src/zae_limiter",
    ).stdout
    assert all(symbol in closure_symbols for symbol in ("bump_shard_count", "random.randrange", "MAX_SHARD_RETRIES"))
    zae_global = advisory_alias("zeroae/zae-limiter", "GHSA-76RV-2R9V-C5M6", "CVE-2026-27695")
    assert zae_global["vulnerabilities"][0]["first_patched_version"] == "0.10.1"

    ha_mcp = ledger["strict-200-v3:alias-02fb7aeb21b9f4e1ab18fbce"]
    ha_repo = Path.home() / ".cache/cve-analyzer/repos" / ha_mcp["release_evidence"]["repo_cache"]
    ha_edge = ha_mcp["candidate_fix_edges"][0]
    ha_fix_member = ha_mcp["atomic_fix_members"][0]
    for sha_value in {ha_edge["candidate_sha"], ha_edge["carrier_sha"], ha_edge["fix_sha"], ha_fix_member}:
        git(ha_repo, "cat-file", "-e", f"{sha_value}^{{commit}}")
    assert len(git(ha_repo, "rev-list", "--parents", "-n", "1", ha_edge["candidate_sha"]).stdout.split()) == 2
    assert len(git(ha_repo, "rev-list", "--parents", "-n", "1", ha_fix_member).stdout.split()) == 2
    assert "claude" in git(
        ha_repo, "show", "-s", "--format=%s%n%b", ha_mcp["ai_provenance"]["marker_sha"]
    ).stdout.lower()
    origin_pr = gh_json("repos/homeassistant-ai/ha-mcp/pulls/368")
    origin_members = gh_json("repos/homeassistant-ai/ha-mcp/pulls/368/commits")
    assert origin_pr["merged"] and origin_pr["merge_commit_sha"] == ha_edge["carrier_sha"]
    assert ha_edge["candidate_sha"] in {item["sha"] for item in origin_members}
    fix_pr = gh_json("repos/homeassistant-ai/ha-mcp/pulls/748")
    fix_members = gh_json("repos/homeassistant-ai/ha-mcp/pulls/748/commits")
    assert fix_pr["merged"] and fix_pr["merge_commit_sha"] == ha_edge["fix_sha"]
    assert ha_fix_member in {item["sha"] for item in fix_members}
    assert git(ha_repo, "merge-base", "--is-ancestor", ha_edge["carrier_sha"], "v6.7.2", check=False).returncode == 0
    assert git(ha_repo, "merge-base", "--is-ancestor", ha_edge["fix_sha"], "v6.7.2", check=False).returncode == 1
    assert git(ha_repo, "merge-base", "--is-ancestor", ha_edge["fix_sha"], "v7.0.0", check=False).returncode == 0
    for revision in (ha_edge["candidate_sha"], ha_edge["carrier_sha"]):
        for pattern in ('form.get("ha_url")', "_validate_ha_credentials", 'f"{ha_url}/api/config"'):
            assert git(ha_repo, "grep", "-F", pattern, revision, "--", "src/ha_mcp", check=False).returncode == 0
    for revision in (ha_fix_member, ha_edge["fix_sha"]):
        for pattern in ('form.get("ha_url")', "_validate_ha_credentials", 'f"{ha_url}/api/config"'):
            assert git(ha_repo, "grep", "-F", pattern, revision, "--", "src/ha_mcp", check=False).returncode == 1
        assert git(
            ha_repo, "grep", "-F", 'os.getenv("HOMEASSISTANT_URL")', revision, "--", "src/ha_mcp/__main__.py"
        ).returncode == 0
    ha_global = advisory_alias("homeassistant-ai/ha-mcp", "GHSA-FMFG-9G7C-3VQ7", "CVE-2026-32111")
    assert ha_global["vulnerabilities"][0]["first_patched_version"] == "7.0.0"

    return {
        "admitted_alias_release_rows": 2,
        "corrected_strict_fix_edges": 2,
        "semantic_overlap_controls": 1,
        "attribution_unknown_controls": 1,
        "targeted_rows": 6,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also replay Git containment and first-party advisory status")
    parser.add_argument("--write-result", action="store_true")
    args = parser.parse_args()
    summary, additions, controls = verify_structural()
    live_counts = verify_live(additions) if args.live else None
    inherited_live = verify_inherited_live() if args.live else None
    result = {
        "status": "HOLD",
        "validation": "PASS",
        "integration_ready": False,
        "validated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "ledger_sha256": summary["ledger_sha256"],
        "structural_counts": summary["counts"],
        "live_counts": live_counts,
        "inherited_live": inherited_live,
        "route_controls": len(controls),
        "gate_status": {
            "public_id_alias_released": "PASS",
            "public_id_alias_widest": "PARTIAL",
            "mechanism_fingerprint_exact": "PASS",
            "semantic_mechanism_review": "PARTIAL",
            "release_containment": "PARTIAL",
            "conservation": "PASS",
        },
        "blockers": summary["blockers"],
    }
    if args.write_result:
        (HERE / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    live_suffix = "" if live_counts is None else (
        f", {live_counts['release_edges'] + inherited_live['admitted_alias_release_rows'] + inherited_live['corrected_strict_fix_edges']} admitted release rows live-replayed"
    )
    print(f"PASS: {summary['counts']['ledger_records']} records, source envelope 132/199/211, HOLD{live_suffix}")


if __name__ == "__main__":
    main()
