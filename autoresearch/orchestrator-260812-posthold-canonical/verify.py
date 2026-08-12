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
        {"PASS": 159, "NARROW": 26, "UNKNOWN": 4, "REJECT": 10}
    )
    public_ids = [value for row in canonical for value in row["public_ids"]]
    assert len(public_ids) == len(set(public_ids)) == 366
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
        "post:argo-artifactgc-podspec@canonical",
        "post:coolify-trust-host-cache@canonical",
        "post:faraday-uri-authority@canonical",
        "post:filebrowser-delete-scope@canonical",
        "post:filebrowser-scoped-fs@canonical",
        "post:gitea-draft-attachment@canonical",
        "post:praisonai-jwt-default@canonical",
        "strict-200-v3:alias-02fb7aeb21b9f4e1ab18fbce",
        "strict-200-v3:alias-043e2fc26bdd6275f9cae512",
        "strict-200-v3:alias-04967329955171a53cc2731f",
        "strict-200-v3:alias-04f677245516e574c5201c86",
        "strict-200-v3:alias-081a549b9da97e4d5e1e54c4",
        "strict-200-v3:alias-08f4ee97e5be53cda71a58d8",
        "strict-200-v3:alias-1416131f1ab575212ff869b2",
        "strict-200-v3:alias-169a79f1a59e092002eab928",
        "strict-200-v3:alias-17d78446a20e0607b519cb7d",
        "strict-200-v3:alias-1ac241b6b959b320f90a397c",
        "strict-200-v3:alias-1c31c40c0a061d5194e8ba95",
        "strict-200-v3:alias-21d75c6b2298811581b2259d",
        "strict-200-v3:alias-2788167921d685f8a3bb43a5",
        "strict-200-v3:alias-29dedb40ead513739ee1d647",
        "strict-200-v3:alias-323bf07420daae79c5a0844f",
        "strict-200-v3:alias-3cac93e2e744b1b362bb38a6",
        "strict-200-v3:alias-3ed594d20d11056d42d54528",
        "strict-200-v3:alias-3f35b69df081559ab1fad010",
        "strict-200-v3:alias-444d166bd62f8714937b931d",
        "strict-200-v3:alias-470d0cf2ef6e3a7cf2d1be73",
        "strict-200-v3:alias-4f3fe99f85fab6a063ea6784",
        "strict-200-v3:alias-57569b18ed81b84118a1fdb1",
        "strict-200-v3:alias-63a1cac4d02e61992ad6cf29",
        "strict-200-v3:alias-69c709472a21c9ed2b2637a2",
        "strict-200-v3:alias-7e96caa20b835ee167518f82",
        "strict-200-v3:alias-8099a555171349d287af92d",
        "strict-200-v3:alias-8fde3b61bfb7a8b43050519d",
        "strict-200-v3:alias-9012f3e444c033b0f2a19660",
        "strict-200-v3:alias-92431dcbbb3899c7f124c4dd",
        "strict-200-v3:alias-948cde45baab136c086accc3",
        "strict-200-v3:alias-9764e28bbc2e093b13aaac3e",
        "strict-200-v3:alias-994d3f3f9e29079393c87538",
        "strict-200-v3:alias-99ee5f834a00aca5862a1926",
        "strict-200-v3:alias-9dc5f3e6176baf486fd2696c",
        "strict-200-v3:alias-a05009adfdf51481b4c4ab3d",
        "strict-200-v3:alias-a16652492e42b6eefef74358",
        "strict-200-v3:alias-a87ef9051feecb7a9cd00c99",
        "strict-200-v3:alias-b2364e4376391dd977cef4fa",
        "strict-200-v3:alias-b52bedc69eca463aef477f74",
        "strict-200-v3:alias-b957cebfc80b884b647c24e8",
        "strict-200-v3:alias-ca54d2dace0b4a1f719ce3be",
        "strict-200-v3:alias-e185a69fdf0f5a626f9bc3d0",
        "strict-200-v3:alias-ed3fab545510d72c9e9ecc14",
        "strict-200-v3:alias-f0b371318e30448b9a250d8a",
        "strict-200-v3:component-ironclaw-cw23-command-risk",
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
    mysti = indexed["strict-200-v3:alias-08f4ee97e5be53cda71a58d8"]
    assert mysti["row_state"] == "PASS" and mysti["repository"] == "DeepMyst/Mysti"
    assert mysti["atomic_fix_members"] == ["c6daf9107a8dc14088feff4671657e6319e36628"]
    assert mysti["release_evidence"]["fix_member_sha"] == mysti["atomic_fix_members"][0]
    assert mysti["release_evidence"]["fixed_tag"] is None
    prek = indexed["strict-200-v3:alias-04f677245516e574c5201c86"]
    assert prek["row_state"] == "NARROW"
    assert "GHSA-PWF7-47C3-MFHX" in prek["public_ids"]
    hermes_session = indexed["strict-200-v3:alias-1ac241b6b959b320f90a397c"]
    assert hermes_session["row_state"] == "NARROW"
    getlogs = indexed["strict-200-v3:alias-63a1cac4d02e61992ad6cf29"]
    assert getlogs["row_state"] == "NARROW" and set(getlogs["public_ids"]) == {
        "CVE-2026-34599",
        "GHSA-Q9J6-XCVX-PX63",
    }
    helper = indexed["strict-200-v3:alias-7e96caa20b835ee167518f82"]
    assert helper["row_state"] == "PASS" and set(helper["public_ids"]) == {
        "CVE-2026-42148",
        "GHSA-X9QH-W4C4-54F9",
    }
    agentic = indexed["strict-200-v3:alias-8fde3b61bfb7a8b43050519d"]
    assert agentic["row_state"] == "PASS"
    assert agentic["atomic_fix_members"] == ["a0f9c2bf95b6203b3e1b24f92a7e390d6774de13"]
    assert agentic["release_evidence"]["fix_sha"] == "0c2ec967736a8b6b85832c6bae2a3e74989705ec"
    media = indexed["strict-200-v3:alias-948cde45baab136c086accc3"]
    assert media["row_state"] == "PASS"
    assert media["candidate_fix_edges"][0]["fix_sha"] == "f865a5455ee03924a444e9ba0f1c4743d8fb6566"
    assert set(media["public_ids"]) == {"CVE-2026-41345", "GHSA-68V4-HMWV-F43H"}
    quay = indexed["strict-200-v3:alias-994d3f3f9e29079393c87538"]
    assert quay["row_state"] == "UNKNOWN"
    assert quay["release_evidence"]["vulnerable_tag"] is None
    attachments = indexed["strict-200-v3:alias-b2364e4376391dd977cef4fa"]
    assert attachments["row_state"] == "REJECT" and attachments["counting"]["canonical_instance"] is True
    gitlab_mcp = indexed["strict-200-v3:alias-9dc5f3e6176baf486fd2696c"]
    assert gitlab_mcp["row_state"] == "NARROW"
    assert "GHSA-7C3W-FXGH-FRC7" in gitlab_mcp["public_ids"]
    filebrowser = indexed["post:filebrowser-scoped-fs@canonical"]
    assert filebrowser["row_state"] == "REJECT" and not any(filebrowser["counting"].values())
    assert set(filebrowser["overlap_with"]) == {
        "post:filebrowser-delete-scope@canonical",
        "post:filebrowser-dangling-write@canonical",
    }
    graphiti = indexed["strict-200-v3:alias-081a549b9da97e4d5e1e54c4"]
    assert graphiti["row_state"] == "UNKNOWN"
    assert graphiti["candidate_fix_edges"][0]["candidate_sha"] == "1d94f7a3e3cebeba404aa4b48cf3d0742750595f"
    coder = indexed["strict-200-v3:alias-ed3fab545510d72c9e9ecc14"]
    assert coder["row_state"] == "REJECT" and coder["counting"]["canonical_instance"] is True
    assert coder["release_evidence"]["vulnerable_tag"] is None
    karakeep = indexed["strict-200-v3:alias-21d75c6b2298811581b2259d"]
    assert karakeep["row_state"] == "REJECT" and "GHSA-MG93-F9MW-WPGJ" in karakeep["public_ids"]
    actual = indexed["strict-200-v3:alias-3ed594d20d11056d42d54528"]
    assert actual["row_state"] == "PASS"
    assert actual["atomic_fix_members"] == ["48699c46b1b5cc296bc76dd637edb47b0c02d926"]
    faraday = indexed["post:faraday-uri-authority@canonical"]
    assert faraday["row_state"] == "PASS"
    assert faraday["candidate_fix_edges"][0]["candidate_sha"] == "a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc"
    delete_scope = indexed["post:filebrowser-delete-scope@canonical"]
    assert delete_scope["row_state"] == "REJECT" and delete_scope["counting"]["canonical_instance"] is True
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

    mysti = ledger["strict-200-v3:alias-08f4ee97e5be53cda71a58d8"]
    mysti_repo = Path.home() / ".cache/cve-analyzer/repos" / mysti["release_evidence"]["repo_cache"]
    mysti_edge = mysti["candidate_fix_edges"][0]
    mysti_fix_member = mysti["atomic_fix_members"][0]
    for sha_value in {mysti_edge["candidate_sha"], mysti_edge["fix_sha"], mysti_fix_member}:
        git(mysti_repo, "cat-file", "-e", f"{sha_value}^{{commit}}")
    assert len(git(mysti_repo, "rev-list", "--parents", "-n", "1", mysti_edge["candidate_sha"]).stdout.split()) == 2
    assert len(git(mysti_repo, "rev-list", "--parents", "-n", "1", mysti_fix_member).stdout.split()) == 2
    assert "claude opus 4.6" in git(
        mysti_repo, "show", "-s", "--format=%s%n%b", mysti["ai_provenance"]["marker_sha"]
    ).stdout.lower()
    assert git(mysti_repo, "rev-parse", "v0.4.0^{commit}").stdout.strip() == mysti_edge["candidate_sha"]
    assert git(mysti_repo, "merge-base", "--is-ancestor", mysti_edge["fix_sha"], "v0.4.0", check=False).returncode == 1
    vulnerable_source = git(mysti_repo, "show", f"{mysti_edge['candidate_sha']}:src/managers/MemoryManager.ts").stdout
    assert ".update(workspacePath).digest('hex').substring(0, 12)" in vulnerable_source
    fixed_source = git(mysti_repo, "show", f"{mysti_fix_member}:src/managers/MemoryManager.ts").stdout
    assert "fs.realpathSync.native(workspacePath)" in fixed_source
    assert "PROJECT_MEMORY_KEY_SCHEMA" in fixed_source
    fix_pr = gh_json("repos/DeepMyst/Mysti/pulls/49")
    fix_members = gh_json("repos/DeepMyst/Mysti/pulls/49/commits")
    assert fix_pr["merged"] and fix_pr["merge_commit_sha"] == mysti_edge["fix_sha"]
    assert mysti_fix_member == fix_members[0]["sha"]
    issue = gh_json("repos/DeepMyst/Mysti/issues/46")
    assert issue["state"] == "closed" and mysti_edge["candidate_sha"] in issue["body"]
    mysti_global = gh_json("advisories/ghsa-fwpr-59hh-gr98")
    assert mysti_global["withdrawn_at"] is None
    assert {item["value"].upper() for item in mysti_global["identifiers"]} == {
        "CVE-2026-14611",
        "GHSA-FWPR-59HH-GR98",
    }
    assert "upgrading to version 0.4.0 is sufficient" in mysti_global["description"].lower()

    return {
        "admitted_alias_release_rows": 2,
        "corrected_strict_fix_edges": 3,
        "semantic_overlap_controls": 1,
        "attribution_unknown_controls": 1,
        "targeted_rows": 7,
    }


def verify_batch_i_live() -> dict:
    ledger = {row["row_key"]: row for row in load_jsonl(HERE / "ledger.jsonl")}
    cache = Path.home() / ".cache/cve-analyzer/repos"

    attachments = ledger["strict-200-v3:alias-b2364e4376391dd977cef4fa"]
    oc = cache / "openclaw_openclaw"
    parent_src = git(oc, "show", "0279f0945916f0c309703dd24cc0f1de3532d63f:src/gateway/chat-attachments.ts").stdout
    assert "export function buildMessageWithAttachments(" in parent_src
    assert 'Buffer.from(b64, "base64").byteLength' in parent_src
    assert attachments["row_state"] == "REJECT"

    prek = ledger["strict-200-v3:alias-04f677245516e574c5201c86"]
    prek_repo = cache / "j178_prek-action"
    parent_action = git(prek_repo, "show", "aa1aa3537bd5d7db7b20d2bcf88c0320f7dee2dd:action.yaml").stdout
    candidate_action = git(prek_repo, "show", prek["candidate_fix_edges"][0]["candidate_sha"] + ":action.yaml").stdout
    assert "${{ inputs.extra_args }}" in parent_action
    assert "prek-version" not in parent_action
    assert "${{ inputs.prek-version }}" in candidate_action
    assert prek["row_state"] == "NARROW"

    getlogs = ledger["strict-200-v3:alias-63a1cac4d02e61992ad6cf29"]
    coolify = cache / "coollabsio_coolify"
    parent_logs = git(
        coolify,
        "show",
        getlogs["candidate_fix_edges"][0]["candidate_sha"] + "^:app/Livewire/Project/Shared/GetLogs.php",
    ).stdout
    candidate_logs = git(
        coolify,
        "show",
        getlogs["candidate_fix_edges"][0]["candidate_sha"] + ":app/Livewire/Project/Shared/GetLogs.php",
    ).stdout
    assert "function getLogs" in parent_logs and "function downloadAllLogs" not in parent_logs
    assert "function downloadAllLogs" in candidate_logs
    assert getlogs["row_state"] == "NARROW"

    media = ledger["strict-200-v3:alias-948cde45baab136c086accc3"]
    first_fix = media["candidate_fix_edges"][0]["fix_sha"]
    later = "e704323ff388ed21f6963f9b8e0b1b8dfaaabc5f"
    assert git(oc, "merge-base", "--is-ancestor", first_fix, later, check=False).returncode == 0
    later_parent = git(oc, "grep", "-n", "retainSafeHeadersForCrossOriginRedirectHeaders", later + "^", "--", "src/media/store.ts")
    assert later_parent.returncode == 0
    assert media["row_state"] == "PASS"

    agentic = ledger["strict-200-v3:alias-8fde3b61bfb7a8b43050519d"]
    af = cache / "github.com_ruvnet_agentic-flow"
    merge_parents = git(af, "rev-list", "--parents", "-n", "1", agentic["release_evidence"]["fix_sha"]).stdout.split()
    assert agentic["atomic_fix_members"][0] in merge_parents
    assert len(git(af, "rev-list", "--parents", "-n", "1", agentic["atomic_fix_members"][0]).stdout.split()) == 2

    quay = ledger["strict-200-v3:alias-994d3f3f9e29079393c87538"]
    quay_repo = cache / "quay_quay"
    tags = git(quay_repo, "tag", "-l", "*3.16*", "*3.17*").stdout.strip()
    assert tags == ""
    assert quay["row_state"] == "UNKNOWN"

    return {
        "state_changing_rows_replayed": 6,
        "reject_rows": 1,
        "narrow_rows": 2,
        "unknown_rows": 1,
        "pass_fix_recoveries": 2,
    }


def verify_batch_ii_live() -> dict:
    ledger = {row["row_key"]: row for row in load_jsonl(HERE / "ledger.jsonl")}
    cache = Path.home() / ".cache/cve-analyzer/repos"
    v2 = ROOT / ".ai-slop/cache/cve-analyzer/repos"

    graphiti = ledger["strict-200-v3:alias-081a549b9da97e4d5e1e54c4"]
    g_repo = cache / "getzep_graphiti"
    search_utils = git(g_repo, "show", "v0.28.1:graphiti_core/search/search_utils.py").stdout
    assert 'group_id:"{g}"' in search_utils
    search_py = git(g_repo, "show", "v0.28.1:graphiti_core/search/search.py").stdout
    assert "from graphiti_core.search.search_utils import" in search_py
    assert ".search_ops" not in search_py
    assert graphiti["row_state"] == "UNKNOWN"

    coder = ledger["strict-200-v3:alias-ed3fab545510d72c9e9ecc14"]
    c_repo = cache / "coder_coder"
    member = coder["candidate_fix_edges"][0]["candidate_sha"]
    carrier = coder["candidate_fix_edges"][0]["carrier_sha"]
    fix = coder["candidate_fix_edges"][0]["fix_sha"]
    assert git(c_repo, "merge-base", "--is-ancestor", carrier, "v2.34.0", check=False).returncode == 0
    assert git(c_repo, "merge-base", "--is-ancestor", fix, "v2.34.0", check=False).returncode == 0
    assert git(c_repo, "merge-base", "--is-ancestor", carrier, "v2.34.0-rc.0", check=False).returncode == 1
    parent = git(c_repo, "rev-parse", member + "^").stdout.strip()
    parent_src = git(c_repo, "show", parent + ":coderd/azureidentity/azureidentity.go").stdout
    assert "allowedCertHosts" in parent_src
    assert coder["row_state"] == "REJECT"

    karakeep = ledger["strict-200-v3:alias-21d75c6b2298811581b2259d"]
    k_repo = cache / "karakeep-app_karakeep"
    assert git(k_repo, "cat-file", "-e", "v0.30.0:apps/workers/scripts/parseHtmlSubprocess.ts", check=False).returncode != 0
    crawler = git(k_repo, "show", "v0.30.0:apps/workers/workers/crawlerWorker.ts").stdout
    assert "meta.readableContentHtml" in crawler
    assert karakeep["row_state"] == "REJECT"

    argo = ledger["post:argo-artifactgc-podspec@canonical"]
    a_repo = cache / "argoproj_argo-workflows"
    parents = git(a_repo, "rev-list", "--parents", "-n", "1", argo["candidate_fix_edges"][0]["candidate_sha"]).stdout.split()
    assert len(parents) == 2
    assert "Claude Opus 4.6" in git(a_repo, "log", "-1", "--format=%B", argo["candidate_fix_edges"][0]["candidate_sha"]).stdout
    assert argo["row_state"] == "UNKNOWN"

    actual = ledger["strict-200-v3:alias-3ed594d20d11056d42d54528"]
    act_repo = cache / "actualbudget_actual"
    origin_parent = git(act_repo, "rev-parse", actual["candidate_fix_edges"][0]["candidate_sha"] + "^").stdout.strip()
    assert git(act_repo, "cat-file", "-e", origin_parent + ":packages/cli/src/output.ts", check=False).returncode != 0
    origin = git(act_repo, "show", actual["candidate_fix_edges"][0]["candidate_sha"] + ":packages/cli/src/output.ts").stdout
    assert "function escapeCsv" in origin and "FORMULA_TRIGGERS" not in origin
    fix_member = git(act_repo, "show", actual["atomic_fix_members"][0] + ":packages/cli/src/output.ts").stdout
    assert "FORMULA_TRIGGERS" in fix_member
    assert actual["row_state"] == "PASS"

    faraday = ledger["post:faraday-uri-authority@canonical"]
    f_repo = cache / "lostisland_faraday"
    vulnerable = git(f_repo, "show", "v2.14.1:lib/faraday/connection.rb").stdout
    assert "url.start_with?('//')" in vulnerable
    assert "url.to_s if url.respond_to?(:host)" not in vulnerable
    fixed = git(f_repo, "show", "v2.14.2:lib/faraday/connection.rb").stdout
    assert "url.to_s if url.respond_to?(:host)" in fixed
    assert faraday["row_state"] == "PASS"

    sticker = ledger["strict-200-v3:alias-169a79f1a59e092002eab928"]
    oc = cache / "openclaw_openclaw"
    sticker_parent = git(oc, "rev-parse", sticker["candidate_fix_edges"][0]["candidate_sha"] + "^").stdout.strip()
    parent_fetch = git(oc, "show", sticker_parent + ":src/media/fetch.ts").stdout
    assert "Failed to fetch media from ${url}" in parent_fetch
    names = git(oc, "diff", "--name-only", sticker_parent, sticker["candidate_fix_edges"][0]["candidate_sha"]).stdout
    assert "src/media/fetch.ts" not in names
    assert sticker["row_state"] == "REJECT"

    delete_scope = ledger["post:filebrowser-delete-scope@canonical"]
    fb = cache / "filebrowser_filebrowser"
    scoped = git(fb, "show", "7c2c0a11b31b2bb214d741005a0b02b1764208b3:files/scoped.go").stdout
    assert "func (s *ScopedFs) RemoveAll(path string) error {\n\treturn s.base.RemoveAll(path)" in scoped
    remove_all = scoped.split("func (s *ScopedFs) RemoveAll")[1].split("func ")[0]
    assert "s.guard(" not in remove_all
    assert delete_scope["row_state"] == "REJECT"

    fission = ledger["strict-200-v3:alias-1416131f1ab575212ff869b2"]
    fi = v2 / fission["release_evidence"]["repo_cache"]
    assert git(fi, "cat-file", "-e", "v1.24.0:pkg/webhook/httptrigger.go", check=False).returncode == 0
    assert git(fi, "merge-base", "--is-ancestor", fission["candidate_fix_edges"][0]["carrier_sha"], "v1.24.0", check=False).returncode == 1
    assert fission["row_state"] == "REJECT"

    return {
        "state_changing_rows_replayed": 9,
        "reject_rows": 5,
        "narrow_rows": 0,
        "unknown_rows": 2,
        "pass_rows": 2,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also replay Git containment and first-party advisory status")
    parser.add_argument("--write-result", action="store_true")
    args = parser.parse_args()
    summary, additions, controls = verify_structural()
    live_counts = verify_live(additions) if args.live else None
    inherited_live = verify_inherited_live() if args.live else None
    batch_i_live = verify_batch_i_live() if args.live else None
    batch_ii_live = verify_batch_ii_live() if args.live else None
    result = {
        "status": "HOLD",
        "validation": "PASS",
        "integration_ready": False,
        "validated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "ledger_sha256": summary["ledger_sha256"],
        "structural_counts": summary["counts"],
        "live_counts": live_counts,
        "inherited_live": inherited_live,
        "batch_i_live": batch_i_live,
        "batch_ii_live": batch_ii_live,
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
        f", batch-I {batch_i_live['state_changing_rows_replayed']} targeted rows replayed"
        f", batch-II {batch_ii_live['state_changing_rows_replayed']} targeted rows replayed"
    )
    print(f"PASS: {summary['counts']['ledger_records']} records, source envelope 132/199/211, HOLD{live_suffix}")


if __name__ == "__main__":
    main()
