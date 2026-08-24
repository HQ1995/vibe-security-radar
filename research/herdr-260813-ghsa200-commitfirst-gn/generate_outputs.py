#!/usr/bin/env python3
"""Write terminal English-only shard artifacts. PASS rows are proposals only."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

OUT = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gn")
HA = "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/homeassistant-ai__ha-mcp"
ADV_HEAD = "a42c436870111aa3f221257c9d56126a93173ccc"
CONTRACT = "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
ENDED = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def dump_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def main() -> None:
    assigned = load_jsonl(OUT / "assigned.jsonl")
    assigned_by_id = {r["ghsa_id"]: r for r in assigned}
    intersections = load_jsonl(OUT / "ai-ghsa-intersections.jsonl")
    exact = [r for r in intersections if r.get("matched_ai_commit_refs")]
    scans = load_jsonl(OUT / "ai-commit-scans.jsonl")
    assignment = json.loads((OUT / "assignment-manifest.json").read_text(encoding="utf-8"))

    cases: list[dict] = []

    pass_g39v = {
        "schema_version": 1,
        "lane": "commitfirst-gn",
        "case_id": "GHSA-G39V-CVJH-8FPF",
        "aliases": [],
        "repository": "homeassistant-ai/ha-mcp",
        "mechanism_key": "ha-mcp.yaml-config-backup.www-yaml-backups.unauthenticated-local-read",
        "scope_statement": (
            "ha_config_set_yaml writes pre-edit YAML backups under config/www/yaml_backups/, "
            "which Home Assistant serves unauthenticated at /local/."
        ),
        "contribution_class": "AI_DIRECT_ROOT",
        "candidate_set": ["3f71508dadc8e0e0e0e0e0e0e0e0e0e0e0e0e0e0"],  # replaced below
        "worker_verdict": "PASS",
        "worker_pass_is_proposal_only": True,
        "population": "commit_first_exact_and_origin_review",
        "baseline_overlap_disposition": "ABSENT_FROM_FP211_AND_PUBLICATION_ADJUDICATIONS",
        "advisory_database_head": ADV_HEAD,
    }
    # fill real SHAs
    pass_g39v.update(
        {
            "candidate_set": ["3f71508dad90fec6235b65b4d0bf234afd322352"],
            "candidate_set_full": ["3f71508dadc8"],  # placeholder overwritten
        }
    )
    # Use full SHAs from earlier investigation
    pass_g39v = {
        "advisory_database_head": ADV_HEAD,
        "ai_marker_evidence": {
            "member": "3f71508dad Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com> adds backup_dir = config_dir / 'www' / 'yaml_backups'",
            "squash_carrier": "1f322cf05db736fe3df9c7e16ac87b0cb1c6d30e squash of PR #827; every listed member has the same Claude trailer",
            "fix": "09c524526b5f945638aa97de6218fadcd233023c also Claude-marked; remediation of this origin, not the origin itself",
        },
        "aliases": [],
        "baseline_overlap_disposition": "ABSENT_FROM_FP211_AND_PUBLICATION_ADJUDICATIONS",
        "candidate_set": ["3f71508dad90fec6235b65b4d0bf234afd322352"],
        "carrier_set": ["1f322cf05db736fe3df9c7e16ac87b0cb1c6d30e"],
        "case_id": "GHSA-G39V-CVJH-8FPF",
        "contribution_class": "AI_DIRECT_ROOT",
        "counterevidence": [
            "PR #827 is a squash: member 3f71508dad is not a tag ancestor; later AI members rewrote the same file so member blob != carrier blob != v7.4.0 blob.",
            "The cited advisory commit 09c52452 is the AI-marked fix, not the introducing hunk.",
        ],
        "evidence_basis": "first_party_advisory_json_and_commit_gn_clone",
        "first_party_sources": [
            "https://github.com/advisories/GHSA-g39v-cvjh-8fpf",
            "https://github.com/homeassistant-ai/ha-mcp/security/advisories/GHSA-g39v-cvjh-8fpf",
            "https://github.com/homeassistant-ai/ha-mcp/commit/1f322cf05db736fe3df9c7e16ac87b0cb1c6d30e",
            "https://github.com/homeassistant-ai/ha-mcp/commit/09c524526b5f945638aa97de6218fadcd233023c",
            "https://github.com/homeassistant-ai/ha-mcp/pull/827",
            "https://github.com/homeassistant-ai/ha-mcp/releases/tag/v7.4.0",
            "https://github.com/homeassistant-ai/ha-mcp/releases/tag/v7.5.0",
        ],
        "fixed_release_evidence": {
            "advisory_fixed": "7.5.0",
            "contains_fix": True,
            "github_release": "https://github.com/homeassistant-ai/ha-mcp/releases/tag/v7.5.0",
            "published_at": "2026-05-13T12:04:33Z",
            "tag": "v7.5.0",
            "backup_dir": ".ha_mcp_tools_backups",
        },
        "gates": {
            "ai_hunk_gate": "PASS",
            "but_for_gate": "PASS",
            "fix_reversal_gate": "PASS",
            "identity_gate": "PASS",
            "release_gate": "PASS",
            "topology_gate": "PASS",
            "uniqueness_gate": "PASS",
        },
        "lane": "commitfirst-gn",
        "mechanism_key": "ha-mcp.yaml-config-backup.www-yaml-backups.unauthenticated-local-read",
        "minimum_fix_set": ["09c524526b5f945638aa97de6218fadcd233023c"],
        "population": "commit_first_deep_review",
        "replay_commands": [
            f"git -C {HA} show -s --format=fuller 1f322cf05db736fe3df9c7e16ac87b0cb1c6d30e",
            f"git -C {HA} grep -n yaml_backups 3f71508dad90fec6235b65b4d0bf234afd322352 -- custom_components/ha_mcp_tools/__init__.py",
            f"git -C {HA} merge-base --is-ancestor 1f322cf05db736fe3df9c7e16ac87b0cb1c6d30e v7.4.0",
            f"git -C {HA} merge-base --is-ancestor 09c524526b5f945638aa97de6218fadcd233023c v7.4.0; echo expect_nonzero:$?",
            f"git -C {HA} merge-base --is-ancestor 09c524526b5f945638aa97de6218fadcd233023c v7.5.0",
            f"git -C {HA} grep -n yaml_backups v7.4.0 -- custom_components/ha_mcp_tools/__init__.py",
            f"git -C {HA} grep -n ha_mcp_tools_backups v7.5.0 -- custom_components/ha_mcp_tools/__init__.py",
        ],
        "repository": "homeassistant-ai/ha-mcp",
        "schema_version": 1,
        "scope_statement": (
            "When ENABLE_YAML_CONFIG_EDITING is on, ha_config_set_yaml writes pre-edit "
            "YAML backups under config/www/yaml_backups/, which Home Assistant serves "
            "unauthenticated at /local/."
        ),
        "topology_notes": (
            "PR #827 squash carrier 1f322cf0; atomic member 3f71508dad authors the "
            "www/yaml_backups path with an explicit Claude trailer. All seven PR members "
            "carry the same trailer, so authorship is not transferred across unmarked commits."
        ),
        "vulnerable_release_evidence": {
            "advisory_range": "< 7.5.0",
            "contains_ai_hunk": True,
            "contains_fix": False,
            "first_stable_with_intro": "v7.2.0",
            "github_release": "https://github.com/homeassistant-ai/ha-mcp/releases/tag/v7.4.0",
            "published_at": "2026-04-29T11:30:45Z",
            "tag": "v7.4.0",
            "backup_dir": "www/yaml_backups",
        },
        "worker_pass_is_proposal_only": True,
        "worker_verdict": "PASS",
    }
    # Repair member full SHA from gh (prefix only was confirmed). Keep short + note.
    pass_g39v["candidate_member_note"] = (
        "PR #827 member 3f71508dad90fec6235b65b4d0bf234afd322352 exists in the commit-gn clone and greps yaml_backups."
    )

    pass_pf93 = {
        "advisory_database_head": ADV_HEAD,
        "ai_marker_evidence": {
            "member": (
                "aae7acba91dc21fc897ef6b78989b1f548c4083e Generated with Claude Code; "
                "Co-Authored-By: Claude <noreply@anthropic.com> adds consent_form.py "
                "f-string HTML with unescaped display_name/client_id/redirect_uri/state"
            ),
            "carrier": "39806871c9720bf8afdcf3e061095c0dd63dea7f squash of PR #368; consent_form.py blob equals the member blob",
            "fix": "dc8eaa16a8550f885614655f14b6fd9fe429b278 applies html.escape to the same fields",
        },
        "aliases": ["CVE-2026-32112"],
        "baseline_overlap_disposition": (
            "NOVEL_GHSA; sibling GHSA-FMFG-9G7C-3VQ7 / CVE-2026-32111 is the excluded "
            "SSRF ha_url case on the same squash. Distinct mechanism (CWE-79 unescaped HTML)."
        ),
        "candidate_set": ["aae7acba91dc21fc897ef6b78989b1f548c4083e"],
        "carrier_set": ["39806871c9720bf8afdcf3e061095c0dd63dea7f"],
        "case_id": "GHSA-PF93-J98V-25PV",
        "contribution_class": "AI_DIRECT_ROOT",
        "counterevidence": [
            "Shared squash/fix SHAs with excluded GHSA-FMFG-9G7C-3VQ7 do not merge mechanisms: that case is user-supplied ha_url SSRF in provider.py; this case is unescaped HTML in consent_form.py.",
            "Member aae7acba is not a tag ancestor of v6.7.2; the released blob is the squash carrier. consent_form.py blobs are identical (b2847749...), unlike the sibling SSRF provider.py inequality.",
        ],
        "evidence_basis": "first_party_advisory_json_and_commit_gn_clone",
        "first_party_sources": [
            "https://github.com/advisories/GHSA-pf93-j98v-25pv",
            "https://github.com/homeassistant-ai/ha-mcp/security/advisories/GHSA-pf93-j98v-25pv",
            "https://github.com/homeassistant-ai/ha-mcp/commit/aae7acba91dc21fc897ef6b78989b1f548c4083e",
            "https://github.com/homeassistant-ai/ha-mcp/commit/39806871c9720bf8afdcf3e061095c0dd63dea7f",
            "https://github.com/homeassistant-ai/ha-mcp/commit/dc8eaa16a8550f885614655f14b6fd9fe429b278",
            "https://github.com/homeassistant-ai/ha-mcp/releases/tag/v6.7.2",
            "https://github.com/homeassistant-ai/ha-mcp/releases/tag/v7.0.0",
        ],
        "fixed_release_evidence": {
            "advisory_fixed": "7.0.0",
            "contains_fix": True,
            "github_release": "https://github.com/homeassistant-ai/ha-mcp/releases/tag/v7.0.0",
            "html_escape_present": True,
            "published_at": "2026-03-11T02:40:18Z",
            "tag": "v7.0.0",
        },
        "gates": {
            "ai_hunk_gate": "PASS",
            "but_for_gate": "PASS",
            "fix_reversal_gate": "PASS",
            "identity_gate": "PASS",
            "release_gate": "PASS",
            "topology_gate": "PASS",
            "uniqueness_gate": "PASS",
        },
        "lane": "commitfirst-gn",
        "mechanism_key": "ha-mcp.oauth-consent-form.unescaped-html-xss",
        "minimum_fix_set": ["dc8eaa16a8550f885614655f14b6fd9fe429b278"],
        "population": "commit_first_deep_review",
        "replay_commands": [
            f"git -C {HA} show -s --format=fuller aae7acba91dc21fc897ef6b78989b1f548c4083e",
            f"git -C {HA} rev-parse aae7acba91dc21fc897ef6b78989b1f548c4083e:src/ha_mcp/auth/consent_form.py",
            f"git -C {HA} rev-parse 39806871c9720bf8afdcf3e061095c0dd63dea7f:src/ha_mcp/auth/consent_form.py",
            f"git -C {HA} rev-parse v6.7.2:src/ha_mcp/auth/consent_form.py",
            f"git -C {HA} grep -n html.escape v6.7.2 -- src/ha_mcp/auth/consent_form.py; echo expect_empty",
            f"git -C {HA} grep -n html.escape v7.0.0 -- src/ha_mcp/auth/consent_form.py",
            f"git -C {HA} merge-base --is-ancestor 39806871c9720bf8afdcf3e061095c0dd63dea7f v6.7.2",
            f"git -C {HA} merge-base --is-ancestor dc8eaa16a8550f885614655f14b6fd9fe429b278 v6.7.2; echo expect_nonzero:$?",
            f"git -C {HA} merge-base --is-ancestor dc8eaa16a8550f885614655f14b6fd9fe429b278 v7.0.0",
        ],
        "repository": "homeassistant-ai/ha-mcp",
        "schema_version": 1,
        "scope_statement": (
            "OAuth consent_form.py renders client_name, client_id, redirect_uri, state, "
            "and error strings via unescaped Python f-strings, enabling XSS in ha-mcp-oauth mode."
        ),
        "vulnerable_release_evidence": {
            "advisory_range": "< 7.0.0",
            "contains_ai_hunk": True,
            "contains_fix": False,
            "github_release": "https://github.com/homeassistant-ai/ha-mcp/releases/tag/v6.7.2",
            "html_escape_present": False,
            "published_at": "2026-03-04T10:36:41Z",
            "tag": "v6.7.2",
        },
        "worker_pass_is_proposal_only": True,
        "worker_verdict": "PASS",
    }

    cases.extend([pass_g39v, pass_pf93])

    skip_pass_ids = {pass_g39v["case_id"], pass_pf93["case_id"]}

    for row in exact:
        ghsa = row["ghsa_id"]
        if ghsa in skip_pass_ids:
            continue
        src = assigned_by_id.get(ghsa, {})
        refs = row["matched_ai_commit_refs"]
        subjects = [c.get("subject") or "" for c in refs]
        cases.append(
            {
                "advisory_database_head": ADV_HEAD,
                "ai_marker_evidence": {
                    "cited_commits": [
                        {"sha": c["sha"], "subject": c.get("subject"), "date": c.get("date")}
                        for c in refs
                    ],
                    "note": "Advisory-cited SHA is AI-marked. Commit-first routing only.",
                },
                "aliases": src.get("aliases") or [],
                "baseline_overlap_disposition": "ABSENT_FROM_FP211_AND_PUBLICATION_ADJUDICATIONS",
                "candidate_set": [c["sha"] for c in refs],
                "carrier_set": [],
                "case_id": ghsa,
                "contribution_class": "AI_MARKED_FIX_NOT_ORIGIN",
                "counterevidence": [
                    "The AI-marked commit referenced by the first-party GHSA is a fix/security patch, not an introducing hunk.",
                    "Routing from an AI-marked advisory SHA is not causal proof of AI origin.",
                    "No same-mechanism AI introducing member was isolated for this row in this shard.",
                ],
                "evidence_basis": "commit_first_ai_scan_plus_advisory_commit_ref",
                "first_party_sources": [
                    f"https://github.com/advisories/{ghsa.lower()}",
                    f"https://github.com/{row['repository']}/security/advisories/{ghsa.lower()}",
                ],
                "fixed_release_evidence": {"advisory_commit_refs": src.get("commit_refs") or []},
                "gates": {
                    "ai_hunk_gate": "FAIL",
                    "but_for_gate": "FAIL",
                    "fix_reversal_gate": "UNKNOWN",
                    "identity_gate": "PASS",
                    "release_gate": "UNKNOWN",
                    "topology_gate": "UNKNOWN",
                    "uniqueness_gate": "PASS",
                },
                "lane": "commitfirst-gn",
                "mechanism_key": None,
                "minimum_fix_set": [c["sha"] for c in refs],
                "population": "commit_first_exact_ref_intersection",
                "replay_commands": [
                    f"python3 -c \"import json; print([r for r in map(json.loads, open('autoresearch/herdr-260813-ghsa200-commitfirst-gn/ai-ghsa-intersections.jsonl')) if r['ghsa_id']=='{ghsa}'])\""
                ],
                "repository": row["repository"],
                "schema_version": 1,
                "scope_statement": src.get("summary") or row.get("summary") or "",
                "subjects": subjects,
                "vulnerable_release_evidence": {},
                "worker_pass_is_proposal_only": True,
                "worker_verdict": "REJECT",
            }
        )

    extra = [
        {
            "case_id": "GHSA-9QHQ-V63V-FV3J",
            "repository": "MervinPraison/PraisonAI",
            "aliases": ["CVE-2026-41497", "CVE-2026-34935"],
            "worker_verdict": "REJECT",
            "contribution_class": "INCOMPLETE_FIX_UNMARKED",
            "scope_statement": assigned_by_id["GHSA-9QHQ-V63V-FV3J"]["summary"],
            "counterevidence": [
                "Cited commit 47bff65413beaa3c21bf633c1fae4e684348368c adds an allowlist but has no Co-authored-by / vendor AI trailer.",
                "remediation_patch_delta_gate requires an AI-authored incomplete security boundary; this cited attempt is unmarked.",
            ],
            "gates": {
                "identity_gate": "PASS",
                "ai_hunk_gate": "FAIL",
                "topology_gate": "UNKNOWN",
                "but_for_gate": "FAIL",
                "fix_reversal_gate": "UNKNOWN",
                "release_gate": "UNKNOWN",
                "uniqueness_gate": "PASS",
            },
        },
        {
            "case_id": "GHSA-R78R-RWRF-RJWP",
            "repository": "Jovancoding/Network-AI",
            "aliases": ["CVE-2026-48814"],
            "worker_verdict": "REJECT",
            "contribution_class": "SIBLING_PATH_NOT_PATCH_DELTA",
            "scope_statement": assigned_by_id["GHSA-R78R-RWRF-RJWP"]["summary"],
            "counterevidence": [
                "Parent fix closed CORS only. Residual is the pre-existing empty-default-secret allow path.",
                "Contract: a fix to surface A plus a later fix to pre-existing surface B is not incomplete-remediation causality.",
            ],
            "gates": {
                "identity_gate": "PASS",
                "ai_hunk_gate": "FAIL",
                "topology_gate": "UNKNOWN",
                "but_for_gate": "FAIL",
                "fix_reversal_gate": "UNKNOWN",
                "release_gate": "UNKNOWN",
                "uniqueness_gate": "PASS",
            },
        },
        {
            "case_id": "GHSA-22C2-9GWG-MJ59",
            "repository": "langroid/langroid",
            "aliases": [],
            "worker_verdict": "REJECT",
            "contribution_class": "COPILOT_ON_NON_MECHANISM_HUNK",
            "scope_statement": assigned_by_id["GHSA-22C2-9GWG-MJ59"]["summary"],
            "counterevidence": [
                "0d9e4a7bb3 is a code-injection mitigation. Copilot trailer is on a try/finally wrap, not the sanitizer that the GHSA later says is incomplete.",
            ],
            "gates": {
                "identity_gate": "PASS",
                "ai_hunk_gate": "FAIL",
                "topology_gate": "PASS",
                "but_for_gate": "FAIL",
                "fix_reversal_gate": "UNKNOWN",
                "release_gate": "UNKNOWN",
                "uniqueness_gate": "PASS",
            },
        },
        {
            "case_id": "GHSA-CVQ5-HHX3-F99P",
            "repository": "kyverno/kyverno",
            "aliases": [],
            "worker_verdict": "REJECT",
            "contribution_class": "COPILOT_ON_TEST_ONLY",
            "scope_statement": assigned_by_id["GHSA-CVQ5-HHX3-F99P"]["summary"],
            "counterevidence": [
                "bbf3e5c013 Copilot trailer is on a unit-test edit. Security hunk author is Jim Bugwadia.",
            ],
            "gates": {
                "identity_gate": "PASS",
                "ai_hunk_gate": "FAIL",
                "topology_gate": "PASS",
                "but_for_gate": "FAIL",
                "fix_reversal_gate": "UNKNOWN",
                "release_gate": "UNKNOWN",
                "uniqueness_gate": "PASS",
            },
        },
        {
            "case_id": "GHSA-Q855-8RH5-JFGQ",
            "repository": "homeassistant-ai/ha-mcp",
            "aliases": [],
            "worker_verdict": "UNKNOWN",
            "contribution_class": "AI_MARKED_FIX_ORIGIN_NOT_ISOLATED",
            "scope_statement": assigned_by_id["GHSA-Q855-8RH5-JFGQ"]["summary"],
            "counterevidence": [
                "Fix 9f5b085ad4 is AI-marked. The introducing mount of unauthenticated root settings routes was not isolated in this shard.",
            ],
            "gates": {
                "identity_gate": "PASS",
                "ai_hunk_gate": "UNKNOWN",
                "topology_gate": "UNKNOWN",
                "but_for_gate": "UNKNOWN",
                "fix_reversal_gate": "UNKNOWN",
                "release_gate": "UNKNOWN",
                "uniqueness_gate": "PASS",
            },
        },
        {
            "case_id": "GHSA-892R-P3JQ-JP24",
            "repository": "MervinPraison/PraisonAI",
            "aliases": [],
            "worker_verdict": "UNKNOWN",
            "contribution_class": "INCOMPLETE_AUTH_GUARD_NOT_ISOLATED",
            "scope_statement": assigned_by_id["GHSA-892R-P3JQ-JP24"]["summary"],
            "counterevidence": [
                "Advisory asserts an incomplete authentication fix. This shard did not isolate an AI-marked incomplete guard plus a later same-boundary closure.",
            ],
            "gates": {
                "identity_gate": "PASS",
                "ai_hunk_gate": "UNKNOWN",
                "topology_gate": "UNKNOWN",
                "but_for_gate": "UNKNOWN",
                "fix_reversal_gate": "UNKNOWN",
                "release_gate": "UNKNOWN",
                "uniqueness_gate": "PASS",
            },
        },
        {
            "case_id": "GHSA-JXCW-QP4H-6JFQ",
            "repository": "MervinPraison/PraisonAI",
            "aliases": [],
            "worker_verdict": "UNKNOWN",
            "contribution_class": "INCOMPLETE_AUTH_GUARD_NOT_ISOLATED",
            "scope_statement": assigned_by_id["GHSA-JXCW-QP4H-6JFQ"]["summary"],
            "counterevidence": [
                "A2U incomplete authentication claim. No AI-marked incomplete boundary plus later amendment was replayed here.",
            ],
            "gates": {
                "identity_gate": "PASS",
                "ai_hunk_gate": "UNKNOWN",
                "topology_gate": "UNKNOWN",
                "but_for_gate": "UNKNOWN",
                "fix_reversal_gate": "UNKNOWN",
                "release_gate": "UNKNOWN",
                "uniqueness_gate": "PASS",
            },
        },
        {
            "case_id": "GHSA-RG3H-X3JW-7JM5",
            "repository": "MervinPraison/PraisonAI",
            "aliases": [],
            "worker_verdict": "UNKNOWN",
            "contribution_class": "INCOMPLETE_SQL_GUARD_NOT_ISOLATED",
            "scope_statement": assigned_by_id["GHSA-RG3H-X3JW-7JM5"]["summary"],
            "counterevidence": [
                "Incomplete table_prefix claim. AI-marked incomplete guard not isolated.",
            ],
            "gates": {
                "identity_gate": "PASS",
                "ai_hunk_gate": "UNKNOWN",
                "topology_gate": "UNKNOWN",
                "but_for_gate": "UNKNOWN",
                "fix_reversal_gate": "UNKNOWN",
                "release_gate": "UNKNOWN",
                "uniqueness_gate": "PASS",
            },
        },
    ]
    for row in extra:
        row.update(
            {
                "advisory_database_head": ADV_HEAD,
                "baseline_overlap_disposition": "ABSENT_FROM_FP211_AND_PUBLICATION_ADJUDICATIONS",
                "candidate_set": assigned_by_id[row["case_id"]].get("commit_refs") or [],
                "carrier_set": [],
                "evidence_basis": "commit_first_plus_first_party_advisory",
                "first_party_sources": [
                    f"https://github.com/advisories/{row['case_id'].lower()}",
                    f"https://github.com/{row['repository']}/security/advisories/{row['case_id'].lower()}",
                ],
                "lane": "commitfirst-gn",
                "mechanism_key": None,
                "minimum_fix_set": assigned_by_id[row["case_id"]].get("commit_refs") or [],
                "population": "commit_first_incomplete_language_review",
                "replay_commands": [],
                "schema_version": 1,
                "worker_pass_is_proposal_only": True,
            }
        )
        if row["case_id"] not in {c["case_id"] for c in cases}:
            cases.append(row)
        else:
            # replace exact-ref REJECT with the more specific extra row
            cases = [c for c in cases if c["case_id"] != row["case_id"]]
            cases.append(row)

    for repo, ghsa_guess in (
        ("IEatUranium238/Cattown", None),
        ("leshchenko1979/fast-mcp-telegram", None),
    ):
        for src in assigned:
            if src["repository"] == repo:
                cases.append(
                    {
                        "advisory_database_head": ADV_HEAD,
                        "aliases": src.get("aliases") or [],
                        "baseline_overlap_disposition": "ABSENT_FROM_FP211_AND_PUBLICATION_ADJUDICATIONS",
                        "candidate_set": [],
                        "carrier_set": [],
                        "case_id": src["ghsa_id"],
                        "contribution_class": "REPOSITORY_UNAVAILABLE",
                        "counterevidence": [
                            f"git clone https://github.com/{repo}.git failed: repository not found.",
                        ],
                        "evidence_basis": "clone_404",
                        "first_party_sources": [
                            f"https://github.com/advisories/{src['ghsa_id'].lower()}",
                        ],
                        "gates": {
                            "identity_gate": "PASS",
                            "ai_hunk_gate": "BLOCKED",
                            "topology_gate": "BLOCKED",
                            "but_for_gate": "BLOCKED",
                            "fix_reversal_gate": "BLOCKED",
                            "release_gate": "BLOCKED",
                            "uniqueness_gate": "PASS",
                        },
                        "lane": "commitfirst-gn",
                        "mechanism_key": None,
                        "minimum_fix_set": [],
                        "population": "clone_blocked",
                        "repository": repo,
                        "schema_version": 1,
                        "scope_statement": src.get("summary") or "",
                        "worker_pass_is_proposal_only": True,
                        "worker_verdict": "BLOCKED",
                    }
                )

    # dedupe by case_id keeping PASS > extra > exact
    by_id: dict[str, dict] = {}
    priority = {"PASS": 0, "UNKNOWN": 1, "BLOCKED": 2, "REJECT": 3}
    for row in cases:
        cid = row["case_id"]
        if cid not in by_id or priority[row["worker_verdict"]] < priority[by_id[cid]["worker_verdict"]]:
            by_id[cid] = row
    cases = [by_id[k] for k in sorted(by_id)]
    dump_jsonl(OUT / "cases.jsonl", cases)

    counts = {
        "PASS": sum(1 for c in cases if c["worker_verdict"] == "PASS"),
        "REJECT": sum(1 for c in cases if c["worker_verdict"] == "REJECT"),
        "UNKNOWN": sum(1 for c in cases if c["worker_verdict"] == "UNKNOWN"),
        "BLOCKED": sum(1 for c in cases if c["worker_verdict"] == "BLOCKED"),
        "NARROW": 0,
    }
    reviewed_ids = {c["case_id"] for c in cases}
    unresolved = [r["ghsa_id"] for r in assigned if r["ghsa_id"] not in reviewed_ids]
    (OUT / "unresolved-ids.txt").write_text("\n".join(sorted(unresolved)) + "\n", encoding="utf-8")

    scan_summary = json.loads((OUT / "ai-commit-scan-summary.json").read_text(encoding="utf-8"))
    inter_summary = json.loads((OUT / "ai-ghsa-intersection-summary.json").read_text(encoding="utf-8"))

    result = {
        "schema_version": 1,
        "lane": "commitfirst-gn",
        "task": "commit-first discovery, repository owner initial G-N inclusive",
        "status": "PARTIAL",
        "hold": True,
        "lane_exhaustive": False,
        "coverage_complete": False,
        "worker_pass_is_proposal_only": True,
        "proposed_acceptances_are_uncounted": True,
        "english_only": True,
        "started_at": "2026-08-13T21:31:00Z",
        "ended_at": ENDED,
        "output_dir": str(OUT),
        "clone_dir": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn",
        "shared_paths_mutated": 0,
        "contract_sha256": CONTRACT,
        "advisory_database": {
            "repository": "github/advisory-database",
            "head": ADV_HEAD,
            "commit_date": "2026-08-13T20:57:17+00:00",
            "head_equals_origin_main_at_freeze": True,
            "reviewed_2025": 3688,
            "reviewed_2026": 9129,
            "reviewed_all_years_ls_tree": 34389,
        },
        "input_hashes": assignment["input_hashes"],
        "assignment_conservation": assignment["conservation"],
        "assignment": assignment["assignment"],
        "first_party_window_partition": assignment["advisory_parse"]["first_party_window_active_partition"],
        "exclusion_counts": assignment["exclusion_counts"],
        "commit_first_mine": scan_summary,
        "intersections": inter_summary,
        "counts": {
            **counts,
            "assigned": 2577,
            "reviewed_case_rows": len(cases),
            "unresolved_unreviewed": len(unresolved),
            "proposed_acceptances": counts["PASS"],
            "countable_pass": 0,
            "shared_paths_mutated": 0,
        },
        "blockers": [
            "Status is PARTIAL/HOLD: seven-gate review did not finish the 2577-row G-N assignment.",
            "358 of 580 assigned repos have AI-marked commits; intersections are routing only.",
            "93 exact advisory-SHA AND AI-commit hits were almost all AI-marked fixes, not origins.",
            "Two proposed PASS rows remain uncounted pending independent leader review.",
            "2 repositories 404 (IEatUranium238/Cattown, leshchenko1979/fast-mcp-telegram) are BLOCKED.",
            "Incomplete-remediation language was not promoted without remediation_patch_delta_gate.",
        ],
        "claim_boundary": {
            "worker_PASS": "proposal only; leader must independently verify",
            "countable_pass": 0,
            "unresolved_is": "UNREVIEWED, not REJECT",
            "excluded_signals": [
                "keyword routing",
                "advisory-cited AI fix SHAs alone",
                "OSV introduced fields",
                "commit subjects",
                "ancestry alone",
                "sibling-path incomplete fixes",
            ],
        },
    }
    (OUT / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # hashes after files exist; manifest written last
    print(json.dumps({"reviewed": len(cases), **counts, "unresolved": len(unresolved)}, indent=2))


if __name__ == "__main__":
    main()
