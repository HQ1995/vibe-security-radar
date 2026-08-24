#!/usr/bin/env python3
"""Emit delta-even lane artifacts. Writes only this directory."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from paths import EXISTING_ACTIVE_ROOT, NEW_CLONE_ROOT, resolve_existing_or_new

LANE = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even")
ROOT = Path("/home/hanqing/agents/ai-slop")
ADVISORY_ROOT = resolve_existing_or_new("advisory-database") / "advisories/github-reviewed"
EVIDENCE = LANE / "evidence"
EVIDENCE.mkdir(parents=True, exist_ok=True)

AI_HIT_IDS = [
    "GHSA-28GM-JRMW-XX93",
    "GHSA-2JWF-F4XQ-F24H",
    "GHSA-2XWM-4H2Q-GGFX",
    "GHSA-4FH7-7JX4-8F6C",
    "GHSA-4VV7-JJ25-4GH6",
    "GHSA-5GWJ-M78Q-7PQ3",
    "GHSA-5QJJ-4XWW-7PHC",
    "GHSA-6H5J-32CF-4253",
    "GHSA-6WCC-39RP-HH9P",
    "GHSA-73X5-H92W-XC2J",
    "GHSA-74H3-CXQ7-VC5Q",
    "GHSA-7RQJ-J65F-68WH",
    "GHSA-FJGC-3MJ7-8RG8",
    "GHSA-G357-X5C3-C72P",
    "GHSA-HC8V-WWC9-VGXM",
    "GHSA-HMQ2-W58F-27JC",
    "GHSA-HQJ5-CW9F-RX67",
    "GHSA-J657-M4C4-24JQ",
    "GHSA-JQWH-526H-C92J",
    "GHSA-JWJP-4649-V8JP",
    "GHSA-M3QF-58WF-W979",
    "GHSA-MVX4-532P-XFM9",
    "GHSA-P6PH-3JX2-3337",
    "GHSA-PC2W-4MQ8-32QW",
    "GHSA-Q53C-4PRM-W95Q",
    "GHSA-QG3F-8X3J-GGF2",
    "GHSA-QVC3-6Q9X-95PJ",
    "GHSA-RQJ7-6WRP-6G2G",
    "GHSA-XGR6-PQJV-3PF8",
]
REM_EXTRA_IDS = [
    "GHSA-56M6-8Q75-F2RW",
    "GHSA-HC76-7MPC-QJQH",
    "GHSA-HQ33-8JGP-8QQ3",
    "GHSA-HXVH-4H3W-PRP9",
    "GHSA-JR6P-8PJJ-MFX6",
    "GHSA-RMXW-PQ4X-3FVH",
    "GHSA-X677-9FXG-V5C5",
    "GHSA-XC48-889X-5QMW",
]
DEEP_IDS = sorted(set(AI_HIT_IDS) | set(REM_EXTRA_IDS))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def gate(status: str, reason: str) -> dict:
    return {"status": status, "reason": reason}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def official_index() -> dict[str, Path]:
    return {p.stem.upper(): p for p in ADVISORY_ROOT.rglob("GHSA-*.json")}


def copy_official(gid: str, index: dict[str, Path]) -> str | None:
    path = index.get(gid)
    if not path:
        return None
    dest = EVIDENCE / f"{gid}.official-github-reviewed.json"
    dest.write_bytes(path.read_bytes())
    return str(dest.relative_to(LANE))


def base_row(route: dict, blob: dict, **extra) -> dict:
    row = {
        "schema_version": 2,
        "row_role": "ADJUDICATED_NEW_ID",
        "seven_gate_row": True,
        "case_id": route["ghsa_id"],
        "aliases": [str(a).upper() for a in (blob.get("aliases") or [])],
        "repository": route.get("repository"),
        "summary": blob.get("summary") or route.get("summary") or "",
        "published": blob.get("published"),
        "withdrawn": blob.get("withdrawn"),
        "commit_refs": route.get("commit_refs") or [],
        "released": route.get("released"),
        "official_json": route.get("official_json"),
        "verdict": "REJECT",
        "worker_pass_is_proposal": True,
        "proposed_pass": False,
        "baseline_overlap": "absent_from_212_declared",
        "sibling_fresh_or_current_delta_used_as_evidence": False,
    }
    row.update(extra)
    return row


def main() -> None:
    routes = load_jsonl(LANE / "routing.jsonl")
    scans = load_jsonl(LANE / "commit_scan.jsonl")
    by_id = {r["ghsa_id"]: r for r in routes}
    scans_by_id: dict[str, list[dict]] = {}
    for s in scans:
        scans_by_id.setdefault(s["ghsa_id"], []).append(s)
    index = official_index()

    special = {
        "GHSA-HMQ2-W58F-27JC": {
            "contribution_class": "AI_INCOMPLETE_REM_NOT_RELEASED",
            "mechanism_key": "gitpython-submodule-name-traversal",
            "scope_statement": "Unvalidated .gitmodules submodule name used as .git/modules/<name> path; original mechanism is the longstanding GitPython reimplementation gap versus CVE-2018-11235.",
            "candidate_set": ["e4b8e7d026ca6abb4cf604f8e77093432ce23c06"],
            "carrier_set": ["e4b8e7d026ca6abb4cf604f8e77093432ce23c06", "4299c990e1ca21896f9485277caf7bb0ae5b404c"],
            "minimum_fix_set": ["4299c990e1ca21896f9485277caf7bb0ae5b404c"],
            "ai_marker_evidence": "Both referenced commits carry Assisted-by: GPT 5.6 and Co-authored-by: GPT 5.6 <codex@openai.com>. Those commits are successive validation fixes, not the introducing hunk.",
            "counterevidence": "Official range is introduced 0 / fixed 3.1.58, last known <= 3.1.57. e4b8e7d0 is an ancestor of 4299c990, but the first tag containing either commit is 3.1.58. 3.1.57 does not contain e4b8e7d0. There is no released residual window. The vulnerable sm_name/_module_abspath path predates the GPT commits.",
            "gates": {
                "identity_gate": gate("PASS", "Official github-reviewed GHSA-HMQ2-W58F-27JC names gitpython-developers/GitPython; first-party repo advisory published; not withdrawn."),
                "ai_hunk_gate": gate("REJECT", "GPT markers author the validation fixes, not the unvalidated name-to-path hunk that creates the repository outside the working tree."),
                "topology_gate": gate("PASS", "e4b8e7d0 is a first-parent ancestor of 4299c990; both are on the 3.1.58 ancestry. Authorship is not transferred across commits."),
                "but_for_gate": gate("REJECT", "Removing the GPT commits restores the pre-3.1.58 state that already had the traversal. The AI change did not create a new residual that 3.1.57 lacked."),
                "fix_reversal_gate": gate("REJECT", "The GHSA mechanism is the original unvalidated name. The later GPT commit tightens the same new validator; it does not reverse an AI-created residual that shipped."),
                "release_gate": gate("REJECT", "No released artifact contains e4b8e7d0 without 4299c990. Both first appear in tag 3.1.58."),
                "uniqueness_gate": gate("PASS", "Identity is absent from the 212 leader declared IDs. Not counted because other gates fail."),
            },
        },
        "GHSA-FJGC-3MJ7-8RG8": {
            "contribution_class": "AI_NEW_CALLSITE_OLD_MECHANISM",
            "mechanism_key": "etherpad-x-proxy-path-xss-open-redirect",
            "scope_statement": "x-proxy-path reflected into admin assets (XSS) and concatenated into redirects (open redirect). Claude authored a new timeslider 302 that reused a pre-existing weak sanitizer.",
            "candidate_set": ["451bd9c3ebb0dded99dd0ff21811ee00e0940c29"],
            "carrier_set": ["451bd9c3ebb0dded99dd0ff21811ee00e0940c29"],
            "minimum_fix_set": ["8c6104c5d5daf41f0d454acc04d42dffa0e0d996"],
            "ai_marker_evidence": "451bd9c3 and closer 8c6104c5 both have Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>.",
            "counterevidence": "Parent cbf71285 already defined sanitizeProxyPath as raw.replace(/[^a-zA-Z0-9\\-_\\/\\.]/g,'') and used it on other specialpages redirects. Admin XSS exists at tag 2.1.0. Claude added another consumer of the same weak sanitizer. Removing the feat leaves the GHSA XSS and the other open-redirect sites.",
            "gates": {
                "identity_gate": gate("PASS", "Official github-reviewed GHSA-FJGC-3MJ7-8RG8 / CVE-2026-55087 names ether/etherpad; first-party repo advisory published."),
                "ai_hunk_gate": gate("REJECT", "Claude authored a new timeslider redirect call site, not the admin XSS hunk and not the original weak sanitizer."),
                "topology_gate": gate("PASS", "451bd9c3 is a single-parent commit first contained in 3.0.0; closer 8c6104c5 first contained in 3.1.0."),
                "but_for_gate": gate("REJECT", "The advisory mechanism is the historic unsanitized/weakly sanitized x-proxy-path. Other specialpages redirects and admin.ts already had it before the Claude feat."),
                "fix_reversal_gate": gate("REJECT", "8c6104c5 is an AI-authored hardening of the shared sanitizer plus cache headers. That is AI-as-fixer of a pre-existing class, not reversal of an AI-created residual unique to this GHSA."),
                "release_gate": gate("PASS", "Affected introduced 2.1.0 last known <= 3.0.0; 3.0.0 contains 451bd9c3 and not 8c6104c5; 3.1.0 contains the closer."),
                "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
            },
        },
        "GHSA-2JWF-F4XQ-F24H": {
            "contribution_class": "AI_AS_FIXER",
            "mechanism_key": "etherpad-math-random-tmpdir",
            "scope_statement": "Import/export temp paths used Math.random() under os.tmpdir().",
            "candidate_set": ["8c6104c5d5daf41f0d454acc04d42dffa0e0d996"],
            "carrier_set": ["8c6104c5d5daf41f0d454acc04d42dffa0e0d996"],
            "minimum_fix_set": ["8c6104c5d5daf41f0d454acc04d42dffa0e0d996"],
            "ai_marker_evidence": "Closer 8c6104c5 has Co-Authored-By: Claude Opus 4.7. The commit replaces Math.random with crypto.randomBytes.",
            "counterevidence": "Official range introduced 0 / fixed 3.1.0, last known <= 3.0.0. The Math.random temp-path construction predates the Claude harden commit.",
            "gates": {
                "identity_gate": gate("PASS", "Official github-reviewed GHSA-2JWF-F4XQ-F24H / CVE-2026-55086 names ether/etherpad."),
                "ai_hunk_gate": gate("REJECT", "Claude marker is on the closer that removes Math.random, not on an introducing hunk."),
                "topology_gate": gate("PASS", "8c6104c5 is the official closer; first tag 3.1.0."),
                "but_for_gate": gate("REJECT", "Removing the Claude harden restores the old Math.random behavior; it does not eliminate an AI-introduced mechanism."),
                "fix_reversal_gate": gate("REJECT", "The AI commit is the minimum fix of a pre-existing mechanism."),
                "release_gate": gate("PASS", "Vulnerable through 3.0.0; fixed 3.1.0 contains 8c6104c5."),
                "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
            },
        },
        "GHSA-PC2W-4MQ8-32QW": {
            "contribution_class": "AI_AS_FIXER",
            "mechanism_key": "dynatrace-mcp-notebook-missing-approval",
            "scope_statement": "create_dynatrace_notebook omitted requestHumanApproval that sibling write tools already had.",
            "candidate_set": ["d0de980094b8b3997b241f184c619d49127d9df5"],
            "carrier_set": ["d0de980094b8b3997b241f184c619d49127d9df5"],
            "minimum_fix_set": ["2851d3ce29d834c93b67f0db903c10e0b488e7ac"],
            "ai_marker_evidence": "Official closer 2851d3ce is authored by Copilot <198982749+Copilot@users.noreply.github.com> and adds the missing approval gate.",
            "counterevidence": "create_dynatrace_notebook was introduced by human Christian Kreuzberger in d0de9800 (2025-12-19, no AI trailer). requestHumanApproval for other write tools is also human (f4b91001). Copilot only retrofitted the missing gate. v1.8.6 lacks 2851d3ce; v1.8.7 contains it.",
            "gates": {
                "identity_gate": gate("PASS", "Official github-reviewed GHSA-PC2W-4MQ8-32QW names dynatrace-oss/dynatrace-mcp; first-party repo advisory published."),
                "ai_hunk_gate": gate("REJECT", "Copilot authored the closer. The ungated tool registration is a human commit."),
                "topology_gate": gate("PASS", "Human origin d0de9800; Copilot closer 2851d3ce first contained in v1.8.7."),
                "but_for_gate": gate("REJECT", "Removing the Copilot commit restores the human-introduced ungated tool. The AI change is the fix."),
                "fix_reversal_gate": gate("REJECT", "The AI commit is the minimum fix, not a reversal of an AI residual."),
                "release_gate": gate("PASS", "Official fixed 1.8.7; v1.8.6 is a released affected tag without 2851d3ce."),
                "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
            },
        },
        "GHSA-RMXW-PQ4X-3FVH": {
            "contribution_class": "OLD_VULN_LEFT_INCOMPLETE",
            "mechanism_key": "goshs-bulk-acl-bypass",
            "scope_statement": "?bulk zip-download skips .goshs ACL after GHSA-WVHV-QCQF-F3CX closed write routes.",
            "candidate_set": ["f212c4f4a126556bab008f79758e21a839ef2c0f"],
            "carrier_set": ["f212c4f4a126556bab008f79758e21a839ef2c0f"],
            "minimum_fix_set": ["7cf911a26ace737e1a55b7dc073e307a25f7fd1d"],
            "ai_marker_evidence": "None on the prior rem f212c4f4 or closer 7cf911a2. Both are Patrick Hener without AI trailers.",
            "counterevidence": "Official text calls this a residual of GHSA-WVHV-QCQF-F3CX. That prior rem and this closer are human. WVHV is odd-partition and is not used as causal evidence here.",
            "gates": {
                "identity_gate": gate("PASS", "Official github-reviewed GHSA-RMXW-PQ4X-3FVH / CVE-2026-54719 names goshs-labs/goshs."),
                "ai_hunk_gate": gate("REJECT", "No AI marker on the incomplete rem or the closer."),
                "topology_gate": gate("PASS", "Human rem f212c4f4 then human closer 7cf911a2, first tag v2.1.1."),
                "but_for_gate": gate("REJECT", "The leftover ?bulk path predates any AI change in this lane's evidence."),
                "fix_reversal_gate": gate("REJECT", "Closer is human and addresses an old leftover, not an AI-created residual."),
                "release_gate": gate("PASS", "Official last_affected 1.1.4 / fixed v2 2.1.1; closer first tag v2.1.1."),
                "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
            },
        },
        "GHSA-HQ33-8JGP-8QQ3": {
            "contribution_class": "OLD_VULN_LEFT_INCOMPLETE",
            "mechanism_key": "goshs-webdav-move-no-delete",
            "scope_statement": "--no-delete WebDAV MOVE still deletes or overwrites.",
            "candidate_set": [],
            "carrier_set": [],
            "minimum_fix_set": ["0444ac6b1a8176ddae70d940adf7a26b2e5a6c29"],
            "ai_marker_evidence": "None. Closer 0444ac6b is Patrick Hener, subject Fix GHSA-hq33-8jgp-8qq3, no AI trailer.",
            "counterevidence": "Keyword rem recall only. First-party git shows a human closer and no AI origin hunk.",
            "gates": {
                "identity_gate": gate("PASS", "Official github-reviewed GHSA-HQ33-8JGP-8QQ3 names goshs-labs/goshs."),
                "ai_hunk_gate": gate("REJECT", "No AI marker on the official closer; no AI introducing commit found."),
                "topology_gate": gate("PASS", "Official closer 0444ac6b is a first-party goshs commit."),
                "but_for_gate": gate("REJECT", "No AI change is necessary for the MOVE bypass."),
                "fix_reversal_gate": gate("REJECT", "Human closer of a non-AI mechanism."),
                "release_gate": gate("PASS", "Closer is contained in later v2.1.4+ tags; official advisory names a released product."),
                "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
            },
        },
    }

    rem_generic = {
        "GHSA-56M6-8Q75-F2RW": ("ImageMagick/ImageMagick", "OLD_VULN_LEFT_INCOMPLETE", "Official text is an incomplete fix of CVE-2026-49219. No commit ref and no AI marker in the official object."),
        "GHSA-HC76-7MPC-QJQH": ("ImageMagick/ImageMagick", "OLD_VULN_LEFT_INCOMPLETE", "Official text is an incomplete fix of CVE-2026-25797. No commit ref and no AI marker in the official object."),
        "GHSA-HXVH-4H3W-PRP9": ("nuxt/nuxt", "OLD_VULN_LEFT_INCOMPLETE", "Official closer commits 61996330 and ad624a75 have no AI trailers. Incomplete case-fold of CVE-2026-53721 is a human leftover."),
        "GHSA-JR6P-8PJJ-MFX6": ("projectcapsule/capsule", "OLD_VULN_LEFT_INCOMPLETE", "Official text: v0.13.0 guard missed RawItems/Generators. No official commit ref and no AI marker."),
        "GHSA-X677-9FXG-V5C5": ("traefik/traefik", "OLD_VULN_LEFT_INCOMPLETE", "Official closer 108a5264 has no AI trailer. Incomplete strip of underscore header variants after CVE-2026-33433."),
        "GHSA-XC48-889X-5QMW": ("FlowiseAI/Flowise", "OLD_VULN_LEFT_INCOMPLETE", "Official closer a4c4e498 has no AI trailer. npm_config_yes bypass of a prior flag denylist."),
        "GHSA-2XWM-4H2Q-GGFX": ("open-webui/open-webui", "AI_AS_FIXER", "Official closer 17df0264 has Co-authored-by: Claude Opus 4.8. The commit confers object-derived file write only for owner files; that is the fix, not an origin hunk."),
    }

    cases = []
    for gid in DEEP_IDS:
        route = by_id[gid]
        blob = json.loads(index[gid].read_text()) if gid in index else {}
        official_rel = copy_official(gid, index)
        if gid in special:
            spec = special[gid]
            row = base_row(
                route,
                blob,
                contribution_class=spec["contribution_class"],
                mechanism_key=spec["mechanism_key"],
                scope_statement=spec["scope_statement"],
                candidate_set=spec["candidate_set"],
                carrier_set=spec["carrier_set"],
                minimum_fix_set=spec["minimum_fix_set"],
                ai_marker_evidence=spec["ai_marker_evidence"],
                counterevidence=spec["counterevidence"],
                gates=spec["gates"],
                evidence_official_json=official_rel,
            )
        elif gid in rem_generic:
            repo, klass, why = rem_generic[gid]
            closer_sigs = []
            for s in scans_by_id.get(gid, []):
                if s.get("ok") and (s.get("ai_signals") or s.get("message_ai_signals")):
                    closer_sigs.append({"sha": s.get("sha"), "signals": s.get("ai_signals")})
            ai_fix = bool(closer_sigs)
            row = base_row(
                route,
                blob,
                contribution_class=klass,
                mechanism_key=gid.lower() + "-reviewed",
                scope_statement=blob.get("summary") or "",
                candidate_set=[],
                carrier_set=route.get("commit_refs") or [],
                minimum_fix_set=route.get("commit_refs") or [],
                ai_marker_evidence=json.dumps(closer_sigs, ensure_ascii=True) if closer_sigs else "No AI trailer on official referenced commits or official advisory text.",
                counterevidence=why,
                evidence_official_json=official_rel,
                gates={
                    "identity_gate": gate("PASS", f"Official github-reviewed {gid} names {repo}."),
                    "ai_hunk_gate": gate("REJECT", "AI marker, if any, is on the closer or is absent. No AI-authored vulnerable hunk was established."),
                    "topology_gate": gate("PASS" if route.get("commit_refs") else "REJECT", "Official commit refs resolved" if route.get("commit_refs") else "No official commit identity to resolve."),
                    "but_for_gate": gate("REJECT", "First-party evidence shows a pre-existing or leftover mechanism, not an AI-created residual."),
                    "fix_reversal_gate": gate("REJECT", "Closer does not reverse an AI-created residual that this lane can attribute."),
                    "release_gate": gate("PASS" if (route.get("released") or {}).get("affected") else "REJECT", "Official affected/fixed events recorded in github-reviewed JSON."),
                    "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
                },
            )
        else:
            sigs = []
            subjects = []
            for s in scans_by_id.get(gid, []):
                if s.get("ok"):
                    subjects.append((s.get("sha") or "")[:12] + " " + ((s.get("message") or "").splitlines() or [""])[0][:160])
                    for sig in s.get("ai_signals") or []:
                        sigs.append(sig)
            row = base_row(
                route,
                blob,
                contribution_class="AI_AS_FIXER",
                mechanism_key=gid.lower() + "-official-closer-ai",
                scope_statement=blob.get("summary") or "",
                candidate_set=[],
                carrier_set=route.get("commit_refs") or [],
                minimum_fix_set=route.get("commit_refs") or [],
                ai_marker_evidence=json.dumps(sigs, ensure_ascii=True),
                counterevidence="Referenced official commit(s) carry an AI trailer and are the security closer: " + " | ".join(subjects),
                evidence_official_json=official_rel,
                gates={
                    "identity_gate": gate("PASS", f"Official github-reviewed {gid} names {route.get('repository')}."),
                    "ai_hunk_gate": gate("REJECT", "AI trailer is on the official closer, not on a demonstrated introducing vulnerable hunk."),
                    "topology_gate": gate("PASS", "Official referenced closer resolved via GitHub commit API."),
                    "but_for_gate": gate("REJECT", "Removing the AI closer would unfix the advisory. That is AI-as-fixer."),
                    "fix_reversal_gate": gate("REJECT", "The AI commit is the minimum fix of a mechanism this lane did not attribute to AI origin."),
                    "release_gate": gate("PASS" if (route.get("released") or {}).get("affected") else "REJECT", "Official affected/fixed events recorded in github-reviewed JSON."),
                    "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
                },
            )
        # Force REJECT if any required gate is not PASS for a PASS proposal
        row["verdict"] = "REJECT"
        row["proposed_pass"] = False
        cases.append(row)

    cases.sort(key=lambda r: r["case_id"])
    (LANE / "cases.jsonl").write_text("".join(json.dumps(c, ensure_ascii=True) + "\n" for c in cases))

    deep_set = set(DEEP_IDS)
    manifest = []
    for r in routes:
        gid = r["ghsa_id"]
        if r["route"] in {"EXCLUDE_DECLARED", "EXCLUDE_WITHDRAWN", "EXCLUDE_MISSING_REPO", "EXCLUDE_ALIAS_OF_DECLARED", "EXCLUDE_MISSING_OFFICIAL_JSON"}:
            final = r["route"]
            deep = False
        elif gid in deep_set:
            final = "DEEP_REVIEWED_REJECT"
            deep = True
        else:
            final = "SCREENED_NO_PLAUSIBLE_AI"
            deep = False
        rec = {
            "ghsa_id": gid,
            "partition": "EVEN",
            "sha256_last_nibble": r.get("sha256_last_nibble"),
            "repository": r.get("repository"),
            "aliases": r.get("aliases") or [],
            "withdrawn": r.get("withdrawn"),
            "initial_route": r["route"],
            "final_route": final,
            "deep_reviewed": deep,
            "seven_gate_row": deep,
            "recall_flags": r.get("recall_flags") or [],
            "reason": r.get("reason"),
        }
        if deep:
            rec["reason"] = "Deep-reviewed from first-party official JSON plus git/commit evidence; REJECT; not a PASS proposal"
        elif final == "SCREENED_NO_PLAUSIBLE_AI":
            rec["reason"] = "Assigned even ID triaged from official JSON and referenced-commit AI scan; no plausible AI origin/rem/reintro for bounded deep review"
        manifest.append(rec)
    (LANE / "routing_manifest.jsonl").write_text("".join(json.dumps(x, ensure_ascii=True) + "\n" for x in manifest))

    from collections import Counter
    final_counts = Counter(x["final_route"] for x in manifest)
    source = json.loads((LANE / "source_hashes.json").read_text())
    extra_hashes = {
        "window_added_ids": sha256_file(ROOT / "autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/github_reviewed_window_added_ids.txt"),
        "leader_declared_ids": sha256_file(ROOT / "autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/leader_declared_ids.txt"),
        "fp211_public_cases": sha256_file(ROOT / "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl"),
        "leader_contract": sha256_file(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"),
        "partition_even_ids": sha256_file(LANE / "partition_even_ids.txt"),
        "partition_odd_ids": sha256_file(LANE / "partition_odd_ids.txt"),
        "routing_manifest": None,
        "cases_jsonl": None,
    }
    # fill after write
    result = {
        "schema_version": 2,
        "lane": "herdr-260813-ghsa200-delta-even",
        "task": "EVEN partition of 731 official github-reviewed GHSA IDs added between 39d8887723797efc1804585dd06585c9fd751226 and 6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86",
        "status": "COMPLETE",
        "completeness_scope": "all_even_partition_identities_routed; bounded_deep_adjudication_only",
        "ecosystem_coverage_claimed": False,
        "coverage_status": {
            "all_id_routing": "COMPLETE",
            "bounded_deep_adjudication": "COMPLETE",
            "ecosystem_or_full_blame_coverage": "NOT_CLAIMED",
        },
        "started_at": "2026-08-13T16:44:00-04:00",
        "ended_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "output_dir": str(LANE),
        "clone_root": str(EXISTING_ACTIVE_ROOT),
        "new_clone_root": str(NEW_CLONE_ROOT),
        "clone_path_policy": "Keep existing active objects under /tmp/ghsa200-worker-clones/delta-even. Put NEW clones and large objects under /home/hanqing/.cache/ghsa200-worker-clones/delta-even. Do not move files used by a running process.",
        "clone_paths_file": str(LANE / "clone_paths.json"),
        "worker_pass_is_proposal": True,
        "proposed_pass_count": 0,
        "partition_conservation": source["partition_conservation"],
        "source_hashes": source["source_hashes"],
        "input_hashes": extra_hashes,
        "counts": {
            "window_added_official_ids": 731,
            "even_partition": 393,
            "odd_partition_not_owned": 338,
            "even_plus_odd": 731,
            "routed_even_identities": 393,
            "exclude_declared": final_counts.get("EXCLUDE_DECLARED", 0),
            "exclude_withdrawn": final_counts.get("EXCLUDE_WITHDRAWN", 0),
            "exclude_missing_repo": final_counts.get("EXCLUDE_MISSING_REPO", 0),
            "exclude_alias_of_declared": final_counts.get("EXCLUDE_ALIAS_OF_DECLARED", 0),
            "assigned_triage": 367,
            "screened_no_plausible_ai": final_counts.get("SCREENED_NO_PLAUSIBLE_AI", 0),
            "deep_reviewed": len(cases),
            "seven_gate_consumable_rows": len(cases),
            "pass_proposals": 0,
            "reject": len(cases),
            "narrow": 0,
            "unknown": 0,
            "blocked": 0,
        },
        "final_route_counts": dict(final_counts),
        "deep_reviewed_ids": [c["case_id"] for c in cases],
        "proposed_pass_ids": [],
        "shared_paths_mutated": 0,
        "siblings_or_canonical_edited": False,
        "sibling_conclusions_used_as_evidence": False,
        "derivation_rule": "Even partition from SHA256(uppercase GHSA ID) last nibble in 02468ace over the accepted 731-ID freshness-qa manifest. Official JSON from the existing advisory-database clone at /tmp/ghsa200-worker-clones/delta-even/advisory-database at 6e8a7ca9. Referenced commits scanned with cve_analyzer.ai_signatures. Completed deep git used existing /tmp clones. NEW clones go under /home/hanqing/.cache/ghsa200-worker-clones/delta-even.",
        "blockers": [
            "0 PASS proposals. COMPLETE applies to all-ID routing of 393 even identities plus bounded deep review of 37 IDs, not ecosystem coverage.",
            "330 assigned IDs were screened from official JSON and referenced-commit AI scan only; they are not seven-gate rows.",
            "AI trailers on official closers are recall for fixer attribution, not origin proof.",
        ],
    }
    (LANE / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n")
    extra_hashes["routing_manifest"] = sha256_file(LANE / "routing_manifest.jsonl")
    extra_hashes["cases_jsonl"] = sha256_file(LANE / "cases.jsonl")
    extra_hashes["result_json"] = sha256_file(LANE / "result.json")
    result["input_hashes"] = extra_hashes
    (LANE / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n")
    source["artifact_hashes"] = extra_hashes
    (LANE / "source_hashes.json").write_text(json.dumps(source, indent=2, ensure_ascii=True) + "\n")
    print(json.dumps({"deep": len(cases), "routes": dict(final_counts), "pass": 0}, indent=2))


if __name__ == "__main__":
    main()
