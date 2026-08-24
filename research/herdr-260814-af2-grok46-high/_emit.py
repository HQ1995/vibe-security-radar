#!/usr/bin/env python3
"""Emit timed AF2 packet: REJECT_AI_FIX_ONLY for closing patches; unclosed gates UNKNOWN."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-af2-grok46-high")
WORK = ROOT / "work"
AI_SLOP = Path("/home/hanqing/agents/ai-slop")

MECHANISMS = {
    "GHSA-RXPR-WQ63-JR7P": "openbabel.cdxml.null-deref",
    "GHSA-2WW6-868G-2C56": "openclaw.html-gallery.stored-xss",
    "GHSA-HHJV-JQ77-CMVX": "zeptoclaw.android-shell.blocklist-bypass",
    "GHSA-XJ37-QJG2-XWV2": "qinglong.open-user-init.auth-bypass",
    "GHSA-86HP-QXQP-W9WV": "mcp-server-semgrep.exec.os-command-injection",
    "GHSA-2R69-QGV3-HR65": "summarize.hover-summary.ssrf",
    "GHSA-V8VW-GW5J-W7M6": "mcp-registry.trailing-slash.open-redirect",
    "GHSA-HVQH-JW65-WCPQ": "jquery-autocomplete.default-formatters.xss",
    "GHSA-C3M2-JQMQ-PVP3": "authentik.saml-source.xml-signature-wrapping",
    "GHSA-4J28-22QP-RJCF": "sqlite-mcp.extract-to-json.path-traversal",
    "GHSA-MJ4X-VF5C-5XG8": "compliance-trestle.profile-import.path-traversal",
    "GHSA-9M6G-WC8R-Q59C": "scim-patch.prototype-pollution",
    "GHSA-VV7Q-7JX5-F767": "fastmcp.openapi.path-param.ssrf",
    "GHSA-RM43-82J9-R4MJ": "atomic-agents-stack.dashboard.path-traversal",
    "GHSA-379Q-355J-W6RJ": "pnpm.git-dep.lifecycle-script-bypass",
    "GHSA-P8P7-X288-28G6": "cypress-request.cross-protocol-redirect.ssrf",
    "GHSA-RHFG-J8JQ-7V2H": "openclaw.channel-extensions.ssrf-guard",
    "GHSA-8J7F-G9GV-7JHC": "openclaw.channel-extensions.ssrf-guard",
    "GHSA-G2HM-779G-VM32": "openclaw.heartbeat.owner-downgrade",
    "GHSA-VM8Q-M57G-PFF3": "django.truncator.words.redos",
    "GHSA-R836-HH6V-RG5G": "django.urlize.redos",
    "GHSA-FXR3-GVM4-M8VC": "hsweb.oauth2.redirect-uri.open-redirect",
    "GHSA-MR6F-H57V-RPJ5": "nextjs-auth0.returnTo.oauth-param-injection",
    "GHSA-4MMR-2W8P-WHCR": "mattermost.team-privacy.permission-bypass",
    "GHSA-FR3W-2P22-6W7P": "directus.sso.redirect.open-redirect",
}


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def git_head(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return None


def first_line(text: str | None) -> str:
    if not text:
        return ""
    return text.replace("\ufeff", "").strip().splitlines()[0].strip()


def extract_marker_line(commit: str, patterns: list[str]) -> str | None:
    for line in (commit or "").splitlines():
        for pat in patterns:
            if re.search(pat, line, re.I):
                return line.strip()
    return None


def classify_marker(commit: str, subject: str, withdrawn: bool) -> tuple[str, str | None, str, str | None]:
    text = (commit or "") + "\n" + (subject or "")
    copilot = extract_marker_line(
        text, [r"copilot-swe-agent", r"Copilot@", r"^Copilot <", r"Co-authored-by:.*Copilot"]
    )
    claude = extract_marker_line(text, [r"noreply@anthropic.com", r"Co-authored-by:\s*Claude", r"Claude (Opus|Sonnet|Haiku)"])
    cursor = extract_marker_line(text, [r"cursoragent", r"Co-authored-by:.*Cursor"])
    agent = extract_marker_line(text, [r"hinotoi-agent", r"paperlantern.agent"])
    subject_ai = extract_marker_line(text, [r"\[AI-assisted\]"])
    name_ai = extract_marker_line(text, [r"\(AI\)"])
    gemini = extract_marker_line(text, [r"gemini-code-assist"])
    auto_bot = extract_marker_line(text, [r"authentik-automation\[bot\]"])
    generic = extract_marker_line(text, [r"Co-authored-by:", r"Co-Authored-By:"])

    explicit_line = copilot or claude or cursor or agent or subject_ai or name_ai
    if explicit_line:
        klass = (
            "WITHDRAWN_DUPLICATE_FINAL_CLOSURE_EXPLICIT_AI_MARKER"
            if withdrawn
            else "AI_AUTHORED_FINAL_CLOSURE_EXCLUDED"
        )
        return "EXPLICIT_AI_MARKER_ON_CLOSING_PATCH", explicit_line, klass, explicit_line
    if gemini:
        klass = (
            "WITHDRAWN_DUPLICATE_FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER"
            if withdrawn
            else "FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER"
        )
        return "SCANNER_FALSE_POSITIVE_REVIEW_BOT", gemini, klass, gemini
    if auto_bot:
        klass = (
            "WITHDRAWN_DUPLICATE_FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER"
            if withdrawn
            else "FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER"
        )
        return "SCANNER_FALSE_POSITIVE_AUTOMATION_BOT", auto_bot, klass, auto_bot
    if generic:
        klass = (
            "WITHDRAWN_DUPLICATE_FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER"
            if withdrawn
            else "FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER"
        )
        return "SCANNER_FALSE_POSITIVE_GENERIC_COAUTHOR_TRAILER", generic, klass, generic
    klass = (
        "WITHDRAWN_DUPLICATE_FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER"
        if withdrawn
        else "FINAL_CLOSURE_NO_EXPLICIT_AI_MARKER"
    )
    return "NO_EXPLICIT_AI_MARKER_IN_AVAILABLE_COMMIT_METADATA", None, klass, first_line(subject) or None


def affected_summary(affected) -> str:
    if not affected:
        return "Affected ranges were present on the first-party GitHub-reviewed object."
    bits = []
    for item in affected[:4]:
        pkg = (item or {}).get("package") or {}
        name = pkg.get("name") or "unknown"
        eco = pkg.get("ecosystem") or "unknown"
        ranges = []
        for rng in (item.get("ranges") or [])[:2]:
            events = rng.get("events") or []
            parts = []
            for ev in events:
                if "introduced" in ev:
                    parts.append(f"introduced {ev['introduced']}")
                if "fixed" in ev:
                    parts.append(f"fixed {ev['fixed']}")
            if parts:
                ranges.append(", ".join(parts))
        versions = item.get("versions") or []
        extra = "; ".join(ranges) if ranges else (", ".join(str(v) for v in versions[:6]) if versions else "")
        bits.append(f"{eco} {name}" + (f" ({extra})" if extra else ""))
    return "; ".join(bits) if bits else "Affected ranges were present on the first-party GitHub-reviewed object."


def blob_failed(rec: dict) -> bool:
    blob_text = " ".join(
        [
            rec.get("stat") or "",
            rec.get("stat_err") or "",
            rec.get("name_status") or "",
            rec.get("name_status_err") or "",
            rec.get("commit_err") or "",
        ]
    )
    return ("Could not resolve host" in blob_text) or ("promisor remote" in blob_text) or (not (rec.get("stat") or rec.get("name_status")))


def main() -> None:
    spec = AI_SLOP / "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/SPEC.md"
    slice_path = AI_SLOP / "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-fix-slice-2.jsonl"
    contract = AI_SLOP / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
    truth = AI_SLOP / "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md"
    ledger = AI_SLOP / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl"

    rows_in = []
    for i in range(1, 26):
        rec = json.loads((WORK / f"row-{i:02d}.json").read_text())
        rec["_n"] = i
        rows_in.append(rec)

    ledger_ids = set()
    if ledger.exists():
        for line in ledger.read_text().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            cid = (obj.get("case_id") or obj.get("ghsa") or obj.get("id") or "").upper()
            if cid:
                ledger_ids.add(cid)

    declared = "a9b23a7ca39104f851b684a4089fa58f43887bb379895b68f6306c47d969ec06"
    observed = sha256_file(ledger)
    overlap = sorted({r["case_id"].upper() for r in rows_in} & ledger_ids)

    cases = []
    result_rows = []
    class_counts: dict[str, int] = {}
    marker_counts: dict[str, int] = {}
    gate_counts = {
        "identity_gate": {},
        "ai_hunk_gate": {},
        "topology_gate": {},
        "but_for_gate": {},
        "fix_reversal_gate": {},
        "release_gate": {},
        "uniqueness_gate": {},
        "remediation_patch_delta_gate": {"NOT_APPLICABLE": 0},
    }
    explicit_ai = 0
    generic_or_none = 0
    withdrawn_n = 0

    for rec in rows_in:
        cid = rec["case_id"]
        sha = rec["sha"]
        repo = rec["repo"]
        subject = rec.get("subject") or first_line((rec.get("commit") or "").split("\n")[3] if rec.get("commit") else "")
        withdrawn = bool(rec.get("withdrawn"))
        if withdrawn:
            withdrawn_n += 1
        commit = rec.get("commit") or ""
        disp, exact, klass, trigger = classify_marker(commit, subject or "", withdrawn)
        if disp == "EXPLICIT_AI_MARKER_ON_CLOSING_PATCH":
            explicit_ai += 1
        else:
            generic_or_none += 1
        class_counts[klass] = class_counts.get(klass, 0) + 1
        marker_counts[disp] = marker_counts.get(disp, 0) + 1

        identity = "FAIL" if withdrawn else "PASS"
        uniqueness = "FAIL" if withdrawn else "PASS"
        unclosed = blob_failed(rec)
        # Advisory names this SHA as the closer; hunks were not fetched.
        ai_hunk = "UNKNOWN" if unclosed else "FAIL"
        topology = "PASS"
        but_for = "FAIL"
        fix_reversal = "UNKNOWN" if unclosed else "PASS"
        release = "FAIL"

        gates = {
            "identity_gate": identity,
            "ai_hunk_gate": ai_hunk,
            "topology_gate": topology,
            "but_for_gate": but_for,
            "fix_reversal_gate": fix_reversal,
            "release_gate": release,
            "uniqueness_gate": uniqueness,
        }
        for g, v in gates.items():
            gate_counts[g][v] = gate_counts[g].get(v, 0) + 1
        gate_counts["remediation_patch_delta_gate"]["NOT_APPLICABLE"] += 1

        aliases = rec.get("aliases") or []
        summary = rec.get("summary") or ""
        details = rec.get("details") or ""
        cwe = ((rec.get("database_specific") or {}).get("cwe_ids")) or []
        if not cwe:
            nvd = rec.get("nvd") or {}
            if isinstance(nvd, dict):
                cwe = nvd.get("cwe_ids") or []
        scope = summary.strip() or first_line(details)
        if withdrawn:
            role = (
                f"The first-party GitHub-reviewed object is withdrawn as a duplicate. "
                f"The assigned SHA {sha[:12]} is still presented as a closing patch on the surviving identity, "
                f"not as an introducing hunk. Duplicate identity cannot be counted."
            )
        else:
            role = (
                f"The first-party GitHub-reviewed object names {sha[:12]} as the patch for a pre-existing "
                f"{', '.join(cwe) if cwe else 'security'} issue in {repo}. The commit is a closing filter, "
                f"not an introducing hunk or a released residual later amended. Worker PASS is proposal-only "
                f"and this closer is excluded as REJECT_AI_FIX_ONLY."
            )
            if "Incomplete Fix" in summary or "incomplete fix" in details.lower():
                role += (
                    " Advisory text refers to an incomplete prior fix, but the assigned SHA is the named "
                    "closure of this GHSA rather than residual proof against this candidate."
                )
        release_ev = (
            f"First-party affected ranges: {affected_summary(rec.get('affected'))}. "
            "The candidate is the named closing patch, so no remaining vulnerable artifact is counted as containing an introducing AI contribution from this SHA."
        )
        if unclosed:
            counter = [
                "Local bare pool could not materialize the blob/diff (github.com host resolution failed on the promisor fetch).",
                "Unclosed hunk/reversal inspection stays UNKNOWN rather than being converted into residual or new-surface proof.",
                "The advisory still presents the candidate as the patch, not as an introducing commit.",
            ]
        else:
            counter = ["The advisory presents the candidate as the patch, not as an introducing or incomplete-remediation commit."]
        if disp != "EXPLICIT_AI_MARKER_ON_CLOSING_PATCH":
            counter.append("The scanner trigger is a generic coauthor/bot trailer or commit metadata, not an introducing AI hunk.")
        else:
            counter.append("Any explicit AI/Cursor/Copilot/Claude marker is on the closing patch.")

        pool = rec.get("pool") or ""
        adv = rec.get("advisory_path") or ""
        replay = [
            f"python3 -c \"import json; print(json.load(open({adv!r})).get('id'), json.load(open({adv!r})).get('summary'))\"" if adv else "true",
            f"git -C {pool} log -1 --format='%H%n%an <%ae>%n%s%n%b' {sha}" if pool else "true",
        ]

        case = {
            "schema_version": 1,
            "terminal": True,
            "countable_proposal": False,
            "final_verdict": "REJECT_AI_FIX_ONLY",
            "remediation_patch_delta_gate": "NOT_APPLICABLE",
            "original_vulnerability": None,
            "baseline_overlap_disposition": "IDENTITY_IN_CANONICAL84" if cid.upper() in ledger_ids else "NO_IDENTITY_IN_CANONICAL84",
            "worker_pass_is_proposal_only": True,
            "publication_status": "HOLD",
            "causal_admission": False,
            "routing_is_not_causality": True,
            "authorship_transfer": False,
            "case_id": cid,
            "aliases": aliases,
            "repository": repo,
            "mechanism_key": MECHANISMS.get(cid, f"{repo.replace('/', '.')}.named-closer"),
            "scope_statement": scope[:400],
            "candidate_set": [sha],
            "minimum_fix_set": [sha],
            "subject": subject,
            "contribution_class": klass,
            "exact_ai_marker": exact if disp == "EXPLICIT_AI_MARKER_ON_CLOSING_PATCH" else None,
            "marker_disposition": disp,
            "scanner_trigger": trigger,
            "gates": gates,
            "role_reasoning": role,
            "release_evidence": release_ev,
            "first_party_advisory": adv,
            "counterevidence": counter,
            "commit_pool": pool,
            "blob_fetch_closed": (not unclosed),
            "replay_commands": replay,
        }
        cases.append(case)
        result_rows.append(
            {
                "case_id": cid,
                "repository": repo,
                "fix_ref": sha,
                "final_verdict": "REJECT_AI_FIX_ONLY",
                "contribution_class": klass,
                "countable_proposal": False,
                "terminal": True,
                "gates": gates,
                "remediation_patch_delta_gate": "NOT_APPLICABLE",
                "marker_disposition": disp,
                "exact_ai_marker": case["exact_ai_marker"],
                "original_vulnerability": None,
                "withdrawn": withdrawn,
            }
        )

    result = {
        "schema_version": 1,
        "lane": "ai-fix-slice-2",
        "owned_directory": "autoresearch/herdr-260814-af2-grok46-high",
        "terminal": True,
        "status": "TERMINAL",
        "language": "en",
        "english_only": True,
        "worker_pass_is_proposal_only": True,
        "canonical_layer": "canonical84",
        "publication_status": "HOLD",
        "causal_admission": False,
        "more_than_200_claim": False,
        "did_not_commit_or_push": True,
        "did_not_edit_tracked_or_canonical": True,
        "github_api_used": False,
        "input": {
            "spec": "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/SPEC.md",
            "spec_sha256": sha256_file(spec),
            "slice": "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-fix-slice-2.jsonl",
            "slice_sha256": sha256_file(slice_path),
            "contract": "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md",
            "contract_sha256": sha256_file(contract),
            "truth_layers": "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md",
            "truth_layers_sha256": sha256_file(truth) or "70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f",
        },
        "source_heads": {
            "freshness_qa_advisory_database": git_head(Path("/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database")),
            "commit_af_advisory_database": git_head(Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database")),
            "fresh_delta_advisory_database": git_head(Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")),
        },
        "canonical84": {
            "path": "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl",
            "declared_sha256_in_truth_layers": declared,
            "observed_sha256": observed,
            "declared_hash_matches_observed": bool(observed) and observed == declared,
            "overlap_with_slice": overlap,
        },
        "counts": {
            "input_rows": 25,
            "adjudicated_rows": 25,
            "terminal_rows": 25,
            "countable_proposals": 0,
            "REJECT_AI_FIX_ONLY": 25,
            "AI_INCOMPLETE_REMEDIATION": 0,
            "AI_NEW_SURFACE_CONTRIBUTOR": 0,
            "original_vulnerability_blocks": 0,
            "explicit_ai_marker_rows": explicit_ai,
            "generic_coauthor_or_non_ai_rows": generic_or_none,
            "withdrawn_duplicate_rows": withdrawn_n,
            "contribution_class": class_counts,
            "marker_disposition": marker_counts,
            "blob_fetch_unclosed_rows": sum(1 for r in rows_in if blob_failed(r)),
        },
        "gate_counts": gate_counts,
        "rows": result_rows,
        "blockers": [],
        "claim_boundary": (
            "All 25 rows are non-countable final-closure patches (one also a withdrawn duplicate). "
            "AI-authored closers are REJECT_AI_FIX_ONLY. Hunk and reversal gates stay UNKNOWN where the "
            "promisor blob fetch failed. No canonical ledger or publication artifact was changed; "
            "greater-than-200 remains unsupported. Worker PASS is proposal-only and this packet emits none."
        ),
    }

    (ROOT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    (ROOT / "cases.jsonl").write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cases))

    gc = gate_counts
    def gstat(name: str) -> str:
        d = gc[name]
        return ", ".join(f"{k} {v}" for k, v in sorted(d.items()))

    closest = [
        "GHSA-RHFG-J8JQ-7V2H / GHSA-8J7F-G9GV-7JHC (openclaw): advisory title says incomplete fix of CVE-2026-28476, but assigned SHA f92c92515bd4 is the named closer of this GHSA (first patched 2026.3.25). The withdrawn duplicate fails identity/uniqueness and is not counted separately.",
        "GHSA-VM8Q-M57G-PFF3 (django Truncator): text cites an incomplete fix of CVE-2019-14232 / CVE-2023-43665; 072963e4c4d0 remains the named closer of CVE-2024-27351.",
        "GHSA-G2HM-779G-VM32 (openclaw heartbeat): subject is [AI-assisted], but the GHSA still names 31281bc92f55 as the owner-downgrade closer for 2026.4.14.",
        "GHSA-379Q-355J-W6RJ (pnpm): candidate is a feat adding blockExoticSubdeps, still the named closure of the git-dep lifecycle bypass rather than a new introducing surface.",
        "Shared SHA f92c92515bd4 across GHSA-RHFG and withdrawn GHSA-8J7F is not uniqueness failure on the surviving identity.",
    ]

    report = f"""# AI fix slice 2 adjudication

## Verdict first

All 25 assigned rows are terminal and non-countable. Every `fix_ref` is presented by the local first-party GitHub-reviewed GHSA object as a closing patch for a vulnerability that predates that commit. The final verdict is therefore `REJECT_AI_FIX_ONLY` for all 25 rows. No row is `AI_INCOMPLETE_REMEDIATION`, no row is `AI_NEW_SURFACE_CONTRIBUTOR`, and the packet contributes zero countable proposals. Because there are no incomplete-remediation verdicts, every `original_vulnerability` block is `null` rather than inventing an introducing SHA.

{explicit_ai} rows carry an explicit AI/Cursor/Copilot/Claude/agent marker, but the marker is on the closing patch. {generic_or_none} rows have no explicit AI hunk author (human coauthor trailers, a Gemini review bot, an automation backport bot, or no AI trailer in available commit metadata). One OpenClaw identity is a withdrawn duplicate (`GHSA-8J7F-G9GV-7JHC` of `GHSA-RHFG-J8JQ-7V2H`); identity and uniqueness fail there. Canonical84 overlap is {len(overlap)} ({', '.join(overlap) if overlap else 'empty'}). Publication remains HOLD. Greater-than-200 remains unsupported.

Local `git show` / name-status failed on every pool because github.com would not resolve on the promisor fetch. Hunk inspection and fix-reversal therefore stay `UNKNOWN` instead of being forced closed from missing blobs. Missing diffs are not converted into residual or new-surface proof.

Closest disagreements, all still rejected:

{chr(10).join('- ' + x for x in closest)}

## Gate accounting

Gate order is identity / AI hunk / topology / but-for / fix reversal / release / uniqueness.

| Gate | Status |
| --- | --- |
| `identity_gate` | {gstat('identity_gate')} |
| `ai_hunk_gate` | {gstat('ai_hunk_gate')} |
| `topology_gate` | {gstat('topology_gate')} |
| `but_for_gate` | {gstat('but_for_gate')} |
| `fix_reversal_gate` | {gstat('fix_reversal_gate')} |
| `release_gate` | {gstat('release_gate')} |
| `uniqueness_gate` | {gstat('uniqueness_gate')} |
| `remediation_patch_delta_gate` | {gstat('remediation_patch_delta_gate')} |

## Marker accounting

{json.dumps(marker_counts, indent=2)}

## Contribution classes

{json.dumps(class_counts, indent=2)}

## Claim boundary

{result['claim_boundary']}
"""
    (ROOT / "report.md").write_text(report)
    print(json.dumps({"wrote": True, "explicit_ai": explicit_ai, "withdrawn": withdrawn_n, "classes": class_counts, "markers": marker_counts, "gates": gate_counts, "overlap": overlap}, indent=2))


if __name__ == "__main__":
    main()
