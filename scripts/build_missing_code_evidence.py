#!/usr/bin/env python3
"""Build comparison hunks for published cases that still lack code evidence.

Uses GitHub commit patches. Mechanical: no fabricated files or SHAs.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "web/src/generated/research-data.json"
OUT = ROOT / "scripts/generated-code-evidence.json"
FETCH_OVERRIDES = ROOT / "scripts/evidence_fetch_overrides.json"

SKIP = re.compile(
    r"(^|/)("
    r"package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|Cargo\.lock|"
    r"poetry\.lock|.*\.min\.(js|css)|.*\.map|.*\.(png|jpg|svg|woff2?|lock)"
    r")$",
    re.I,
)
SOURCE = re.compile(
    r"\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|php|rb|java|kt|cs|swift|vue|svelte)$",
    re.I,
)
SECURITY = re.compile(
    r"fetch\(|exec\(|eval\(|innerHTML|path\.join|spawn\(|shell|subprocess|"
    r"unquote|allowlist|denylist|validat|authorize|permission|symlink|"
    r"csrf|ssrf|sanitize|escape\(|trust|redirect|secret|token|password",
    re.I,
)


def gh_commit(repo: str, sha: str) -> dict | None:
    if not repo or not sha:
        return None
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/commits/{sha}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("message") in {
        "Not Found",
        "No commit found for SHA: " + sha,
    }:
        return None
    if "sha" not in payload:
        return None
    return payload


def load_fetch_overrides() -> dict[str, dict]:
    if not FETCH_OVERRIDES.exists():
        return {}
    try:
        payload = json.loads(FETCH_OVERRIDES.read_text())
    except ValueError:
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(key).upper(): value
        for key, value in payload.items()
        if isinstance(value, dict)
    }


def fetch_override_for(case: dict, overrides: dict[str, dict]) -> dict:
    keys = [case.get("case_id"), *(case.get("aliases") or [])]
    for key in keys:
        hit = overrides.get(str(key or "").upper())
        if hit:
            return hit
    return {}


def marker_from_message(message: str) -> str | None:
    for line in (message or "").splitlines():
        if re.search(r"co-auth|assisted-by|generated-by|\[ai", line, re.I):
            return line.strip()
    return None


def score_file(path: str, patch: str, mechanism: str) -> int:
    score = 0
    if SOURCE.search(path):
        score += 6
    if SKIP.search(path):
        return -100
    if re.search(r"(^|/)(tests?|spec|__tests__|fixtures)/", path, re.I):
        score -= 5
    blob = f"{path}\n{patch}\n{mechanism}".lower()
    for word in re.findall(r"[a-z]{4,}", (mechanism or "").lower())[:16]:
        if word in blob:
            score += 1
    if SECURITY.search(patch):
        score += 4
    return score


def trim_patch(patch: str, limit: int = 90) -> str:
    keep = [
        line
        for line in patch.splitlines()
        if line.startswith(("+", "-", " ", "@"))
    ]
    return "\n".join(keep[:limit])


def annotate(patch: str, mechanism: str, kind: str) -> str:
    interesting = [
        line
        for line in patch.splitlines()
        if line.startswith(("+", "-"))
        and not line.startswith(("+++", "---"))
        and SECURITY.search(line)
    ]
    added = [line[1:].strip() for line in interesting if line.startswith("+")]
    removed = [line[1:].strip() for line in interesting if line.startswith("-")]
    if kind == "candidate":
        if added:
            return f"AI introduced this behavior: `{added[0][:140]}`"
        if removed:
            return f"AI removed a constraint: `{removed[0][:140]}`"
    if kind == "fix" and added:
        return f"The fix adds: `{added[0][:140]}`"
    text = (mechanism or "").strip()
    return text[:180] if len(text) > 40 else ""


def hunks_from_commit(
    commit: dict,
    mechanism: str,
    kind: str,
    limit: int = 3,
) -> list[dict]:
    files = []
    for item in commit.get("files") or []:
        path = item.get("filename") or ""
        patch = item.get("patch") or ""
        if not path or not patch or SKIP.search(path):
            continue
        files.append((score_file(path, patch, mechanism), path, patch))
    files.sort(reverse=True)
    hunks = []
    for score, path, patch in files:
        if score < 0:
            continue
        code = trim_patch(patch)
        if not code:
            continue
        hunks.append(
            {
                "file": path,
                "code": code,
                "annotation": annotate(code, mechanism, kind),
            }
        )
        if len(hunks) >= limit:
            break
    return hunks


def subject(commit: dict) -> str:
    message = ((commit.get("commit") or {}).get("message") or "").strip()
    return message.splitlines()[0] if message else "Commit"


def build_case(case: dict, override: dict | None = None) -> dict | None:
    override = override or {}
    repo = override.get("fetch_repo") or case.get("repository")
    cand = override.get("candidate") or ((case.get("candidate_set") or [None])[0])
    fix = override.get("fix") or ((case.get("minimum_fix_set") or [None])[0])
    if not repo or (not cand and not fix):
        return None
    mechanism = case.get("mechanism") or case.get("description") or ""
    cand_commit = gh_commit(repo, cand) if cand else None
    fix_commit = gh_commit(repo, fix) if fix else None
    ch = hunks_from_commit(cand_commit, mechanism, "candidate") if cand_commit else []
    fh = hunks_from_commit(fix_commit, mechanism, "fix") if fix_commit else []
    if not ch and not fh:
        return None
    comparison = (ch + fh)[:6] or fh or ch
    cid = case["case_id"]
    evidence = {
        "ai_marker": marker_from_message(
            ((cand_commit or {}).get("commit") or {}).get("message") or ""
        ),
        "fix_marker": None,
        "candidate_url": (
            f"https://github.com/{repo}/commit/{cand_commit['sha']}"
            if cand_commit
            else ""
        ),
        "fix_url": (
            f"https://github.com/{repo}/commit/{fix_commit['sha']}"
            if fix_commit
            else ""
        ),
        "advisory_url": (
            f"https://github.com/advisories/{cid.lower()}"
            if str(cid).upper().startswith("GHSA-")
            else ""
        ),
        "summary": (mechanism or "")[:280],
        "steps": [
            *([{"title": "AI change", "detail": subject(cand_commit)}] if cand_commit else []),
            *([{"title": "Fix", "detail": subject(fix_commit)}] if fix_commit else []),
        ],
        "candidate_hunks": ch,
        "fix_hunks": fh,
        "comparison_hunks": comparison,
        "candidate_patch_sha256": hashlib.sha256(
            "\n".join(hunk["code"] for hunk in ch).encode()
        ).hexdigest()
        if ch
        else None,
        "fix_patch_sha256": hashlib.sha256(
            "\n".join(hunk["code"] for hunk in fh).encode()
        ).hexdigest()
        if fh
        else None,
    }
    return evidence


def ledger_cases(path: Path) -> list[dict]:
    """Build case dicts for round-N TP rows that carry commit shas.

    These rows are confirmed TPs not yet in the published catalog; their
    roundN_research holds introducer/fix shas and the mechanism prose.
    """
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("status") not in ("AI_ROOT_CAUSE", "AI_CODE_FLAWED"):
            continue
        rec = None
        for key in (
            "round9_research",
            "round8_research",
            "round7_research",
            "round6_research",
            "round5_research",
            "round4_research",
            "round3_research",
            "causal_research",
        ):
            value = row.get(key)
            if isinstance(value, dict) and value:
                rec = value
                break
        if not rec or not (rec.get("introducer_sha") or rec.get("fix_sha")):
            continue
        ids = [str(i) for i in (rec.get("advisory_ids") or [])]
        ghsas = [i for i in ids if str(i).upper().startswith("GHSA-")]
        cves = [i for i in ids if str(i).upper().startswith("CVE-")]
        case_id = (ghsas or cves or [row.get("class_id")])[0]
        mechanism = " ".join(
            str(rec.get(k) or "")
            for k in ("flaw_origin", "bug_semantics", "reasoning")
        ).strip() or row.get("class_id", "")
        out.append(
            {
                "case_id": case_id,
                "class_id": row.get("class_id"),
                "aliases": [case_id, *(cves or ghsas)],
                "repository": row.get("repo"),
                "mechanism": mechanism[:400],
                "candidate_set": [
                    str(rec["introducer_sha"])
                ]
                if rec.get("introducer_sha")
                else [],
                "minimum_fix_set": [
                    str(rec.get("direct_fix_sha") or rec.get("fix_sha"))
                ]
                if rec.get("direct_fix_sha") or rec.get("fix_sha")
                else [],
            }
        )
    return out


def main() -> None:
    ledger_arg = next(
        (arg for arg in sys.argv[1:] if not arg.startswith("-")),
        None,
    )
    if ledger_arg:
        cases = ledger_cases(Path(ledger_arg))
    else:
        cases = json.loads(DATA.read_text())["cases"]
    if not ledger_arg and "FORCE_IDS" not in os.environ:
        cases = [
            c for c in cases
            if not (c.get("code_evidence") or {}).get("comparison_hunks")
        ]
    existing = {}
    if OUT.exists():
        try:
            existing = json.loads(OUT.read_text())
        except ValueError:
            existing = {}
    built = dict(existing)
    force = {line.strip().upper() for line in os.environ.get("FORCE_IDS", "").split() if line.strip()}
    force_file = os.environ.get("FORCE_IDS_FILE")
    if force_file and Path(force_file).exists():
        force.update(
            line.strip().upper()
            for line in Path(force_file).read_text().splitlines()
            if line.strip()
        )
    fetch_overrides = load_fetch_overrides()
    missing = []
    for case in cases:
        override = fetch_override_for(case, fetch_overrides)
        has_source = (
            (override.get("fetch_repo") or case.get("repository"))
            and (
                override.get("candidate")
                or override.get("fix")
                or case.get("candidate_set")
                or case.get("minimum_fix_set")
            )
        )
        needs = case["case_id"].upper() in force or not (
            (case.get("code_evidence") or {}).get("comparison_hunks")
        )
        if has_source and (needs or override):
            if case["case_id"].upper() in force or not (
                (case.get("code_evidence") or {}).get("comparison_hunks")
            ):
                missing.append((case, override))
    print("targets", len(missing))
    ok = 0
    for index, (case, override) in enumerate(missing, 1):
        key = case["case_id"].upper()
        evidence = build_case(case, override)
        if evidence:
            built[key] = evidence
            ok += 1
            print(
                f"{index}/{len(missing)} OK {case['case_id']} "
                f"cand={len(evidence['candidate_hunks'])} "
                f"fix={len(evidence['fix_hunks'])}"
            )
        else:
            print(f"{index}/{len(missing)} SKIP {case['case_id']}")
    OUT.write_text(json.dumps(built, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps({"wrote": len(built), "new": ok, "out": str(OUT)}))


if __name__ == "__main__":
    main()
