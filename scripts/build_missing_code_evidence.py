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

from publish_tp_ledger import collect_ids, public_shas, repo_of, research_records

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "web/src/generated/research-data.json"
OUT = ROOT / "scripts/generated-code-evidence.json"
FETCH_OVERRIDES = ROOT / "scripts/evidence_fetch_overrides.json"
PUBLICATION_OVERRIDES = ROOT / "scripts/tp_publication_overrides.json"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$", re.I)

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
        [
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repo}/commits/{sha}?per_page=100",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        pages = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(pages, list) or not pages or not isinstance(pages[0], dict):
        return None
    payload = dict(pages[0])
    if payload.get("message") in {
        "Not Found",
        "No commit found for SHA: " + sha,
    }:
        return None
    commit_sha = payload.get("sha")
    if not commit_sha:
        return None
    files: list[dict] = []
    seen: set[str] = set()
    for page in pages:
        if not isinstance(page, dict) or page.get("sha") != commit_sha:
            return None
        page_files = page.get("files")
        if not isinstance(page_files, list):
            return None
        for item in page_files:
            if not isinstance(item, dict):
                return None
            filename = str(item.get("filename") or "")
            if filename and filename not in seen:
                seen.add(filename)
                files.append(item)
    payload["files"] = files
    return payload


def gh_blob(repo: str, sha: str) -> str | None:
    if not repo or not SHA40_RE.fullmatch(str(sha or "")):
        return None
    result = subprocess.run(
        [
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github.raw+json",
            f"repos/{repo}/git/blobs/{sha}",
        ],
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 and result.stdout else None


def hydrate_allowed_patches(
    repo: str,
    commit: dict | None,
    allowed_files: object,
    anchors: object,
) -> dict | None:
    """Recover an allowlisted source blob when GitHub omits a large patch."""

    if not isinstance(commit, dict) or not isinstance(allowed_files, list) or not anchors:
        return commit
    allowed = {str(path) for path in allowed_files if str(path).strip()}
    hydrated = dict(commit)
    files: list[dict] = []
    for original in commit.get("files") or []:
        item = dict(original)
        if item.get("filename") in allowed and not str(item.get("patch") or "").strip():
            content = gh_blob(repo, str(item.get("sha") or ""))
            if content:
                prefix = "+" if not commit.get("parents") else " "
                item["patch"] = "\n".join(
                    ["@@ GitHub omitted this source patch; showing file context @@"]
                    + [prefix + line for line in content.splitlines()]
                )
        files.append(item)
    hydrated["files"] = files
    return hydrated


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

def needs_evidence(case_id: str, existing: dict, force: set[str]) -> bool:
    return case_id in force or (not force and not (
        (existing.get(case_id) or {}).get("comparison_hunks")
    ))



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
    blob = f"{path}\n{patch}".lower()
    for word in re.findall(r"[a-z]{4,}", (mechanism or "").lower())[:16]:
        if word in blob:
            score += 1
    if SECURITY.search(patch):
        score += 4
    return score


def trim_patch(patch: str, limit: int = 90, anchors: object = None) -> str:
    keep = [
        line
        for line in patch.splitlines()
        if line.startswith(("+", "-", " ", "@"))
    ]
    selectors = (
        [anchors]
        if isinstance(anchors, str) and anchors.strip()
        else [value for value in anchors if isinstance(value, str) and value.strip()]
        if isinstance(anchors, list)
        else []
    )
    if selectors:
        index = next(
            (
                index
                for selector in selectors
                for index, line in enumerate(keep)
                if selector.casefold() in line.casefold()
            ),
            None,
        )
        if index is None:
            return ""
        keep = keep[max(0, index - limit // 3) :]
    return "\n".join(keep[:limit])


def hunks_from_commit(
    commit: dict,
    mechanism: str,
    limit: int = 3,
    allowed_files: object = None,
    anchors: object = None,
) -> list[dict]:
    allowed = (
        {str(path) for path in allowed_files if str(path).strip()}
        if isinstance(allowed_files, list)
        else None
    )
    files = []
    for item in commit.get("files") or []:
        path = item.get("filename") or ""
        patch = item.get("patch") or ""
        if (
            not path
            or not patch
            or SKIP.search(path)
            or allowed is not None
            and path not in allowed
        ):
            continue
        files.append((score_file(path, patch, mechanism), path, patch))
    files.sort(reverse=True)
    hunks = []
    for score, path, patch in files:
        if score < 0:
            continue
        code = trim_patch(patch, anchors=anchors)
        if not code:
            continue
        hunks.append(
            {
                "file": path,
                "code": code,
                "annotation": "",
            }
        )
        if len(hunks) >= limit:
            break
    return hunks


def patch_file_witness(commit: dict | None, allowed_files: object) -> list[str]:
    if not isinstance(commit, dict) or not isinstance(allowed_files, list):
        return []
    patched = {
        str(item.get("filename") or "")
        for item in commit.get("files") or []
        if str(item.get("patch") or "").strip()
    }
    return [
        str(path)
        for path in allowed_files
        if str(path).strip() and str(path) in patched
    ]


def subject(commit: dict) -> str:
    message = ((commit.get("commit") or {}).get("message") or "").strip()
    return message.splitlines()[0] if message else "Commit"


def build_case(case: dict, override: dict | None = None) -> dict | None:
    override = override or {}
    repo = override.get("fetch_repo") or case.get("repository")
    candidate_repo = override.get("candidate_repo") or repo
    fix_repo = override.get("fix_repo") or repo
    cand = override.get("candidate") or ((case.get("candidate_set") or [None])[0])
    fix = override.get("fix") or ((case.get("minimum_fix_set") or [None])[0])
    if (not candidate_repo or not cand) and (not fix_repo or not fix):
        return None
    mechanism = case.get("mechanism") or case.get("description") or ""
    cand_commit = gh_commit(candidate_repo, cand) if candidate_repo and cand else None
    fix_commit = gh_commit(fix_repo, fix) if fix_repo and fix else None
    cand_commit = hydrate_allowed_patches(
        candidate_repo,
        cand_commit,
        override.get("candidate_files"),
        override.get("candidate_anchors"),
    )
    fix_commit = hydrate_allowed_patches(
        fix_repo,
        fix_commit,
        override.get("fix_files"),
        override.get("fix_anchors"),
    )
    ch = (
        hunks_from_commit(
            cand_commit,
            mechanism,
            allowed_files=override.get("candidate_files"),
            anchors=override.get("candidate_anchors"),
        )
        if cand_commit
        else []
    )
    fh = (
        hunks_from_commit(
            fix_commit,
            mechanism,
            allowed_files=override.get("fix_files"),
            anchors=override.get("fix_anchors"),
        )
        if fix_commit
        else []
    )
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
            f"https://github.com/{candidate_repo}/commit/{cand_commit['sha']}"
            if cand_commit
            else ""
        ),
        "fix_url": (
            f"https://github.com/{fix_repo}/commit/{fix_commit['sha']}"
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
    if isinstance(override.get("candidate_files"), list):
        evidence["candidate_patch_files"] = patch_file_witness(
            cand_commit, override["candidate_files"]
        )
    if isinstance(override.get("fix_files"), list):
        evidence["fix_patch_files"] = patch_file_witness(
            fix_commit, override["fix_files"]
        )
    return evidence


def ledger_case(row: dict, publication_overrides: dict | None = None) -> dict | None:
    """Use the publisher's canonical research-record priority for one row."""

    if row.get("status") not in ("AI_ROOT_CAUSE", "AI_CODE_FLAWED"):
        return None
    records = research_records(row)
    rec = records[0] if records else None
    if not rec:
        return None
    candidates, fixes = public_shas(rec, None)
    if not candidates and not fixes:
        return None
    ghsas, cves = collect_ids(row, rec)
    case_id = (ghsas or cves or [row.get("class_id")])[0]
    mechanism = " ".join(
        str(rec.get(key) or "")
        for key in ("flaw_origin", "bug_semantics", "reasoning")
    ).strip() or row.get("class_id", "")
    case = {
        "case_id": case_id,
        "class_id": row.get("class_id"),
        "aliases": [case_id, *(cves or ghsas)],
        "repository": repo_of(row, rec),
        "mechanism": mechanism[:400],
        "candidate_set": candidates,
        "minimum_fix_set": fixes,
    }
    spec = ((publication_overrides or {}).get("cases") or {}).get(
        str(row.get("class_id") or "")
    ) or {}
    if spec.get("case_id"):
        case["case_id"] = str(spec["case_id"]).upper()
        case["aliases"] = [
            case_id,
            *(alias for alias in case["aliases"] if alias.upper() != case["case_id"]),
        ]
    for field in ("repository", "mechanism", "candidate_set", "minimum_fix_set"):
        if field in spec:
            case[field] = spec[field]
    return case


def ledger_cases(path: Path) -> list[dict]:
    """Build cases from every canonical record container used by the publisher."""

    publication_overrides = json.loads(PUBLICATION_OVERRIDES.read_text())
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        case = ledger_case(json.loads(line), publication_overrides)
        if case:
            out.append(case)
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
    active = {str(case.get("case_id") or "").upper() for case in cases}
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
    built = {
        key: value for key, value in existing.items() if key.upper() in active
    }
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
    scheduled: set[str] = set()
    for case in cases:
        key = case["case_id"].upper()
        override = fetch_override_for(case, fetch_overrides)
        has_source = (
            (
                override.get("candidate_repo")
                or override.get("fix_repo")
                or override.get("fetch_repo")
                or case.get("repository")
            )
            and (
                override.get("candidate")
                or override.get("fix")
                or case.get("candidate_set")
                or case.get("minimum_fix_set")
            )
        )
        needs = needs_evidence(key, existing, force)
        if has_source and needs and key not in scheduled:
            missing.append((case, override))
            scheduled.add(key)
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
