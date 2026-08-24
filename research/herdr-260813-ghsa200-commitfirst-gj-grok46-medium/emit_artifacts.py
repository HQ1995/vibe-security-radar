#!/usr/bin/env python3
"""ABORTED census emitter. Terminal artifacts are already finalized; do not restore REJECT rows."""
raise SystemExit("aborted: do not re-emit the file-density 30-row REJECT census")


from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium")
GN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gn")
ADV_HEAD = "a42c436870111aa3f221257c9d56126a93173ccc"
CONTRACT = "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
LANE = "commitfirst-gj-grok46-medium"
ENDED = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
STARTED = "2026-08-13T22:24:00Z"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def fail_gates(**overrides: str) -> dict[str, str]:
    gates = {
        "identity_gate": "PASS",
        "ai_hunk_gate": "FAIL",
        "topology_gate": "FAIL",
        "but_for_gate": "FAIL",
        "fix_reversal_gate": "UNKNOWN",
        "release_gate": "UNKNOWN",
        "uniqueness_gate": "PASS",
    }
    gates.update(overrides)
    return gates


def base_row(assigned: dict, **extra) -> dict:
    ghsa = assigned["ghsa_id"]
    slug = ghsa.lower()
    repo = assigned["repository"]
    row = {
        "advisory_database_head": ADV_HEAD,
        "aliases": assigned.get("aliases") or [],
        "baseline_overlap_disposition": "ABSENT_FROM_FP211_AND_PUBLICATION_ADJUDICATIONS",
        "case_id": ghsa,
        "first_party_sources": [
            f"https://github.com/advisories/{slug}",
            f"https://github.com/{repo}/security/advisories/{slug}",
        ],
        "lane": LANE,
        "population": "gj_unreviewed_exact_ai_fix_file_intersection_top30",
        "repository": repo,
        "schema_version": 1,
        "scope_statement": assigned.get("summary"),
        "worker_pass_is_proposal_only": True,
    }
    row.update(extra)
    return row


def main() -> None:
    assigned = {r["ghsa_id"]: r for r in load_jsonl(GN / "assigned.jsonl")}
    gn_cases = load_jsonl(GN / "cases.jsonl")
    gn_reviewed = {r["case_id"].upper() for r in gn_cases}
    all_assigned = load_jsonl(GN / "assigned.jsonl")
    gj = [r for r in all_assigned if r.get("owner", "").casefold()[:1] in "ghij"]
    gj_ids = {r["ghsa_id"].upper() for r in gj}
    rank = json.loads((OWNED / "origin-rank.json").read_text(encoding="utf-8"))
    top30 = rank["top30"]
    freeze = json.loads((GN / "freeze.json").read_text(encoding="utf-8"))
    gn_result = json.loads((GN / "result.json").read_text(encoding="utf-8"))

    rejects: dict[str, dict] = {
        "GHSA-268J-37XF-PP52": {
            "contribution_class": "UNRELATED_SIBLING_REWRITE",
            "counterevidence": [
                "Blamed AI commit a1fa62b270 decouples API types from go-gogs-client; it does not add write-collaborator mutation of admin-only repository settings.",
                "Same-file overlap with the later API fix is routing, not but-for authorship of the scoped mechanism.",
            ],
        },
        "GHSA-3W28-36P9-W929": {
            "contribution_class": "SIBLING_PATH_NOT_PATCH_DELTA",
            "counterevidence": [
                "Claude-marked 441c64d7bd restricts data: URIs in internal/markup/sanitizer.go.",
                "The GHSA is the ipynb sanitizer in internal/app/api.go that still AllowURLSchemes(\"data\").",
                "A later same-repo sanitizer improvement is not incomplete remediation of this endpoint.",
            ],
        },
        "GHSA-X9P5-W45C-7FFC": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Blame hit .claude/commands/ghsa.md, not internal/context/auth.go query-token parsing.",
                "The introducing hunk for token-in-URL is not the Claude-marked template-escape commit.",
            ],
        },
        "GHSA-6XJ8-QV9J-XCJQ": {
            "contribution_class": "WRONG_EDGE_OLD_BUG",
            "counterevidence": [
                "Advisory mechanism is template.Render of filesystem path components in src/segments/path.go.",
                "Claude-marked 367ec8331b only adds transient right-aligned templates in src/prompt/extra.go.",
                "Advisory range starts at introduced 0; this is old-bug preservation, not AI origin.",
            ],
        },
        "GHSA-35HP-HQMV-8QG8": {
            "contribution_class": "OLD_BUG_PRESERVATION",
            "counterevidence": [
                "Parent of Copilot commit 27d359e8d0 already used defaultKeyGenerator with c.Path() and DisableQueryKeys.",
                "The AI hunk wraps boundKeySegment around Path; it does not introduce path-only cache keys.",
                "Advisory-cited later hardening is not reversal of an AI-introduced query omission.",
            ],
        },
        "GHSA-89MR-XQFV-758M": {
            "contribution_class": "CARRIER_RENAME_NOT_ORIGIN",
            "counterevidence": [
                "AI-marked 36d56d55 is a package rename util -> x. Authorship of UploadRepoFiles symlink behavior does not transfer with the rename.",
            ],
        },
        "GHSA-C39W-43GM-34H5": {
            "contribution_class": "UNRELATED_SIBLING_REWRITE",
            "counterevidence": [
                "Same API-types decoupling commit as GHSA-268J; organization-name path traversal is a different edge.",
            ],
        },
        "GHSA-FJ8V-HJWV-QM88": {
            "contribution_class": "SQUASH_CARRIER_PREEXISTING_BRANCH",
            "counterevidence": [
                "IsCollaborativeOwner already existed on the parent of squash 45809c8f54.",
                "The parent collaborative-owner path also lacked an IsForkPullRequest discriminator.",
                "The squash lists Copilot, Claude, and several human co-authors; the missing fork-PR guard is not an isolated AI hunk.",
            ],
        },
        "GHSA-JMH7-G254-2CQ9": {
            "contribution_class": "SQUASH_CARRIER_TRANSFER",
            "counterevidence": [
                "Hit is the Gradio 6.0 no-merge squash 029034f785, not an atomic AI member that added proxy_url SSRF.",
            ],
        },
        "GHSA-C32J-VQHX-RX3X": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Blame landed on CHANGELOG.md and lib/jwt/version.rb from a ruby-head compatibility commit.",
                "Empty-key HMAC bypass is not authored by that documentation/version bump.",
            ],
        },
        "GHSA-HQJG-PWW4-PCGQ": {
            "contribution_class": "DOCS_ONLY_OLD_BUG",
            "counterevidence": [
                "9c141469c5 is Jules documentation on src/core/files.ts, not the path-traversal clone/pull logic.",
                "Advisory range starts at introduced 0.",
            ],
        },
        "GHSA-777R-4V59-6486": {
            "contribution_class": "UNRELATED_SIBLING_FIX",
            "counterevidence": [
                "Blamed commit fixes issue-label deletion with Actions tokens, not the permanent fork-PR approval-gate bypass.",
            ],
        },
        "GHSA-45Q4-X4R9-8FQJ": {
            "contribution_class": "UNRELATED_SIBLING_FIX",
            "counterevidence": [
                "AI-marked commit rewrites self-assignment notification wording.",
                "The GHSA is HTML injection via task titles in overdue emails.",
            ],
        },
        "GHSA-FW57-JGCH-PGF3": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Blame hit routers/api/v1/org/team.go from a CodeQL cleanup, not ParseAcceptLanguage / locale middleware.",
            ],
        },
        "GHSA-6R28-9PPF-4HJ5": {
            "contribution_class": "SQUASH_CARRIER_COPILOT_ON_NON_MECHANISM_HUNK",
            "counterevidence": [
                "Squash fe11a243b3 adds Diameter AVP decoding, but PR #140 members show Copilot only on ports.go (6de0ba93cfa9).",
                "The AVP decoder member d23e7f51dfec is Philipp Mieden without an AI marker.",
                "AI branding on the squash/carrier must not transfer authorship of the underflow hunk.",
            ],
        },
        "GHSA-6W67-HWM5-92MQ": {
            "contribution_class": "UNRELATED_SIBLING_REWRITE",
            "counterevidence": [
                "AI-marked hit is a ruff/pyupgrade modernization of docs and pytorch config, not vision-language image URL fetch.",
            ],
        },
        "GHSA-C3PX-H233-H6FQ": {
            "contribution_class": "SIBLING_PATH_NOT_PATCH_DELTA",
            "counterevidence": [
                "AI commit adds scan depth limits; the GHSA is CreateProject/GetProjectFileContent include-path read.",
                "A nearby directory-scan hardening is not patch-delta on the include validator.",
            ],
        },
        "GHSA-C54G-XJWJ-8G82": {
            "contribution_class": "SIBLING_SECURITY_BOUNDARY",
            "counterevidence": [
                "Claude-marked 454450a647 tightens security.http.urls userinfo deny.",
                "The GHSA is verbatim text/html content emission; the later allowContent whitelist is a different boundary.",
            ],
        },
        "GHSA-F283-GHQC-FG79": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "File-history hit is QUERY-redirect documentation from 6e4dc82771, not unbounded response-cookie handling.",
            ],
        },
        "GHSA-FWJX-9P69-H25H": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "AI commit configures progress-sequence terminals; the GHSA is unsanitized prompt segment escape injection.",
            ],
        },
        "GHSA-H95V-H523-3MW8": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Same QUERY-redirect commit/docs as GHSA-F283; Referer fragment disclosure is a different cookie/redirect edge.",
            ],
        },
        "GHSA-WM3W-8RRP-J577": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Same QUERY-redirect commit/docs as GHSA-F283; host-only cookie scope is a different mechanism.",
            ],
        },
        "GHSA-25GQ-J9JX-43PG": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "File-history hit custom/conf/app.example.ini from DEFAULT_TITLE_SOURCE (#37465), not release-attachment allowlist bypass.",
            ],
        },
        "GHSA-2625-RW7M-5Q5X": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Hit is README.md from an identity/service-account feature, not default diagnostic secret leakage.",
            ],
        },
        "GHSA-39MP-8HJ3-5C49": {
            "contribution_class": "SQUASH_CARRIER_TRANSFER",
            "counterevidence": [
                "Same Gradio 6.0 squash as GHSA-JMH7; Windows absolute path traversal is not isolated as an AI hunk.",
            ],
        },
        "GHSA-5C3F-6486-3G7G": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Hit is CHANGELOG for 0.14.2, not RESET_PASSWORD_CODE_LIVES vs activation-token lifetime.",
            ],
        },
        "GHSA-5GFJ-64GH-MGMW": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "AI-marked commit handles executions during answer; the GHSA is safe_join path traversal.",
            ],
        },
        "GHSA-66M4-5JJR-2RG5": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Same DEFAULT_TITLE_SOURCE / app.example.ini hit as GHSA-25GQ; collaborator webhook persistence is unrelated.",
            ],
        },
        "GHSA-683J-3FF6-HH2X": {
            "contribution_class": "WRONG_EDGE",
            "counterevidence": [
                "Same DEFAULT_TITLE_SOURCE / app.example.ini hit as GHSA-25GQ; access-token scope escalation is unrelated.",
            ],
        },
    }

    cases: list[dict] = []
    pass_row = base_row(
        assigned["GHSA-6P9M-Q3JP-47H4"],
        ai_marker_evidence={
            "member_origin": (
                "85ebf175c0f953253247717f72f50fd6aba2d362 Co-Authored-By: Claude Opus 4.6 "
                "<noreply@anthropic.com> adds O_EXCL exist-path that drains the body without hashing "
                "and returns success so the caller can insert a cross-repo lfs_object row"
            ),
            "member_shipped_form": (
                "90f99d5f672ba95cf8cdb1a1d915acb079adb5ef Co-Authored-By: Claude Opus 4.6 "
                "rewrites that exist-path into the early os.Stat shortcut that ships: "
                "io.Copy(io.Discard, rc); return fi.Size()"
            ),
            "squash_carrier": "81ee8836445ac888d99da8b652be7d5cbc5c4d5c GitHub squash of PR #8166; every security member carries the same Claude trailer",
            "release_carrier": "5e6014c421f7e3ab1d541983372377331aa4bf7a same patch-id and same Claude trailer on the 0.14.2 line",
            "fix": "f35a767af74e05342bafc6fdda02c791816426f8 hashes the request body on the Stat shortcut; e2fae5d0455d4f92c6382433d21c3a16da077d64 cherry-picks it onto v0.14.3",
        },
        candidate_set=["85ebf175c0f953253247717f72f50fd6aba2d362", "90f99d5f672ba95cf8cdb1a1d915acb079adb5ef"],
        carrier_set=["81ee8836445ac888d99da8b652be7d5cbc5c4d5c", "5e6014c421f7e3ab1d541983372377331aa4bf7a"],
        contribution_class="AI_INCOMPLETE_REMEDIATION",
        counterevidence=[
            "PR #8166 is also the remediation of excluded-from-this-row GHSA-gmf8-978x-2fg2 (overwrite without hash). That older overwrite hole is not counted here.",
            "Mainline 81ee8836 is not a git ancestor of tag v0.14.2; containment is by identical blob/patch-id on the release cherry-pick 5e6014c4.",
        ],
        evidence_basis="first_party_advisory_json_plus_commit_gn_clone_plus_release_tags",
        first_party_sources=[
            "https://github.com/advisories/ghsa-6p9m-q3jp-47h4",
            "https://github.com/gogs/gogs/security/advisories/GHSA-6p9m-q3jp-47h4",
            "https://github.com/gogs/gogs/pull/8166",
            "https://github.com/gogs/gogs/pull/8333",
            "https://github.com/gogs/gogs/commit/81ee8836445ac888d99da8b652be7d5cbc5c4d5c",
            "https://github.com/gogs/gogs/commit/f35a767af74e05342bafc6fdda02c791816426f8",
            "https://github.com/gogs/gogs/releases/tag/v0.14.2",
            "https://github.com/gogs/gogs/releases/tag/v0.14.3",
        ],
        fixed_release_evidence={
            "advisory_fixed": "0.14.3",
            "contains_fix": True,
            "github_release": "https://github.com/gogs/gogs/releases/tag/v0.14.3",
            "published_at": "2026-06-07T20:51:06Z",
            "prerelease": False,
            "tag": "v0.14.3",
            "release_fix_sha": "e2fae5d0455d4f92c6382433d21c3a16da077d64",
            "storage_blob": "b082fbcf287744a468d8d22d75234d250327e59a",
            "shortcut_hashes_body": True,
        },
        gates={
            "identity_gate": "PASS",
            "ai_hunk_gate": "PASS",
            "topology_gate": "PASS",
            "but_for_gate": "PASS",
            "fix_reversal_gate": "PASS",
            "release_gate": "PASS",
            "uniqueness_gate": "PASS",
        },
        mechanism_key="gogs.lfs.localstorage.upload.dedupe-shortcut.unhashed-oid-bind",
        minimum_fix_set=["f35a767af74e05342bafc6fdda02c791816426f8", "e2fae5d0455d4f92c6382433d21c3a16da077d64"],
        remediation_patch_delta_gate="PASS",
        replay_commands=[
            "git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show 85ebf175c0f953253247717f72f50fd6aba2d362 -- internal/lfsutil/storage.go",
            "git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show 90f99d5f672ba95cf8cdb1a1d915acb079adb5ef -- internal/lfsutil/storage.go",
            "git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs rev-parse v0.14.2:internal/lfsutil/storage.go",
            "git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show v0.14.2:internal/lfsutil/storage.go | sed -n '77,82p'",
            "git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show v0.14.3:internal/lfsutil/storage.go | sed -n '77,90p'",
        ],
        scope_statement=(
            "LocalStorage.Upload returns success on an existing OID file without hashing the request body, "
            "so serveUpload can bind a second repository to another tenant's LFS object."
        ),
        vulnerable_release_evidence={
            "advisory_introduced": "0",
            "contains_ai_shortcut": True,
            "github_release": "https://github.com/gogs/gogs/releases/tag/v0.14.2",
            "published_at": "2026-02-19T03:47:48Z",
            "prerelease": False,
            "tag": "v0.14.2",
            "release_intro_sha": "5e6014c421f7e3ab1d541983372377331aa4bf7a",
            "storage_blob": "b53522f10a33f5021b005c6577a8492ecd1202fc",
            "blob_equals_main_squash": True,
            "patch_id_equals_main_squash": "9e3a66e9446ff29bfdeb688f73e83c3bffe65d6b",
        },
        worker_verdict="PASS",
    )
    cases.append(pass_row)

    rank_by_id = {item["ghsa_id"]: item for item in top30}
    for ghsa, meta in rejects.items():
        item = rank_by_id[ghsa]
        best = item["best"]
        row = base_row(
            assigned[ghsa],
            ai_marker_evidence={
                "intro_sha": best["intro_sha"],
                "intro_subject": best["intro_subject"],
                "evidence": best.get("evidence"),
                "files": best.get("files"),
                "note": "AI-commit/advisory-fix file intersection is routing only.",
            },
            candidate_set=[best["intro_sha"]],
            carrier_set=[],
            contribution_class=meta["contribution_class"],
            counterevidence=meta["counterevidence"],
            evidence_basis="frozen_gn_scans_plus_fix_parent_file_history_or_blame",
            fixed_release_evidence={"advisory_commit_refs": assigned[ghsa].get("commit_refs") or []},
            gates=fail_gates(),
            mechanism_key=None,
            minimum_fix_set=assigned[ghsa].get("commit_refs") or [],
            replay_commands=[
                f"python3 -c \"import json; print([r for r in map(json.loads, open('autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium/origin-rank.jsonl')) if r['ghsa_id']=='{ghsa}'])\""
            ],
            vulnerable_release_evidence={},
            worker_verdict="REJECT",
        )
        cases.append(row)

    order = {item["ghsa_id"]: i for i, item in enumerate(top30)}
    cases.sort(key=lambda r: order[r["case_id"]])
    assert len(cases) == 30
    assert len({r["case_id"] for r in cases}) == 30

    with (OWNED / "cases.jsonl").open("w", encoding="utf-8") as fh:
        for row in cases:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")

    gj_already = len(gj_ids & gn_reviewed)
    gj_unreviewed_pool = len(gj) - gj_already
    reviewed_here = 30
    still_unreviewed = gj_unreviewed_pool - reviewed_here

    input_hashes = {
        "CONTRACT.md": CONTRACT,
        "gn/assigned.jsonl": sha256_file(GN / "assigned.jsonl"),
        "gn/cases.jsonl": sha256_file(GN / "cases.jsonl"),
        "gn/ai-ghsa-intersections.jsonl": sha256_file(GN / "ai-ghsa-intersections.jsonl"),
        "gn/ai-commit-scans.jsonl": sha256_file(GN / "ai-commit-scans.jsonl"),
        "gn/freeze.json": sha256_file(GN / "freeze.json"),
        "gn/assignment-manifest.json": sha256_file(GN / "assignment-manifest.json"),
        "gn/exclusion-ghsa-ids.txt": sha256_file(GN / "exclusion-ghsa-ids.txt"),
        "gn/unresolved-ids.txt": sha256_file(GN / "unresolved-ids.txt"),
        "fp211_canonical_ledger.jsonl": freeze["input_hashes"]["fp211_canonical_ledger.jsonl"],
        "fp211_public_cases.jsonl": freeze["input_hashes"]["fp211_public_cases.jsonl"],
        "fp211_public_id_dispositions.jsonl": freeze["input_hashes"]["fp211_public_id_dispositions.jsonl"],
        "publication_adjudications.json": freeze["input_hashes"]["publication_adjudications.json"],
        "web_data_index.json": freeze["input_hashes"]["web_data_index.json"],
        "origin-rank.json": sha256_file(OWNED / "origin-rank.json"),
    }

    replay = f"""# Replay for {LANE}
# Frozen G-N packet only. Writes only under {OWNED}.

python3 - <<'PY'
import hashlib, json
from pathlib import Path
GN = Path("{GN}")
print("assigned.jsonl", hashlib.sha256((GN/"assigned.jsonl").read_bytes()).hexdigest())
print("cases.jsonl", hashlib.sha256((GN/"cases.jsonl").read_bytes()).hexdigest())
print("ai-ghsa-intersections.jsonl", hashlib.sha256((GN/"ai-ghsa-intersections.jsonl").read_bytes()).hexdigest())
print("ai-commit-scans.jsonl", hashlib.sha256((GN/"ai-commit-scans.jsonl").read_bytes()).hexdigest())
print("freeze.json", hashlib.sha256((GN/"freeze.json").read_bytes()).hexdigest())
PY

python3 {OWNED / "rank_origin_intersections.py"}

# Gogs LFS proposed PASS
GOGS=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs
git -C "$GOGS" fetch --tags --filter=blob:none origin 'refs/tags/v0.14*:refs/tags/v0.14*'
git -C "$GOGS" show 85ebf175c0f953253247717f72f50fd6aba2d362 -- internal/lfsutil/storage.go
git -C "$GOGS" show 90f99d5f672ba95cf8cdb1a1d915acb079adb5ef -- internal/lfsutil/storage.go
git -C "$GOGS" show 81ee8836445ac888d99da8b652be7d5cbc5c4d5c --format=fuller -s
git -C "$GOGS" rev-parse v0.14.2:internal/lfsutil/storage.go
git -C "$GOGS" rev-parse 81ee8836445ac888d99da8b652be7d5cbc5c4d5c:internal/lfsutil/storage.go
git -C "$GOGS" show --format='%B' 5e6014c421f7e3ab1d541983372377331aa4bf7a | head
git -C "$GOGS" show v0.14.2:internal/lfsutil/storage.go | sed -n '77,82p'
git -C "$GOGS" show v0.14.3:internal/lfsutil/storage.go | sed -n '77,90p'
git -C "$GOGS" log -1 --format='%H %s%n%b' e2fae5d0455d4f92c6382433d21c3a16da077d64

python3 {OWNED / "emit_artifacts.py"}
"""
    (OWNED / "replay.txt").write_text(replay, encoding="utf-8")

    report = f"""# G-J commit-first GHSA discovery (bounded)

Status: **TERMINAL / HOLD**. Proposed PASS = 1. Countable PASS = 0.
Worker PASS is a proposal only. The remaining G-J assignment is UNREVIEWED, not REJECT.

Contract SHA256: `{CONTRACT}`
Advisory-database freeze: `{ADV_HEAD}` (`2026-08-13T20:57:17+00:00`, origin/main at freeze).

Independence: frozen packet `autoresearch/herdr-260813-ghsa200-commitfirst-gn/`, first-party `github/advisory-database`, official GitHub advisory/release pages, and git history under `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn`. Sibling worker proposals were not used as evidence. Shared tracked files were not edited. No commit, push, or credential output.

## Verdict

This shard proposes one first-party GHSA, `GHSA-6P9M-Q3JP-47H4` in `gogs/gogs`, as `AI_INCOMPLETE_REMEDIATION` of the LFS upload hash boundary. Claude-authored PR #8166 members added a no-hash exist/dedupe shortcut that lets `serveUpload` bind another tenant's OID. `v0.14.2` contains that shortcut blob. `v0.14.3` hashes the body on the same shortcut. The proposal is not admitted here.

Twenty-nine other ranked identities are REJECT. Exact SHA advisory-ref AND AI-commit hits for G-J were already in the G-N packet `cases.jsonl` (44/44). This worker did not re-review them.

## Selection algorithm

1. Population: frozen G-N `assigned.jsonl` whose repository owner casefolds to G, H, I, or J.
2. Exclude every identity already present in frozen G-N `cases.jsonl` (this also drops baseline/final-review G-J IDs `GHSA-G39V-CVJH-8FPF` and `GHSA-PF93-J98V-25PV`).
3. Exact SHA intersections of advisory `commit_refs` with the frozen AI-commit scan: 44 G-J rows, all already reviewed. Remaining exact-SHA pool = 0.
4. Rank remaining unreviewed G-J rows that still have advisory commit refs by an exact *file* intersection: AI-marked commits in `git log` of files changed by `parent(advisory_commit_ref)`, with line-blame refinement when the diff is small.
5. Order: blame evidence before file-history, non-fix subjects before fix-like subjects, blamed-line count, then GHSA id.
6. Deep-review the first 30 distinct GHSA identities only. Do not infer dispositions for the rest.

Routing from commit/reference/name overlap is never causal proof.

## Population conservation

Owner rule for this shard: first character of the repository owner, casefolded, in `g`-`j` inclusive, inside the frozen G-N assignment.

| Set | Count |
|---|---:|
| Frozen G-N assigned | 2577 |
| G-N assigned with owner G-J | 1072 |
| G-J already in G-N `cases.jsonl` | {gj_already} |
| G-J unreviewed pool entering this worker | {gj_unreviewed_pool} |
| Ranked by fix-file AI intersection | {rank["ranked"]} |
| Deep-reviewed here (cap 30) | {reviewed_here} |
| G-J still UNREVIEWED after this worker | {still_unreviewed} |
| Exact SHA G-J intersections remaining unreviewed | 0 |

G-N conservation from the freeze remains `46 excluded + 2577 assigned = 2623` G-N window-active. This worker does not re-parse advisories.

G-J owner split of assigned: G 449, H 191, I 251, J 181.

Skipped among the 1025 unreviewed (ranking, not review): no commit refs 512, no AI commits 113, no AI intersection with fix files 306. Those skips are UNREVIEWED.

## Deep-reviewed rows

| Worker verdict | Rows |
|---|---:|
| PASS (proposal only) | 1 |
| REJECT | 29 |
| NARROW | 0 |
| UNKNOWN | 0 |
| BLOCKED | 0 |
| Unresolved G-J (UNREVIEWED) | {still_unreviewed} |

### Proposed PASS

**GHSA-6P9M-Q3JP-47H4** / `CVE-2026-52812` (`gogs/gogs`) — `AI_INCOMPLETE_REMEDIATION`.
PR #8166 member `85ebf175c0f953253247717f72f50fd6aba2d362` is marked `Co-Authored-By: Claude Opus 4.6` and, while adding SHA-256 verification for new LFS objects, adds an O_EXCL exist-path that drains the body and returns success so a second repository can bind the OID. Member `90f99d5f672ba95cf8cdb1a1d915acb079adb5ef` (same Claude trailer) rewrites that path into the shipped `os.Stat` shortcut. Squash carrier `81ee8836445ac888d99da8b652be7d5cbc5c4d5c` has the same trailer on every security member. Release-line carrier `5e6014c421f7e3ab1d541983372377331aa4bf7a` has identical patch-id `9e3a66e9446ff29bfdeb688f73e83c3bffe65d6b` and identical `internal/lfsutil/storage.go` blob `b53522f10a33f5021b005c6577a8492ecd1202fc` as `v0.14.2` (published 2026-02-19, not prerelease). `v0.14.3` (published 2026-06-07) contains cherry-pick `e2fae5d0455d4f92c6382433d21c3a16da077d64` of minimum fix `f35a767af74e05342bafc6fdda02c791816426f8`, which hashes the request body on that same shortcut. Removing the AI exist/dedupe success path eliminates the unhashed OID bind. This is distinct from changelog sibling `GHSA-gmf8-978x-2fg2` (pre-8166 overwrite without any hash).

### REJECT (bounded rank)

Exact-SHA AI-fix intersections were already reviewed in the G-N packet. The 29 rejects here are the next-strongest unreviewed G-J file/blame intersections. Typical failures: AI marker on a squash carrier or non-mechanism hunk; old-bug preservation; sibling-path incomplete language; package rename; documentation-only blame.

Notable: `GHSA-6R28-9PPF-4HJ5` (gopacket Diameter underflow) would have been origin-shaped, but Copilot appears only on `layers/ports.go` member `6de0ba93cfa9`; the AVP decoder member is unmarked. Squash branding is not transferred.

## Hold reason

Seven-gate review covered 30 of 1025 unreviewed G-J identities. Status stays HOLD. Unresolved rows are UNREVIEWED.

## Claim boundary

- Countable PASS requires all seven gates on a first-party GHSA case and leader admission.
- Proposed PASS: **1**. Countable PASS: **0**.
- REJECT is preserved. Absence of review is not negative proof.
- Routing, branding, OSV `introduced`, commit subjects, and ancestry alone are never causal proof.
- Incomplete remediation is labeled `AI_INCOMPLETE_REMEDIATION` and required `remediation_patch_delta_gate`.
- No tracked file or other worker directory was edited.
"""
    (OWNED / "report.md").write_text(report, encoding="utf-8")

    result = {
        "advisory_database": gn_result["advisory_database"],
        "assignment_conservation": {
            "gn_assigned": 2577,
            "gn_excluded": 46,
            "gn_window_active": 2623,
            "gj_assigned": len(gj),
            "gj_already_in_gn_cases": gj_already,
            "gj_unreviewed_pool": gj_unreviewed_pool,
            "gj_ranked_fix_file_intersections": rank["ranked"],
            "gj_deep_reviewed": reviewed_here,
            "gj_still_unreviewed": still_unreviewed,
            "exact_sha_gj_unreviewed": 0,
            "exact_sha_gj_already_reviewed": 44,
            "arithmetic_gj": gj_already + gj_unreviewed_pool == len(gj),
            "arithmetic_reviewed_split": reviewed_here + still_unreviewed == gj_unreviewed_pool,
        },
        "blockers": [
            "Status is HOLD: seven-gate review covered 30 of 1025 unreviewed G-J identities.",
            "All 44 G-J exact SHA advisory-ref AND AI-commit hits were already in the frozen G-N cases.jsonl.",
            "One proposed PASS remains uncounted pending independent leader review.",
            "Gopacket Diameter underflow was not promoted because Copilot authored only ports.go.",
        ],
        "claim_boundary": {
            "countable_pass": 0,
            "excluded_signals": [
                "keyword routing",
                "advisory-cited AI fix SHAs alone",
                "OSV introduced fields",
                "commit subjects",
                "ancestry alone",
                "sibling-path incomplete fixes",
                "squash branding transfer",
            ],
            "unresolved_is": "UNREVIEWED, not REJECT",
            "worker_PASS": "proposal only; leader must independently verify",
        },
        "clone_dir": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn",
        "contract_sha256": CONTRACT,
        "counts": {
            "BLOCKED": 0,
            "NARROW": 0,
            "PASS": 1,
            "REJECT": 29,
            "UNKNOWN": 0,
            "gj_assigned": len(gj),
            "gj_unreviewed_pool": gj_unreviewed_pool,
            "countable_pass": 0,
            "proposed_acceptances": 1,
            "reviewed_case_rows": 30,
            "shared_paths_mutated": 0,
            "unresolved_unreviewed": still_unreviewed,
        },
        "coverage_complete": False,
        "ended_at": ENDED,
        "english_only": True,
        "hold": True,
        "input_hashes": input_hashes,
        "lane": LANE,
        "lane_exhaustive": False,
        "output_dir": str(OWNED),
        "proposed_acceptances_are_uncounted": True,
        "schema_version": 1,
        "selection_algorithm": rank["algorithm"],
        "shared_paths_mutated": 0,
        "started_at": STARTED,
        "status": "TERMINAL",
        "task": "commit-first discovery, repository owner initial G-J inclusive, unreviewed remainder of frozen G-N packet, cap 30",
        "worker_pass_is_proposal_only": True,
    }
    # artifact hashes after writing cases/report/replay
    result["artifact_hashes"] = {
        "cases.jsonl": sha256_file(OWNED / "cases.jsonl"),
        "report.md": sha256_file(OWNED / "report.md"),
        "replay.txt": sha256_file(OWNED / "replay.txt"),
        "origin-rank.json": sha256_file(OWNED / "origin-rank.json"),
        "origin-rank.jsonl": sha256_file(OWNED / "origin-rank.jsonl"),
    }
    (OWNED / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "PASS": 1, "REJECT": 29, "unreviewed": still_unreviewed, "out": str(OWNED)}, indent=2))


if __name__ == "__main__":
    main()
