#!/usr/bin/env python3
"""Close the three remaining Gogs causal chains (shard-042 NOT_AI verdicts)."""

from collections import Counter
from pathlib import Path
import json
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
AUDIT = ROOT / ".ai-slop/state/notai-review/notai-causal-gate-v4-20260819.jsonl"
SUMMARY = ROOT / "artifacts/ledger-summary.md"
BACKUP = ROOT / "artifacts/funnel-account-20260817.jsonl.bak-gogs-remaining-20260823"
SHARD = ROOT / ".ai-slop/state/partial-wave/results/shard-042-out.jsonl"

SHARD_ROWS = {r["class_id"]: r for r in (json.loads(l) for l in SHARD.read_text(encoding="utf-8").splitlines() if l.strip())}

DOSSIERS = {
    "alias-771f47230669a59d649529ec": {
        "class_id": "alias-771f47230669a59d649529ec",
        "repo": "gogs/gogs",
        "advisory_ids": ["CVE-2026-52797", "GHSA-PM6V-2H4W-4RP2"],
        "bug_semantics": (
            "DiffPreviewPost interpolated c.Repo.TreePath into an exec.Command(\"git\", \"diff\", treePath)"
            " call. An attacker-controlled tree path could inject git options (option injection),"
            " enabling a git denial of service or unintended git behavior."
        ),
        "flaw_origin": (
            "Human commit 01c8df01ec0608f1f25b2f1444adabb98fa5ee8a (\"internal: move packages under"
            " this directory (#5836)\", Joe Chen, 2019-10-24) introduced the DiffPreviewPost handler"
            " with the exec.Command(\"git\", \"diff\", treePath) sink."
        ),
        "introducer_sha": "01c8df01ec0608f1f25b2f1444adabb98fa5ee8a",
        "introducer_parent": None,
        "introducer_parent_absent": False,
        "squash_decomposed": False,
        "decomposed_shas": [],
        "ai_marker": (
            "The atomic introducer is authored by Joe Chen and has no AI trailer. The direct fix"
            " 68b3c8f339bc90667dba78d9370d73c69a739093 is authored by Joe Chen and also has no AI"
            " trailer. No causal AI marker was found."
        ),
        "verdict": "NOT_AI",
        "fix_sha": "68b3c8f339bc90667dba78d9370d73c69a739093",
        "direct_fix_sha": "68b3c8f339bc90667dba78d9370d73c69a739093",
        "evidence": (
            "git log -- internal/route/repo/editor.go shows 01c8df01ec0 as the first commit where"
            " DiffPreviewPost appears with the exec.Command(\"git\", \"diff\", treePath) sink. Direct"
            " fix 68b3c8f339b (\"repo: ignore unintended Git options for diff preview (#7871)\")"
            " sanitizes c.Repo.TreePath via pathutil.Clean and adds '--end-of-options'. Both commits"
            " are single-parent and have no AI trailer."
        ),
        "reasoning": (
            "The vulnerability is the un-sanitized treePath passed to git diff, introduced when the"
            " preview handler was added, and closed by the fix that passes '--end-of-options'. Both"
            " the introducer and the direct fix are human-authored. This is a closed NOT_AI chain."
        ),
    },
    "alias-da4217b7b50e1d96c772489d": {
        "class_id": "alias-da4217b7b50e1d96c772489d",
        "repo": "gogs/gogs",
        "advisory_ids": ["CVE-2025-64111", "GHSA-GG64-XXR9-QHJP"],
        "bug_semantics": (
            "UpdateRepoFile did not reject path hierarchies containing a .git symlink. A PUT"
            " /contents API request with a path that traverses a .git symlink could write"
            " .git/config, leading to repository compromise (RCE)."
        ),
        "flaw_origin": (
            "Human commit 3650b32ec586dbf48a1b8f2f91f340368d1204fd is the blamed atomic introducer"
            " of the UpdateRepoFile behavior (2024-02-18) that lacked isRepositoryGitPath()"
            " enforcement; later refactors preserved the same behavior."
        ),
        "introducer_sha": "3650b32ec586dbf48a1b8f2f91f340368d1204fd",
        "introducer_parent": None,
        "introducer_parent_absent": False,
        "squash_decomposed": False,
        "decomposed_shas": [],
        "ai_marker": (
            "No causal AI marker. The direct fix c3eca1fca3a4750e55dfa6d9935564a897232858 (\"repository:"
            " reject any updates that has symlink in path hierarchy (#8082)\") is authored by Joe Chen;"
            " the introduced behavior predates AI-assisted development."
        ),
        "verdict": "NOT_AI",
        "fix_sha": "c3eca1fca3a4750e55dfa6d9935564a897232858",
        "direct_fix_sha": "c3eca1fca3a4750e55dfa6d9935564a897232858",
        "evidence": (
            "git blame on internal/database/repo_editor.go UpdateRepoFile attributes the sink to"
            " 3650b32ec58 (2024-02-18) before isRepositoryGitPath() existed. Direct fix c3eca1fca3a"
            " adds hasSymlinkInPath rejection and regression tests. Neither the introducer nor the"
            " fix carries an AI trailer."
        ),
        "reasoning": (
            "The vulnerability is the missing symlink-in-path hierarchy rejection in the repository"
            " contents writer, introduced by human code and closed by a human-authored fix. This is"
            " a closed NOT_AI chain."
        ),
    },
    "alias-df15c3c07b638f9f46d9acc0": {
        "class_id": "alias-df15c3c07b638f9f46d9acc0",
        "repo": "gogs/gogs",
        "advisory_ids": ["GHSA-6VXV-WG6J-5QWP"],
        "bug_semantics": (
            "Gogs rendered Jupyter Notebook (.ipynb) HTML via notebookjs 0.4.2 without routing the"
            " markdown/html through DOMPurify, allowing stored/reflected Web XSS in the notebook"
            " viewer."
        ),
        "flaw_origin": (
            "Human commit 9af0dd23dd6afc9b4103a8aeb17e6eba1c649f6c (\"Ipython notebook support (#4070)\","
            " Herbert, 2017-02-07) introduced the notebook rendering path with notebookjs 0.4.2 and no"
            " sanitization."
        ),
        "introducer_sha": "9af0dd23dd6afc9b4103a8aeb17e6eba1c649f6c",
        "introducer_parent": None,
        "introducer_parent_absent": False,
        "squash_decomposed": False,
        "decomposed_shas": [],
        "ai_marker": (
            "The atomic introducer is authored by Herbert in 2017 (PR #4070) and has no AI trailer."
            " The direct fix f6b8c5847deadf07fe40e2eb8568311715e5918a (\"security: upgrade notebookjs"
            " and route ipynb HTML through DOMPurify (#8330)\") is authored by Joe Chen and has no AI"
            " trailer. No causal AI marker was found."
        ),
        "verdict": "NOT_AI",
        "fix_sha": "f6b8c5847deadf07fe40e2eb8568311715e5918a",
        "direct_fix_sha": "f6b8c5847deadf07fe40e2eb8568311715e5918a",
        "evidence": (
            "templates/base/head.tmpl and templates/repo/view_file.tmpl show the notebookjs 0.4.2"
            " include introduced by 9af0dd23dd6 (2017). Direct fix f6b8c5847de upgrades notebookjs to"
            " 0.8.3 and routes ipynb HTML through DOMPurify 3.4.8. Neither commit carries an AI trailer."
        ),
        "reasoning": (
            "The vulnerability is the unsanitized notebook HTML rendering introduced in 2017, before"
            " AI-assisted development, and closed by a human-authored DOMPurify fix. This is a closed"
            " NOT_AI chain."
        ),
    },
}

def load(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def main():
    rows = load(LEDGER)
    assert len(rows) == 23861
    by_class = {row["class_id"]: row for row in rows}
    assert len(by_class) == 23861
    for cid, dossier in DOSSIERS.items():
        assert cid in by_class, f"missing class_id: {cid}"
        row = by_class[cid]
        assert row["repo"] == "gogs/gogs", cid
        assert row.get("status") == "PARTIALLY_ANALYZED", f"{cid} status {row.get('status')}"
        assert row.get("partial_wave_verdict") == "NOT_AI", cid
        assert cid in SHARD_ROWS, f"missing shard row: {cid}"

    shutil.copy2(LEDGER, BACKUP)
    for cid, dossier in DOSSIERS.items():
        row = by_class[cid]
        row["status"] = "NOT_AI"
        row["partial_wave_verdict"] = "NOT_AI"
        row["causal_research"] = dossier
        row["notai_causal_review_refreshed"] = "2026-08-23-gogs-remaining"
        row["notai_review_state"] = "CONFIRMED_NOT_AI"
        row["notai_review_refreshed"] = "2026-08-23-gogs-remaining"
        row["notai_causal_review_status"] = "MECHANISM_AND_ATTRIBUTION_CLOSED"
        row["notai_attribution_status"] = "NOT_AI_CONFIRMED"
        row["notai_causal_review_status_source"] = "shard-042-out.jsonl"

    out = "\n".join(json.dumps(r, ensure_ascii=False, sort_keys=True) for r in rows) + "\n"
    tmp = ROOT / ".ai-slop/state/.gogs-remaining-write.tmp"
    tmp.write_text(out, encoding="utf-8")
    tmp.replace(LEDGER)

    counts = Counter(r["status"] for r in rows)
    assert counts["NOT_AI"] == 212, counts
    assert counts["PARTIALLY_ANALYZED"] == 5990, counts
    print(json.dumps(dict(counts), sort_keys=True))

if __name__ == "__main__":
    main()
