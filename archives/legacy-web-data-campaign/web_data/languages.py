"""Language inference for CVE web data generation.

Maps file extensions to programming languages and infers project language
from bug-commit blamed files and fix-commit diffs.
"""

from __future__ import annotations

import os
import subprocess

from web_data.constants import (
    DEFAULT_REPOS_DIR,
    EXTENSION_TO_LANGUAGE,
    TEMPLATE_EXTENSIONS,
)


def _file_extension_to_language(filepath: str) -> str | None:
    """Map a file path to a programming language via its extension.

    Returns None if the extension is not recognized.
    """
    if not filepath:
        return None
    # GitHub Actions composite actions (action.yml / action.yaml)
    basename = os.path.basename(filepath).lower()
    if basename in ("action.yml", "action.yaml"):
        return "GitHub Actions"
    ext = os.path.splitext(filepath)[1].lower()
    return EXTENSION_TO_LANGUAGE.get(ext)


def _fix_commit_files(fix_commits: list[dict], repos_dir: str) -> list[str]:
    """Get changed file paths from fix commits using local repo clones."""
    files: list[str] = []
    for fc in fix_commits:
        repo_url = fc.get("repo_url", "")
        sha = fc.get("sha", "")
        if not repo_url or not sha:
            continue
        # Derive local repo dir: owner_repo from URL
        parts = repo_url.rstrip("/").split("/")
        if len(parts) >= 2:
            repo_dir = os.path.join(repos_dir, f"{parts[-2]}_{parts[-1]}")
            if os.path.isdir(repo_dir):
                try:
                    out = subprocess.run(
                        ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", sha],
                        cwd=repo_dir, capture_output=True, text=True, timeout=10,
                    )
                    if out.returncode == 0:
                        files.extend(line for line in out.stdout.strip().split("\n") if line)
                except Exception:
                    pass
    return files


def _infer_language_from_template(filepath: str, fix_commits: list[dict] | None,
                                   repos_dir: str) -> str | None:
    """Infer the project language when the blamed file is a template/config.

    Template files (.html, .yaml, etc.) don't have vulnerabilities on their
    own — the bug is in the server-side framework.  Infer the framework
    language from sibling files in the fix commit diff.
    """
    fix_files = _fix_commit_files(fix_commits, repos_dir) if fix_commits else []
    # Count languages from fix commit files
    lang_counts: dict[str, int] = {}
    for f in fix_files:
        lang = _file_extension_to_language(f)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    if lang_counts:
        return max(lang_counts, key=lang_counts.get)  # type: ignore[arg-type]
    # Heuristic from template type or path → likely framework
    ext = os.path.splitext(filepath)[1].lower()
    ext_hints = {
        ".erb": "Ruby", ".twig": "PHP", ".ejs": "JavaScript",
        ".j2": "Python", ".jinja": "Python", ".jinja2": "Python",
    }
    if ext in ext_hints:
        return ext_hints[ext]
    # Path-based hints for generic extensions like .html
    path_lower = filepath.lower()
    path_hints = [
        ("/templates/", "Python"),       # Django/Flask
        ("/views/", "PHP"),              # Laravel/PHP
        ("/resources/views/", "PHP"),    # Laravel
    ]
    for pattern, lang in path_hints:
        if pattern in path_lower:
            return lang
    return None


def determine_languages(
    bug_commits: list[dict],
    fix_commits: list | None = None,
    repos_dir: str = DEFAULT_REPOS_DIR,
) -> list[str]:
    """Extract sorted unique languages from blamed_file extensions in bug commits.

    For template/config files (.html, .yaml, etc.), infers the project
    language from fix commit diffs since the vulnerability is in the
    framework, not the template format itself.

    Falls back to fix commit diff files when blamed_file is a placeholder
    (e.g. osv_introduced strategy).
    """
    languages: set[str] = set()
    needs_inference: list[str] = []
    for bc in bug_commits:
        # blamed_file may be comma-separated when a SHA is blamed for multiple files
        for filepath in bc.get("blamed_file", "").split(", "):
            filepath = filepath.strip()
            if not filepath:
                continue
            lang = _file_extension_to_language(filepath)
            if lang:
                languages.add(lang)
            elif os.path.splitext(filepath)[1].lower() in TEMPLATE_EXTENSIONS:
                needs_inference.append(filepath)

    # Infer language for template files from project context
    if needs_inference and not languages:
        for filepath in needs_inference:
            lang = _infer_language_from_template(filepath, fix_commits, repos_dir)
            if lang:
                languages.add(lang)
                break

    # Fallback: infer from fix commit changed files
    if not languages and fix_commits:
        for filepath in _fix_commit_files(fix_commits, repos_dir):
            lang = _file_extension_to_language(filepath)
            if lang:
                languages.add(lang)

    return sorted(languages)
