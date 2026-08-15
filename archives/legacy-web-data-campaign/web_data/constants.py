"""Shared constants for web data generation."""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Cache / output paths
# ---------------------------------------------------------------------------

DEFAULT_CACHE_DIR = os.path.expanduser("~/.cache/cve-analyzer/results")
DEFAULT_REVIEWS_DIR = os.path.expanduser("~/.cache/cve-analyzer/reviews")
DEFAULT_NVD_FEEDS_DIR = os.path.expanduser("~/.cache/cve-analyzer/nvd-feeds")
DEFAULT_GHSA_DB_DIR = os.path.expanduser(
    "~/.cache/cve-analyzer/advisory-database/advisories"
)
DEFAULT_REPOS_DIR = os.path.expanduser("~/.cache/cve-analyzer/repos")
DEFAULT_OUTPUT_DIR = str(Path(__file__).resolve().parent.parent.parent / "web" / "data")

# ---------------------------------------------------------------------------
# File extension → language mapping
# ---------------------------------------------------------------------------

EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".java": "Java",
    ".kt": "Kotlin",
    ".php": "PHP",
    ".c": "C/C++",
    ".h": "C/C++",
    ".cpp": "C/C++",
    ".cc": "C/C++",
    ".cxx": "C/C++",
    ".hpp": "C/C++",
    ".hxx": "C/C++",
    ".cs": "C#",
    ".swift": "Swift",
    ".vue": "Vue",
    ".dart": "Dart",
    ".scala": "Scala",
    ".r": "R",
    ".lua": "Lua",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".zig": "Zig",
    ".nim": "Nim",
    ".pl": "Perl",
    ".pm": "Perl",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".sql": "SQL",
    ".sol": "Solidity",
    ".tf": "Terraform",
    ".hcl": "Terraform",
}

# Template/config extensions that need project-level language inference.
TEMPLATE_EXTENSIONS = frozenset({
    ".html", ".htm",
    ".xml", ".xsl", ".xslt",
    ".yaml", ".yml",
    ".json",
    ".erb",
    ".ejs",
    ".hbs",
    ".twig",
    ".j2", ".jinja", ".jinja2",
})

# ---------------------------------------------------------------------------
# Signal filtering
# ---------------------------------------------------------------------------

# Strong signal types that qualify "unknown_ai" for display
STRONG_SIGNAL_TYPES = frozenset({
    "co_author_trailer", "co_author_trailer_generic",
    "author_email", "committer_email",
})

# String confidence → numeric for web UI (formatConfidence expects 0-1)
CONFIDENCE_STR_TO_NUMERIC: dict[str, float] = {
    "high": 0.95,
    "medium": 0.7,
    "low": 0.4,
}
