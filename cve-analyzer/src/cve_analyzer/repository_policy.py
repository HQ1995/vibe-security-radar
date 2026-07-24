"""Repository role and cost classification for token-free discovery.

Repository role answers whether a URL points at vulnerable code or merely at
advisory metadata.  Cost class is deliberately orthogonal: a large repository
is expensive, not valueless.
"""

from __future__ import annotations

import re
from enum import StrEnum


class RepositoryRole(StrEnum):
    CODE_CANDIDATE = "code_candidate"
    METADATA_ONLY = "metadata_only"


class RepositoryCostClass(StrEnum):
    STANDARD = "standard"
    HEAVYWEIGHT = "heavyweight"


_METADATA_REPOSITORY_PATTERN = re.compile(
    r"advisory[_-]?(database|db)|"
    r"security[_-]?advisories|"
    r"vulndb|"
    r"github\.com/github/advisory-database|"
    r"cvelistV5|"
    r"cve-?assign(?:e?ment|ment)|"
    r"cve-?tracker|"
    r"advisory/advisories|"
    r"vuln-?list|"
    r"security-?tracker|"
    r"vulnerability-?reports?|"
    r"osv-?datasets|"
    r"ubuntu-cve-tracker",
    re.IGNORECASE,
)

_HEAVYWEIGHT_REPOSITORY_PATTERN = re.compile(
    r"git\.kernel\.org/|"
    r"github\.com/torvalds/linux|"
    r"github\.com/gregkh/linux|"
    r"chromium\.googlesource\.com|"
    r"github\.com/chromium/chromium",
    re.IGNORECASE,
)


def repository_role(repo_url: str) -> RepositoryRole:
    """Classify advisory databases separately from possible vulnerable code."""

    if _METADATA_REPOSITORY_PATTERN.search(repo_url):
        return RepositoryRole.METADATA_ONLY
    return RepositoryRole.CODE_CANDIDATE


def repository_cost_class(repo_url: str) -> RepositoryCostClass:
    """Return scheduling cost without changing discovery eligibility."""

    if _HEAVYWEIGHT_REPOSITORY_PATTERN.search(repo_url):
        return RepositoryCostClass.HEAVYWEIGHT
    return RepositoryCostClass.STANDARD


def is_metadata_repository(repo_url: str) -> bool:
    return repository_role(repo_url) is RepositoryRole.METADATA_ONLY


def is_heavyweight_repository(repo_url: str) -> bool:
    return repository_cost_class(repo_url) is RepositoryCostClass.HEAVYWEIGHT
