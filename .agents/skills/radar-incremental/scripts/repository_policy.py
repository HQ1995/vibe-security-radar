from __future__ import annotations

import re

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


def is_metadata_repository(repo_url: str) -> bool:
    return bool(_METADATA_REPOSITORY_PATTERN.search(repo_url))
