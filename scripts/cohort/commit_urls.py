"""Resolve commit URLs on git hosts that ``git_url.parse_commit_url`` skips.

The analyzer only understands GitHub, Bitbucket and GitLab commit URLs. That
is fine for advisories carrying a GIT range, but most Linux/GNU vulnerabilities
reach OSV through distro advisories whose only code pointer is a cgit, gitweb
or gitiles link. Measured on the local archives: 32,767 references to
git.kernel.org sat in advisories where no repository could be identified at
all, which silently excluded the kernel, coreutils, gawk, gzip, wget, bzip2 and
binutils from the frame.

Each parser returns ``(repository_identity, sha)`` so callers get the fix
commit for free alongside the repository.
"""

from __future__ import annotations

import re

# git.kernel.org/stable/c/<sha> is a redirector: the path names no repository,
# but it always resolves into the linux-stable tree.
KERNEL_STABLE_IDENTITY = "git.kernel.org/pub/scm/linux/kernel/git/stable/linux"

_SHA = r"[0-9a-fA-F]{7,40}"

_KERNEL_STABLE_RE = re.compile(rf"^https?://git\.kernel\.org/stable/c/({_SHA})/?$")
# cgit: <host>/[cgit/]<project>.git/commit/?id=<sha>
_CGIT_RE = re.compile(
    rf"^https?://([^/]+)/(?:cgit/)?(.+?)\.git/commit/\?id=({_SHA})",
)
# gitweb, path style: <host>/gitweb/<project>.git/commit/<sha>
_GITWEB_PATH_RE = re.compile(
    rf"^https?://([^/]+)/gitweb/(.+?)\.git/commit/({_SHA})",
)
# gitweb, query style: <host>/<script>?p=<project>.git;...;h=<sha>
_GITWEB_QUERY_RE = re.compile(
    rf"^https?://([^/]+)/([^?]*)\?.*?\bp=([^;&]+?)\.git\b.*?\bh=({_SHA})",
)
# gitiles: <host>/<project>/+/<sha>
_GITILES_RE = re.compile(
    rf"^https?://([^/]+)/(.+?)/\+/({_SHA})",
)
# cgit/gitweb tree or plain commit path without the ?id= form:
# <host>/pub/scm/<project>.git/commit/?id=<sha> is covered by _CGIT_RE; this
# handles <host>/<project>.git/commit/<sha>
_BARE_COMMIT_RE = re.compile(
    rf"^https?://([^/]+)/(.+?)\.git/commit/({_SHA})",
)


def _identity(host: str, path: str) -> str:
    return f"{host}/{path.strip('/')}".casefold()


def parse_foreign_commit_url(url: str) -> tuple[str, str] | None:
    """Return ``(repository_identity, sha)`` for a non-GitHub commit URL.

    Returns ``None`` when the URL is not a recognisable commit link, which is
    the common case: bug trackers, distro advisories and package pages must not
    be mistaken for repositories.
    """

    if not url or "://" not in url:
        return None

    match = _KERNEL_STABLE_RE.match(url)
    if match:
        return KERNEL_STABLE_IDENTITY, match.group(1).lower()

    for pattern in (_CGIT_RE, _GITWEB_PATH_RE, _BARE_COMMIT_RE):
        match = pattern.match(url)
        if match:
            host, path, sha = match.group(1), match.group(2), match.group(3)
            return _identity(host, path), sha.lower()

    match = _GITWEB_QUERY_RE.match(url)
    if match:
        host, script, project, sha = match.groups()
        # Drop the CGI entry point (git/, git/gitweb.cgi) from the identity so
        # the same project reached through different scripts collapses to one.
        prefix = re.sub(r"[^/]*\.cgi$", "", script).strip("/")
        path = f"{prefix}/{project}" if prefix else project
        return _identity(host, path), sha.lower()

    match = _GITILES_RE.match(url)
    if match:
        host, path, sha = match.group(1), match.group(2), match.group(3)
        if not path.endswith(("/+log", "/+doc")):
            return _identity(host, path), sha.lower()

    return None
