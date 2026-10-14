"""Multi-host git URL parser for GitHub, GitLab, and Bitbucket.

Single source of truth for extracting commit, PR/MR, and repo information
from URLs across all supported git hosting platforms.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class GitCommitRef:
    """Parsed commit URL from any supported host."""

    host: str  # "github.com", "gitlab.gnome.org", etc.
    owner: str  # owner or group path (may contain slashes for GitLab)
    repo: str
    sha: str
    repo_url: str  # reconstructed canonical repo URL


@dataclass(frozen=True)
class GitPrRef:
    """Parsed PR/MR URL from any supported host."""

    host: str
    owner: str
    repo: str
    number: int
    repo_url: str

    @property
    def url(self) -> str:
        """Reconstruct the canonical PR/MR URL."""
        if self.host == "github.com":
            return f"https://github.com/{self.owner}/{self.repo}/pull/{self.number}"
        if self.host == "bitbucket.org":
            return f"https://bitbucket.org/{self.owner}/{self.repo}/pull-requests/{self.number}"
        # GitLab (any host)
        return f"https://{self.host}/{self.owner}/{self.repo}/-/merge_requests/{self.number}"


# Self-hosted GitLab instances commonly seen in CVE data.
# Only matches gitlab.* domains — git.* hosts (git.kernel.org, etc.) use
# different URL schemes (cgit, gitweb) and are not GitLab.
_GITLAB_SELF_HOSTED_RE = re.compile(r"^gitlab\.[a-z0-9.-]+$", re.IGNORECASE)

# Some public Git servers expose a repository directly below the host rather
# than under an owner/group path.  Keep this allowlist narrow: generic hosts
# still require at least ``owner/repo`` so arbitrary web paths are not treated
# as repository identities.
_GENERIC_SINGLE_COMPONENT_REPO_HOSTS = frozenset({"git.ffmpeg.org"})

# GitLab browsing paths below a project. Modern GitLab puts all of these
# behind ``/-/``, which is stripped separately; these markers catch the
# pre-2019 unprefixed routes that self-hosted instances still serve (GNOME,
# freedesktop.org, ow2.org and others in real advisory data use them). Without
# this, e.g. ``gitlab.gnome.org/GNOME/glib/commit/<sha>`` parses as owner
# ``GNOME/glib/commit`` and repo ``<sha>`` instead of being recognised as a
# browsing URL for GNOME/glib.
_GITLAB_PROJECT_SUFFIX_MARKERS = (
    "/tree/",
    "/blob/",
    "/raw/",
    "/tags",
    "/releases",
    "/commit/",
    "/commits/",
    "/compare/",
    "/issues/",
    "/merge_requests/",
    "/wikis/",
    "/pipelines/",
)


def _strip_gitlab_browsing_suffix(path: str) -> str:
    """Cut a GitLab project path at the first browsing-suffix marker."""

    project_path = path.split("/-/", 1)[0]
    for marker in _GITLAB_PROJECT_SUFFIX_MARKERS:
        project_path = project_path.split(marker, 1)[0]
    return project_path

_SCP_REPO_RE = re.compile(r"^(?:(?P<user>[^/@:\s]+)@)?(?P<host>[^/:\s]+):(?P<path>[^\s]+)$")
_REPO_URL_SCHEMES = frozenset({"http", "https", "ssh", "git+ssh", "git"})
_DEFAULT_PORTS = {"http": 80, "https": 443, "ssh": 22, "git+ssh": 22, "git": 9418}

# GitHub reserves these top-level routes for product pages and account-wide
# features.  Treating them as repository owners turns advisory/package links
# into clone targets and silently reduces analysis coverage.
_GITHUB_NON_REPO_OWNERS = frozenset(
    {
        "advisories",
        "apps",
        "blog",
        "collections",
        "contact",
        "customer-stories",
        "events",
        "explore",
        "features",
        "github",
        "login",
        "marketplace",
        "new",
        "notifications",
        "orgs",
        "pricing",
        "pulls",
        "readme",
        "search",
        "security",
        "settings",
        "signup",
        "site",
        "sponsors",
        "topics",
    }
)


def _is_github_repository_owner(owner: str) -> bool:
    return owner.lower() not in _GITHUB_NON_REPO_OWNERS


def _transport_location(url: str) -> tuple[str, str] | None:
    """Extract a normalized host and raw path from common Git transports."""
    raw = url.strip()
    if not raw or any(character in raw for character in ("\x00", "\r", "\n")):
        return None

    if "://" not in raw:
        scp_match = _SCP_REPO_RE.fullmatch(raw)
        if scp_match:
            host = scp_match.group("host").lower()
            path = scp_match.group("path").strip("/")
            return (host, path) if path else None
        raw = f"https://{raw}"

    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in _REPO_URL_SCHEMES or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        host = f"{host}:{port}"
    path = parsed.path.strip("/")
    return (host, path) if path else None


def _split_gitlab_path(path: str) -> tuple[str, str]:
    """Split a GitLab group/repo path into (owner, repo).

    GitLab supports nested groups: ``group/subgroup/repo``.
    The last component is the repo name; everything before is the owner/group.
    """
    parts = path.rstrip("/").split("/")
    if len(parts) < 2:
        return ("", parts[0] if parts else "")
    return ("/".join(parts[:-1]), parts[-1])


def _valid_gitlab_project_path(path: str) -> bool:
    parts = path.strip("/").split("/")
    return len(parts) >= 2 and all(
        part not in {"", ".", ".."} and ":" not in part and "\\" not in part for part in parts
    )


def parse_commit_url(url: str) -> GitCommitRef | None:
    """Parse a commit URL from GitHub, GitLab, or Bitbucket.

    Returns a GitCommitRef with host, owner, repo, sha, and repo_url,
    or None if the URL doesn't match any known pattern.
    """
    location = _transport_location(url)
    if location is None:
        return None
    host, path = location

    if host == "github.com":
        m = re.fullmatch(
            r"([^/]+)/([^/]+)/commit/([0-9a-fA-F]{6,40})(?:/.*)?",
            path,
        )
        if m and _is_github_repository_owner(m.group(1)):
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            return GitCommitRef(
                host="github.com",
                owner=owner,
                repo=repo,
                sha=sha,
                repo_url=f"https://github.com/{owner}/{repo}",
            )
        return None

    if host == "bitbucket.org":
        m = re.fullmatch(
            r"([^/]+)/([^/]+)/commits/([0-9a-fA-F]{6,40})(?:/.*)?",
            path,
        )
        if m:
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            return GitCommitRef(
                host="bitbucket.org",
                owner=owner,
                repo=repo,
                sha=sha,
                repo_url=f"https://bitbucket.org/{owner}/{repo}",
            )
        return None

    m = re.fullmatch(
        r"(.+?)/-/commit/([0-9a-fA-F]{6,40})(?:/.*)?",
        path,
    )
    if m:
        project_path, sha = m.group(1), m.group(2)
        if not _valid_gitlab_project_path(project_path):
            return None
        owner, repo = _split_gitlab_path(project_path)
        return GitCommitRef(
            host=host,
            owner=owner,
            repo=repo,
            sha=sha,
            repo_url=f"https://{host}/{owner}/{repo}",
        )

    return None


def parse_pr_url(url: str) -> GitPrRef | None:
    """Parse a PR/MR URL from GitHub, GitLab, or Bitbucket.

    Returns a GitPrRef or None if the URL doesn't match.
    """
    location = _transport_location(url)
    if location is None:
        return None
    host, path = location

    if host == "github.com":
        m = re.fullmatch(r"([^/]+)/([^/]+)/pull/(\d+)(?:/.*)?", path)
        if m and _is_github_repository_owner(m.group(1)):
            owner, repo, number = m.group(1), m.group(2), int(m.group(3))
            return GitPrRef(
                host="github.com",
                owner=owner,
                repo=repo,
                number=number,
                repo_url=f"https://github.com/{owner}/{repo}",
            )
        return None

    if host == "bitbucket.org":
        m = re.fullmatch(
            r"([^/]+)/([^/]+)/pull-requests/(\d+)(?:/.*)?",
            path,
        )
        if m:
            owner, repo, number = m.group(1), m.group(2), int(m.group(3))
            return GitPrRef(
                host="bitbucket.org",
                owner=owner,
                repo=repo,
                number=number,
                repo_url=f"https://bitbucket.org/{owner}/{repo}",
            )
        return None

    m = re.fullmatch(r"(.+?)/-/merge_requests/(\d+)(?:/.*)?", path)
    if m:
        project_path, number = m.group(1), int(m.group(2))
        if not _valid_gitlab_project_path(project_path):
            return None
        owner, repo = _split_gitlab_path(project_path)
        return GitPrRef(
            host=host,
            owner=owner,
            repo=repo,
            number=number,
            repo_url=f"https://{host}/{owner}/{repo}",
        )

    return None


def parse_repo_url(url: str) -> tuple[str, str, str] | None:
    """Extract (host, owner, repo) from any supported git hosting URL.

    Handles GitHub, GitLab (public + self-hosted), and Bitbucket.
    Strips trailing ``.git`` suffix from repo name.
    Returns None if the URL doesn't match any known host pattern.
    """
    location = _transport_location(url)
    if location is None:
        return None
    host, path = location

    if host == "github.com":
        ref = parse_commit_url(url)
        if ref and _is_github_repository_owner(ref.owner):
            return (ref.host, ref.owner, ref.repo)
        pr = parse_pr_url(url)
        if pr and _is_github_repository_owner(pr.owner):
            return (pr.host, pr.owner, pr.repo)
        parts = path.split("/")
        if len(parts) >= 2 and _is_github_repository_owner(parts[0]):
            repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
            if repo:
                return (host, parts[0], repo)
        return None

    if host == "bitbucket.org":
        ref = parse_commit_url(url)
        if ref:
            return (ref.host, ref.owner, ref.repo)
        pr = parse_pr_url(url)
        if pr:
            return (pr.host, pr.owner, pr.repo)
        parts = path.split("/")
        if len(parts) >= 2:
            repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
            if repo:
                return (host, parts[0], repo)
        return None

    if host == "gitlab.com":
        ref = parse_commit_url(url)
        if ref:
            return (ref.host, ref.owner, ref.repo)
        pr = parse_pr_url(url)
        if pr:
            return (pr.host, pr.owner, pr.repo)
        project_path = _strip_gitlab_browsing_suffix(path)
        if project_path.endswith(".git"):
            project_path = project_path[:-4]
        if _valid_gitlab_project_path(project_path):
            owner, repo = _split_gitlab_path(project_path)
            return (host, owner, repo)
        return None

    ref = parse_commit_url(url)
    if ref:
        return (ref.host, ref.owner, ref.repo)
    pr = parse_pr_url(url)
    if pr:
        return (pr.host, pr.owner, pr.repo)

    is_gitlab_location = "/-/" in path or _GITLAB_SELF_HOSTED_RE.fullmatch(host)
    project_path = _strip_gitlab_browsing_suffix(path) if is_gitlab_location else path
    if project_path.endswith(".git"):
        project_path = project_path[:-4]
    if is_gitlab_location and _valid_gitlab_project_path(project_path):
        owner, repo = _split_gitlab_path(project_path)
        return (host, owner, repo)

    return None


def normalize_repo_identity(url: str) -> tuple[str, str] | None:
    """Return a transport-independent, lowercase ``(host, repo_path)``.

    Known GitHub, GitLab, and Bitbucket URLs use :func:`parse_repo_url` so
    browsing suffixes such as ``/tree`` and ``/-/commit`` are excluded.  Base
    repository origins on other hosts still normalize safely when they use
    HTTP(S), SSH, Git, or SCP-like syntax.
    """
    parsed = parse_repo_url(url)
    if parsed is not None:
        host, owner, repo = parsed
        path = f"{owner.strip('/')}/{repo.strip('/')}"
    else:
        location = _transport_location(url)
        if location is None:
            return None
        host, path = location

    if host.lower() == "github.com":
        owner = path.lstrip("/").partition("/")[0]
        if not _is_github_repository_owner(owner):
            return None

    if path.lower().endswith(".git"):
        path = path[:-4]
    parts = path.strip("/").split("/")
    if (
        (len(parts) < 2 and host.lower() not in _GENERIC_SINGLE_COMPONENT_REPO_HOSTS)
        or any(
            not part or part in {".", ".."} or "\\" in part for part in parts
        )
    ):
        return None
    return host.lower(), "/".join(part.lower() for part in parts)


def is_github(ref: GitCommitRef | GitPrRef) -> bool:
    """Check if a parsed ref is on GitHub (needed for API-dependent features)."""
    return ref.host == "github.com"
