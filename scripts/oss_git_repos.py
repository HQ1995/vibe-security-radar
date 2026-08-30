"""Cloneable OSS git identities from advisory URLs.

The simple funnel parser only keeps github.com/owner/repo, gitlab.com/group/project,
and any git.kernel.org link. This module adds Bitbucket, self-hosted GitLab,
googlesource/gitiles, cgit/gitweb, Savannah, and project ``git.*`` hosts.

CMS hosts that merely look like GitLab (``support.broadcom.com/.../-/``) are
dropped. Package names and CPE strings are not treated as repositories.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
_ANALYZER = _SCRIPTS.parent / "cve-analyzer" / "src"
for _path in (_SCRIPTS, _ANALYZER):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from cve_analyzer.git_url import parse_commit_url, parse_pr_url, parse_repo_url
from cve_analyzer.repository_policy import is_metadata_repository
from cohort.commit_urls import parse_foreign_commit_url

KERNEL_REPO = "git.kernel.org/pub/scm/linux/kernel/git/stable/linux"

DENY_HOSTS = frozenset(
    {
        "support.broadcom.com",
        "liferay.dev",
        "www.liferay.com",
        "nvd.nist.gov",
        "cve.mitre.org",
        "www.cve.org",
        "https",
    }
)

SKIP_GITHUB_OWNERS = frozenset(
    {
        "advisories",
        "apps",
        "cveproject",
        "gist",
        "github",
        "nvd",
        "orgs",
        "security",
        "sponsors",
        "users",
    }
)

FORGE_HOSTS = frozenset(
    {
        "github.com",
        "bitbucket.org",
        "gitlab.com",
        "codeberg.org",
        "framagit.org",
        "salsa.debian.org",
        "invent.kde.org",
        "code.videolan.org",
        "foss.heptapod.net",
        "pagure.io",
        "git.sr.ht",
        "sr.ht",
        "git.launchpad.net",
        "sourceware.org",
        "git.ffmpeg.org",
        "git.spip.net",
        "git.libssh.org",
        "git.haproxy.org",
        "git.u-boot-project.org",
        "git.dcmtk.org",
        "git.gnunet.org",
        "git.dpkg.org",
        "git.mahara.org",
        "git.hadrons.org",
        "git.samba.org",
        "git.linux-nfs.org",
        "git.kernel.org",
    }
)

FORGE_PREFIX = ("gitlab.", "cgit.", "gitweb.", "gerrit.")
FORGE_SUFFIX = (".googlesource.com",)


def collect_urls(obj: object) -> list[str]:
    """Pull every ``url`` / GIT ``repo`` string out of an advisory JSON blob."""
    urls: list[str] = []
    stack: list[object] = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            value = node.get("url")
            if isinstance(value, str) and value:
                urls.append(value)
            if node.get("type") == "GIT" and isinstance(node.get("repo"), str) and node["repo"]:
                urls.append(node["repo"])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return urls


def host_of(identity: str) -> str:
    return identity.split("/", 1)[0].lower()


def is_oss_git_host(host: str) -> bool:
    host = host.lower()
    if host in DENY_HOSTS:
        return False
    if host in FORGE_HOSTS:
        return True
    if any(host.startswith(prefix) for prefix in FORGE_PREFIX):
        return True
    if any(host.endswith(suffix) for suffix in FORGE_SUFFIX):
        return True
    if "savannah.gnu.org" in host or "savannah.nongnu.org" in host:
        return True
    if host.startswith("git.") and host.count(".") >= 2:
        return True
    return False


# Advisory databases, researcher PoC dumps, and third-party Claude Code /
# Cursor wrappers are cloneable git — they are not the vulnerable product.
# Matches cve_analyzer.ref_search / repository_policy, plus CSAF and
# CVE-named personal dumps. Vendor trees (anthropics/claude-code) stay.
ADVISORY_SLUGS = frozenset(
    {
        "pypa/advisory-database",
        "rubysec/ruby-advisory-db",
        "github/advisory-database",
        "friendsofphp/security-advisories",
        "rustsec/advisory-db",
        "golang/vulndb",
        "cisagov/csaf",
        "cveproject/cvelistv5",
    }
)
POC_AGGREGATOR_OWNERS = frozenset(
    {
        "trickest",
        "nomi-sec",
        "exploitintel",
        "actuator",
        "litengzheng",
        "goldenglow21",
        "wudipjq",
        "f1rstb100d",
        "zzb1388",
        "yzs17",
        "akuma-qaq",
        "marcelomulder",
        "yihaofuweng",
        "shiky8",
        "master-abc",
        "colorado-all",
        "programmervuln",
        "cymiao1978",
        "d0n601",
        "hwwg",
        "leexsoyoung",
    }
)
_POC_NAME_RE = re.compile(
    r"(^exploit[s_-]?|^pocs?([_-]|$)|^proof[_-]?of[_-]?concept|"
    r"vulnerability[_-]?(test|research)|cve[_-]?research|"
    r"^cve[_-]?\d{4}[_-]?\d+|"
    r"^security[_-]?research$|"
    r"^nuclei[_-]?templates$|^vulhub$|^vulnhub$|"
    r"pocs[_-]and[_-]cves|exploit[_-]intel|eip[_-]pocs|"
    r"^cve-?s?$|^cve2$|^mycve$|^my_vuln$|^0-?day|^vuln[s]?$|^vuln\d+$|"
    r"vulns?$|vuln[_-]?db|"
    r"cve[_-]?(disclosure|report|advisor)|"
    r"writeup|vuln?for)",
    re.IGNORECASE,
)
_CVE_NAME_RE = re.compile(r"cve-?\d{4}-?\d+", re.IGNORECASE)


def split_identity(ident: str) -> tuple[str, str, str]:
    """Return ``(host, owner, name)``. GitHub slugs imply github.com."""
    raw = ident.strip().lower().rstrip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    if raw.startswith("github.com/"):
        rest = raw[len("github.com/") :]
        owner, _, name = rest.partition("/")
        return "github.com", owner, name.split("/", 1)[0]
    first, _, rest = raw.partition("/")
    if "." in first:
        parts = rest.split("/") if rest else []
        name = parts[-1] if parts else ""
        owner = parts[0] if len(parts) >= 2 else ""
        return first, owner, name
    owner, _, name = raw.partition("/")
    return "github.com", owner, name.split("/", 1)[0]


def non_product_reason(ident: str) -> str | None:
    """Why this git identity is not the vulnerable product, or None."""
    if not ident:
        return None
    host, owner, name = split_identity(ident)
    slug = f"{owner}/{name}" if owner else name
    blob = f"{host}/{slug}"
    if (
        is_metadata_repository(ident)
        or is_metadata_repository(blob)
        or is_metadata_repository(slug)
        or slug in ADVISORY_SLUGS
        or (owner == "cisagov" and name == "csaf")
    ):
        return "advisory"
    if owner in POC_AGGREGATOR_OWNERS or _POC_NAME_RE.search(name) or _CVE_NAME_RE.search(name):
        return "poc"
    return None


def product_identities(idents: list[str] | set[str]) -> list[str]:
    return [ident for ident in idents if non_product_reason(ident) is None]


# GitHub facade: public repo, product source is not in the tree.
# anthropics/claude-code is the type: README/CHANGELOG/examples/plugins, CLI is npm.
CODE_TOP_DIRS = frozenset(
    {
        "src",
        "lib",
        "cmd",
        "pkg",
        "packages",
        "app",
        "apps",
        "internal",
        "crates",
        "core",
        "backend",
        "frontend",
        "source",
        "sources",
        "server",
        "client",
        "module",
        "modules",
    }
)
SKIP_TOP_DIRS = frozenset(
    {
        ".github",
        ".git",
        ".vscode",
        ".idea",
        ".devcontainer",
        ".claude",
        ".claude-plugin",
        ".circleci",
        ".husky",
        "docs",
        "doc",
        "documentation",
        "examples",
        "example",
        "demo",
        "demos",
        "scripts",
        "script",
        "plugins",
        "website",
        "www",
        "assets",
        "images",
        "img",
        "media",
        "changelog",
        "licenses",
        "license",
    }
)
# Install/docs scripts at repo root are not the product.
SOURCE_EXTS = frozenset(
    {
        "c",
        "cc",
        "cpp",
        "cxx",
        "h",
        "hh",
        "hpp",
        "go",
        "rs",
        "py",
        "js",
        "jsx",
        "mjs",
        "cjs",
        "ts",
        "tsx",
        "java",
        "kt",
        "rb",
        "php",
        "cs",
        "swift",
        "m",
        "mm",
        "scala",
        "clj",
        "ex",
        "exs",
        "erl",
        "hs",
        "lua",
        "vue",
        "svelte",
        "zig",
        "nim",
        "dart",
        "r",
        "jl",
    }
)
SENTINEL_FILES = frozenset(
    {
        "go.mod",
        "cargo.toml",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "cmakelists.txt",
        "makefile",
        "meson.build",
    }
)


def classify_root_listing(entries: list[dict]) -> str:
    """Return ``has_source`` or ``no_source`` from a GitHub contents listing.

    ``no_source`` is the Claude Code pattern: a public repo whose root is
    README/CHANGELOG/.github/examples/scripts/plugins, with the product
    shipped from elsewhere (npm, installer). Unknown extra top-level dirs
    are treated as ``has_source`` so we do not drop real trees.
    """
    if not entries:
        # Empty listing is a fetch miss, not the Claude Code facade.
        return "has_source"
    dirs: set[str] = set()
    files: list[str] = []
    for entry in entries:
        name = str(entry.get("name") or "")
        kind = str(entry.get("type") or "")
        if not name:
            continue
        if kind == "dir":
            dirs.add(name.lower())
        elif kind == "file":
            files.append(name)
    if dirs & CODE_TOP_DIRS:
        return "has_source"
    for name in files:
        lower = name.lower()
        if lower in SENTINEL_FILES:
            return "has_source"
        ext = lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in SOURCE_EXTS:
            return "has_source"
    leftover = dirs - SKIP_TOP_DIRS
    if leftover:
        return "has_source"
    return "no_source"


def _canonical(identity: str) -> str | None:
    ident = identity.strip().lower().rstrip("/")
    if ident.endswith(".git"):
        ident = ident[:-4]
    if not ident or "/" not in ident:
        return None
    host = host_of(ident)
    if not is_oss_git_host(host):
        return None
    if host == "git.kernel.org":
        return KERNEL_REPO
    if host == "github.com":
        parts = ident.split("/")
        if len(parts) < 3:
            return None
        owner, repo = parts[1], parts[2]
        if owner in SKIP_GITHUB_OWNERS:
            return None
        return f"{owner}/{repo}"
    return ident


def _from_github_slug(owner: str, repo: str) -> str | None:
    owner, repo = owner.lower(), repo.lower()
    if repo.endswith(".git"):
        repo = repo[:-4]
    if owner in SKIP_GITHUB_OWNERS or not repo:
        return None
    return f"{owner}/{repo}"


def parse_git_identity(url: str) -> tuple[str, str] | None:
    """Return ``(canonical_identity, strength)`` or None.

    Strength is ``commit`` for commit/PR/MR/cgit/gitweb/gitiles, else ``repo``.
    """
    if not url or not str(url).strip():
        return None
    raw = str(url).strip()

    try:
        parsed = parse_commit_url(raw)
    except Exception:
        parsed = None
    if parsed:
        ident = _canonical(f"{parsed.host}/{parsed.owner}/{parsed.repo}")
        if ident:
            return ident, "commit"

    try:
        parsed = parse_pr_url(raw)
    except Exception:
        parsed = None
    if parsed:
        ident = _canonical(f"{parsed.host}/{parsed.owner}/{parsed.repo}")
        if ident:
            return ident, "commit"

    try:
        foreign = parse_foreign_commit_url(raw)
    except Exception:
        foreign = None
    if foreign:
        ident = _canonical(foreign[0])
        if ident:
            return ident, "commit"

    try:
        repo = parse_repo_url(raw)
    except Exception:
        repo = None
    if repo:
        host, owner, name = repo
        ident = _canonical(f"{host}/{owner}/{name}")
        if ident:
            return ident, "repo"

    # Gitiles tree / repo root without a /+/<sha> commit path.
    lowered = raw.lower()
    if "googlesource.com/" in lowered and "://" in raw:
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(raw)
            host = (parts.hostname or "").lower()
            if host.endswith(".googlesource.com"):
                path = parts.path.strip("/").split("/+/", 1)[0]
                ident = _canonical(f"{host}/{path}")
                if ident:
                    return ident, "repo"
        except Exception:
            pass

    return None


AOSP_GOOGLESURCE_LEAVES = {
    "appsearch": "AppSearch",
    "bluetooth": "Bluetooth",
    "cellbroadcastservice": "CellBroadcastService",
    "certinstaller": "CertInstaller",
    "connectivity": "Connectivity",
    "contacts": "Contacts",
    "documentsui": "DocumentsUI",
    "downloadprovider": "DownloadProvider",
    "intentresolver": "IntentResolver",
    "managedprovisioning": "ManagedProvisioning",
    "mediaprovider": "MediaProvider",
    "mms": "Mms",
    "permission": "Permission",
    "settings": "Settings",
    "telecomm": "Telecomm",
    "telephony": "Telephony",
    "wifi": "Wifi",
}


def clone_url(ident: str) -> str | None:
    """HTTPS clone URL for a canonical identity, or None if we will not clone it."""

    raw = (ident or "").strip().lower().rstrip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    if not raw:
        return None
    host, owner, name = split_identity(raw)
    if host == "github.com":
        if not owner or not name:
            return None
        if owner in SKIP_GITHUB_OWNERS or owner == "user-attachments":
            return None
        return f"https://github.com/{owner}/{name}.git"
    if host.endswith(".googlesource.com"):
        parts = raw.split("/")
        leaf = parts[-1]
        if host == "android.googlesource.com" and leaf in AOSP_GOOGLESURCE_LEAVES:
            parts[-1] = AOSP_GOOGLESURCE_LEAVES[leaf]
            raw = "/".join(parts)
        return f"https://{raw}"
    if host == "gerrit.wikimedia.org":
        rest = raw.split("/", 1)[1] if "/" in raw else ""
        if rest.startswith("r/c/"):
            rest = rest[4:]
        elif rest.startswith("r/"):
            rest = rest[2:]
        if rest in {"mediawiki", "mediawiki/core"}:
            return "https://github.com/wikimedia/mediawiki.git"
        if rest.startswith("mediawiki/extensions/") and rest.count("/") == 2:
            ext = rest.rsplit("/", 1)[-1]
            return f"https://github.com/wikimedia/mediawiki-extensions-{ext}.git"
        if rest:
            return f"https://gerrit.wikimedia.org/r/{rest}"
        return None
    if "savannah.gnu.org" in host or "savannah.nongnu.org" in host:
        if not name:
            return None
        savannah = "nongnu" if "nongnu" in host else "gnu"
        return f"https://git.savannah.{savannah}.org/git/{name}.git"
    if host == "cgit.ghostscript.com" and name:
        return f"https://cgit.ghostscript.com/{name}.git"
    if host == "sourceware.org" and name:
        return f"https://sourceware.org/git/{name}.git"
    if host.startswith("gitlab.") or host in FORGE_HOSTS:
        if not name:
            return None
        return f"https://{raw}.git"
    if host.startswith("git.") and name:
        return f"https://{raw}.git"
    return None


def identities_from_urls(urls: list[str]) -> dict[str, str]:
    """Map canonical identity → best strength (``commit`` beats ``repo``)."""
    out: dict[str, str] = {}
    for url in urls:
        parsed = parse_git_identity(url)
        if not parsed:
            continue
        ident, strength = parsed
        if out.get(ident) != "commit":
            out[ident] = strength
    return out
