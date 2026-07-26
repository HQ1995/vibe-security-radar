"""Tests for non-GitHub commit URL resolution in the cohort frame.

Every URL here was sampled from the local OSV archives, not invented — these
are the shapes that decide whether the Linux kernel and the GNU projects are
in the sampling frame or silently absent from it.
"""

from __future__ import annotations

import pytest

from cohort.commit_urls import KERNEL_STABLE_IDENTITY, parse_foreign_commit_url


@pytest.mark.parametrize(
    ("url", "identity", "sha"),
    [
        (
            "https://git.kernel.org/stable/c/13e5afd3d773c6fc6ca2b89027befaaaa1ea7293",
            KERNEL_STABLE_IDENTITY,
            "13e5afd3d773c6fc6ca2b89027befaaaa1ea7293",
        ),
        (
            "https://cgit.git.savannah.gnu.org/cgit/coreutils.git/commit/"
            "?id=8c9602e3a145e9596dc1a63c6ed67865814b6633",
            "cgit.git.savannah.gnu.org/coreutils",
            "8c9602e3a145e9596dc1a63c6ed67865814b6633",
        ),
        (
            "https://git.ffmpeg.org/gitweb/ffmpeg.git/commit/"
            "43be8d07281caca2e88bfd8ee2333633e1fb1a13",
            "git.ffmpeg.org/ffmpeg",
            "43be8d07281caca2e88bfd8ee2333633e1fb1a13",
        ),
        (
            "https://sourceware.org/git/?p=bzip2.git;a=commit;"
            "h=7ed62bfb46e87a9e878712603469440e6882b184",
            "sourceware.org/git/bzip2",
            "7ed62bfb46e87a9e878712603469440e6882b184",
        ),
        (
            "https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;"
            "h=5c831a3c7f3ca98d6aba1200353311e1a1f84c70",
            "sourceware.org/git/binutils-gdb",
            "5c831a3c7f3ca98d6aba1200353311e1a1f84c70",
        ),
        (
            "https://chromium.googlesource.com/webm/libwebp/+/902bc9190",
            "chromium.googlesource.com/webm/libwebp",
            "902bc9190",
        ),
    ],
)
def test_recognises_real_commit_urls(url: str, identity: str, sha: str) -> None:
    assert parse_foreign_commit_url(url) == (identity, sha)


@pytest.mark.parametrize(
    "url",
    [
        # Bug trackers share hosts with the git front-ends, so rejecting them
        # cannot rely on the hostname alone.
        "https://sourceware.org/bugzilla/show_bug.cgi?id=29699",
        "https://savannah.gnu.org/bugs/index.php?53132",
        # Advisory and package pages: treating these as repositories inflated
        # the frame from 7.6k to 213k before the strict filter landed.
        "https://ubuntu.com/security/notices/USN-1",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-1",
        "https://www.npmjs.com/package/foo",
        "https://access.redhat.com/errata/RHSA-2025:0001",
        # A bare repository URL names no commit.
        "https://chromium.googlesource.com/webm/libwebp",
        "",
        "not a url",
    ],
)
def test_rejects_non_commit_urls(url: str) -> None:
    assert parse_foreign_commit_url(url) is None


def test_same_project_through_two_gitweb_scripts_collapses() -> None:
    """sourceware exposes one repo via both `/git/?p=` and `/git/gitweb.cgi?p=`."""

    direct = parse_foreign_commit_url(
        "https://sourceware.org/git/?p=binutils-gdb.git;a=commit;"
        "h=5c831a3c7f3ca98d6aba1200353311e1a1f84c70"
    )
    via_cgi = parse_foreign_commit_url(
        "https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;"
        "h=5c831a3c7f3ca98d6aba1200353311e1a1f84c70"
    )
    assert direct is not None and via_cgi is not None
    assert direct[0] == via_cgi[0]


def test_sha_is_lowercased_so_identities_join() -> None:
    upper = parse_foreign_commit_url(
        "https://git.kernel.org/stable/c/13E5AFD3D773C6FC6CA2B89027BEFAAAA1EA7293"
    )
    assert upper == (KERNEL_STABLE_IDENTITY, "13e5afd3d773c6fc6ca2b89027befaaaa1ea7293")
