"""OSS git identity parser: real forges in, CMS lookalikes out."""

from __future__ import annotations

from oss_git_repos import identities_from_urls, parse_git_identity


def test_github_commit_becomes_slug() -> None:
    ident, strength = parse_git_identity(
        "https://github.com/torvalds/linux/commit/deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    )
    assert ident == "torvalds/linux"
    assert strength == "commit"


def test_skips_github_advisory_route() -> None:
    assert parse_git_identity("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz") is None


def test_gitlab_gnome_commit() -> None:
    ident, strength = parse_git_identity(
        "https://gitlab.gnome.org/GNOME/glib/-/commit/0123456789abcdef0123456789abcdef01234567"
    )
    assert ident == "gitlab.gnome.org/gnome/glib"
    assert strength == "commit"


def test_bitbucket_repo_page() -> None:
    ident, strength = parse_git_identity("https://bitbucket.org/b_c/jose4j")
    assert ident == "bitbucket.org/b_c/jose4j"
    assert strength == "repo"


def test_gitiles_android() -> None:
    ident, strength = parse_git_identity(
        "https://android.googlesource.com/platform/frameworks/base/+/0123456789abcdef0123456789abcdef01234567"
    )
    assert ident.startswith("android.googlesource.com/")
    assert strength == "commit"


def test_kernel_collapses_to_stable_identity() -> None:
    ident, _ = parse_git_identity(
        "https://git.kernel.org/stable/c/13e5afd3d773c6fc6ca2b89027befaaaa1ea7293"
    )
    assert ident == "git.kernel.org/pub/scm/linux/kernel/git/stable/linux"


def test_denies_broadcom_cms() -> None:
    assert (
        parse_git_identity(
            "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/12345"
        )
        is None
    )


def test_denies_liferay_dev() -> None:
    assert parse_git_identity("https://liferay.dev/portal/-/issue/foo") is None


def test_savannah_cgit() -> None:
    ident, strength = parse_git_identity(
        "https://cgit.git.savannah.gnu.org/cgit/coreutils.git/commit/"
        "?id=8c9602e3a145e9596dc1a63c6ed67865814b6633"
    )
    assert ident == "cgit.git.savannah.gnu.org/coreutils"
    assert strength == "commit"


def test_batch_keeps_commit_over_repo() -> None:
    hits = identities_from_urls(
        [
            "https://bitbucket.org/b_c/jose4j",
            "https://bitbucket.org/b_c/jose4j/commits/0123456789abcdef0123456789abcdef01234567",
        ]
    )
    assert hits["bitbucket.org/b_c/jose4j"] == "commit"


def test_drops_advisory_database() -> None:
    from oss_git_repos import non_product_reason

    assert non_product_reason("pypa/advisory-database") == "advisory"
    assert non_product_reason("github.com/pypa/advisory-database") == "advisory"
    assert non_product_reason("cisagov/csaf") == "advisory"
    assert non_product_reason("golang/vulndb") == "advisory"


def test_drops_poc_and_cve_named() -> None:
    from oss_git_repos import non_product_reason

    assert non_product_reason("someone/CVE-2025-12345") == "poc"
    assert non_product_reason("wudipjq/my_vuln") == "poc"
    assert non_product_reason("f1rstb100d/mycve") == "poc"
    assert non_product_reason("trickest/cve") == "poc"
    assert non_product_reason("someone/poc-demo") == "poc"
    assert non_product_reason("pocket-id/pocket-id") is None
    assert non_product_reason("pocketbase/pocketbase") is None
    assert non_product_reason("pmmp/pocketmine-mp") is None
    assert non_product_reason("projectdiscovery/nuclei") is None
    assert non_product_reason("projectdiscovery/nuclei-templates") == "poc"


def test_wrappers_with_source_are_not_non_product() -> None:
    from oss_git_repos import non_product_reason

    assert non_product_reason("cnighswonger/claude-code-cache-fix") is None
    assert non_product_reason("musistudio/claude-code-router") is None
    assert non_product_reason("openclaw/openclaw") is None
    assert non_product_reason("n8n-io/n8n") is None
    assert non_product_reason("django/django") is None


def test_empty_root_listing_is_not_no_source() -> None:
    from oss_git_repos import classify_root_listing

    assert classify_root_listing([]) == "has_source"


def test_claude_code_root_is_no_source() -> None:
    from oss_git_repos import classify_root_listing

    entries = [
        {"name": ".github", "type": "dir"},
        {"name": "CHANGELOG.md", "type": "file"},
        {"name": "LICENSE.md", "type": "file"},
        {"name": "README.md", "type": "file"},
        {"name": "SECURITY.md", "type": "file"},
        {"name": "demo.gif", "type": "file"},
        {"name": "examples", "type": "dir"},
        {"name": "plugins", "type": "dir"},
        {"name": "scripts", "type": "dir"},
        {"name": "Script", "type": "dir"},
    ]
    assert classify_root_listing(entries) == "no_source"


def test_real_source_tree_is_has_source() -> None:
    from oss_git_repos import classify_root_listing

    assert (
        classify_root_listing(
            [{"name": "src", "type": "dir"}, {"name": "README.md", "type": "file"}]
        )
        == "has_source"
    )
    assert (
        classify_root_listing(
            [{"name": "main.go", "type": "file"}, {"name": "README.md", "type": "file"}]
        )
        == "has_source"
    )


def test_clone_url_github_and_skip_attachments() -> None:
    from oss_git_repos import clone_url

    assert clone_url("jqlang/jq") == "https://github.com/jqlang/jq.git"
    assert clone_url("user-attachments/files") is None
    assert clone_url("orgs/spree") is None
    assert clone_url("users/god-mellon") is None


def test_clone_url_forges() -> None:
    from oss_git_repos import clone_url

    assert clone_url("sourceware.org/git/binutils-gdb") == (
        "https://sourceware.org/git/binutils-gdb.git"
    )
    assert clone_url("salsa.debian.org/debian/pdns") == (
        "https://salsa.debian.org/debian/pdns.git"
    )
    assert clone_url("invent.kde.org/graphics/krita") == (
        "https://invent.kde.org/graphics/krita.git"
    )
    assert clone_url("bitbucket.org/ritt/elog") == "https://bitbucket.org/ritt/elog.git"
    assert clone_url("aomedia.googlesource.com/aom") == "https://aomedia.googlesource.com/aom"
    assert clone_url("android.googlesource.com/platform/packages/modules/bluetooth") == (
        "https://android.googlesource.com/platform/packages/modules/Bluetooth"
    )
    assert clone_url("go.googlesource.com/crypto") == "https://go.googlesource.com/crypto"
    assert clone_url("cgit.git.savannah.gnu.org/gawk") == (
        "https://git.savannah.gnu.org/git/gawk.git"
    )
    assert clone_url("cgit.ghostscript.com/cgi-bin/cgit.cgi/ghostpdl") == (
        "https://cgit.ghostscript.com/ghostpdl.git"
    )
    assert clone_url("gerrit.wikimedia.org/r/c/mediawiki/extensions/cargo") == (
        "https://github.com/wikimedia/mediawiki-extensions-cargo.git"
    )
    assert clone_url("git.dcmtk.org/dcmtk") == "https://git.dcmtk.org/dcmtk.git"
    assert clone_url("git.gnunet.org/libmicrohttpd") == (
        "https://git.gnunet.org/libmicrohttpd.git"
    )