from repository_policy import is_metadata_repository


def test_ubuntu_tracker_is_metadata_not_vulnerable_code() -> None:
    assert is_metadata_repository("https://git.launchpad.net/ubuntu-cve-tracker")


def test_eclipse_security_trackers_are_metadata_not_vulnerable_code() -> None:
    for url in (
        "https://gitlab.eclipse.org/security/cve-assignement",
        "https://gitlab.eclipse.org/security/vulnerability-reports",
    ):
        assert is_metadata_repository(url)


def test_advisory_databases_are_metadata() -> None:
    for url in ("https://github.com/pypa/advisory-database", "https://github.com/rubysec/ruby-advisory-db"):
        assert is_metadata_repository(url)


def test_upstream_project_is_code_candidate() -> None:
    assert not is_metadata_repository("https://github.com/openssl/openssl")
    assert not is_metadata_repository("https://github.com/torvalds/linux")
