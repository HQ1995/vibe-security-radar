"""Tests for audit_lock.py — parallel audit claim/lock mechanism.

TDD: Written before the implementation.
"""

import json
import threading
import time

import pytest

from audit_lock import (
    claim,
    is_claimed,
    release,
    list_claims,
    save_finding,
    load_claimed_cves,
    STALE_TIMEOUT_SECONDS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def claims_dir(tmp_path):
    d = tmp_path / "claims"
    d.mkdir()
    return d


@pytest.fixture
def findings_path(tmp_path):
    return tmp_path / "findings.json"


# ---------------------------------------------------------------------------
# claim() tests
# ---------------------------------------------------------------------------


class TestClaim:
    def test_claim_creates_lock_file(self, claims_dir):
        result = claim("CVE-2025-1234", claims_dir=claims_dir)
        assert result is True
        lock_file = claims_dir / "CVE-2025-1234.lock"
        assert lock_file.exists()

    def test_claim_file_contains_metadata(self, claims_dir):
        claim("CVE-2025-1234", worker="session-1", claims_dir=claims_dir)
        lock_file = claims_dir / "CVE-2025-1234.lock"
        data = json.loads(lock_file.read_text())
        assert data["cve_id"] == "CVE-2025-1234"
        assert data["worker"] == "session-1"
        assert "timestamp" in data
        assert "pid" in data
        assert isinstance(data["pid"], int)

    def test_claim_fails_if_already_claimed(self, claims_dir):
        claim("CVE-2025-1234", claims_dir=claims_dir)
        result = claim("CVE-2025-1234", claims_dir=claims_dir)
        assert result is False

    def test_claim_succeeds_if_stale(self, claims_dir):
        """A stale claim (older than timeout) can be reclaimed."""
        claim("CVE-2025-1234", claims_dir=claims_dir)
        # Backdate the lock file
        lock_file = claims_dir / "CVE-2025-1234.lock"
        data = json.loads(lock_file.read_text())
        data["timestamp"] = time.time() - STALE_TIMEOUT_SECONDS - 1
        lock_file.write_text(json.dumps(data))

        result = claim("CVE-2025-1234", claims_dir=claims_dir)
        assert result is True

    def test_claim_creates_directory_if_missing(self, tmp_path):
        new_dir = tmp_path / "nonexistent" / "claims"
        result = claim("CVE-2025-1234", claims_dir=new_dir)
        assert result is True
        assert (new_dir / "CVE-2025-1234.lock").exists()

    def test_claim_different_cves_independently(self, claims_dir):
        assert claim("CVE-2025-0001", claims_dir=claims_dir) is True
        assert claim("CVE-2025-0002", claims_dir=claims_dir) is True
        assert claim("CVE-2025-0001", claims_dir=claims_dir) is False


# ---------------------------------------------------------------------------
# is_claimed() tests
# ---------------------------------------------------------------------------


class TestIsClaimed:
    def test_not_claimed_when_no_file(self, claims_dir):
        assert is_claimed("CVE-2025-9999", claims_dir=claims_dir) is False

    def test_claimed_after_claim(self, claims_dir):
        claim("CVE-2025-1234", claims_dir=claims_dir)
        assert is_claimed("CVE-2025-1234", claims_dir=claims_dir) is True

    def test_not_claimed_when_stale(self, claims_dir):
        claim("CVE-2025-1234", claims_dir=claims_dir)
        lock_file = claims_dir / "CVE-2025-1234.lock"
        data = json.loads(lock_file.read_text())
        data["timestamp"] = time.time() - STALE_TIMEOUT_SECONDS - 1
        lock_file.write_text(json.dumps(data))

        assert is_claimed("CVE-2025-1234", claims_dir=claims_dir) is False

    def test_claimed_with_custom_timeout(self, claims_dir):
        claim("CVE-2025-1234", claims_dir=claims_dir)
        # With a very short timeout, even recent claims are stale
        assert is_claimed("CVE-2025-1234", claims_dir=claims_dir, stale_timeout=0) is False


# ---------------------------------------------------------------------------
# release() tests
# ---------------------------------------------------------------------------


class TestRelease:
    def test_release_removes_lock_file(self, claims_dir):
        claim("CVE-2025-1234", claims_dir=claims_dir)
        result = release("CVE-2025-1234", claims_dir=claims_dir)
        assert result is True
        assert not (claims_dir / "CVE-2025-1234.lock").exists()

    def test_release_nonexistent_returns_false(self, claims_dir):
        result = release("CVE-2025-9999", claims_dir=claims_dir)
        assert result is False

    def test_can_reclaim_after_release(self, claims_dir):
        claim("CVE-2025-1234", claims_dir=claims_dir)
        release("CVE-2025-1234", claims_dir=claims_dir)
        assert claim("CVE-2025-1234", claims_dir=claims_dir) is True


# ---------------------------------------------------------------------------
# list_claims() tests
# ---------------------------------------------------------------------------


class TestListClaims:
    def test_empty_when_no_claims(self, claims_dir):
        assert list_claims(claims_dir=claims_dir) == []

    def test_lists_active_claims(self, claims_dir):
        claim("CVE-2025-0001", worker="w1", claims_dir=claims_dir)
        claim("CVE-2025-0002", worker="w2", claims_dir=claims_dir)
        claims = list_claims(claims_dir=claims_dir)
        cve_ids = {c["cve_id"] for c in claims}
        assert cve_ids == {"CVE-2025-0001", "CVE-2025-0002"}

    def test_excludes_stale_claims(self, claims_dir):
        claim("CVE-2025-0001", claims_dir=claims_dir)
        claim("CVE-2025-0002", claims_dir=claims_dir)
        # Make one stale
        lock_file = claims_dir / "CVE-2025-0001.lock"
        data = json.loads(lock_file.read_text())
        data["timestamp"] = time.time() - STALE_TIMEOUT_SECONDS - 1
        lock_file.write_text(json.dumps(data))

        claims = list_claims(claims_dir=claims_dir)
        assert len(claims) == 1
        assert claims[0]["cve_id"] == "CVE-2025-0002"

    def test_handles_missing_directory(self, tmp_path):
        missing = tmp_path / "nonexistent"
        assert list_claims(claims_dir=missing) == []


# ---------------------------------------------------------------------------
# load_claimed_cves() tests
# ---------------------------------------------------------------------------


class TestLoadClaimedCves:
    def test_returns_set_of_cve_ids(self, claims_dir):
        claim("CVE-2025-0001", claims_dir=claims_dir)
        claim("CVE-2025-0002", claims_dir=claims_dir)
        result = load_claimed_cves(claims_dir=claims_dir)
        assert result == {"CVE-2025-0001", "CVE-2025-0002"}

    def test_empty_set_when_no_claims(self, claims_dir):
        assert load_claimed_cves(claims_dir=claims_dir) == set()


# ---------------------------------------------------------------------------
# save_finding() tests
# ---------------------------------------------------------------------------


class TestSaveFinding:
    def test_creates_file_if_not_exists(self, findings_path):
        finding = {"cve_id": "CVE-2025-1234", "verdict": "CONFIRMED"}
        save_finding(finding, findings_path=findings_path)
        data = json.loads(findings_path.read_text())
        assert len(data) == 1
        assert data[0]["cve_id"] == "CVE-2025-1234"

    def test_appends_to_existing_file(self, findings_path):
        findings_path.write_text(json.dumps([{"cve_id": "CVE-2025-0001"}]))
        save_finding({"cve_id": "CVE-2025-0002"}, findings_path=findings_path)
        data = json.loads(findings_path.read_text())
        assert len(data) == 2
        assert data[1]["cve_id"] == "CVE-2025-0002"

    def test_creates_parent_directory(self, tmp_path):
        deep_path = tmp_path / "a" / "b" / "findings.json"
        save_finding({"cve_id": "CVE-2025-1234"}, findings_path=deep_path)
        assert deep_path.exists()

    def test_handles_empty_existing_file(self, findings_path):
        findings_path.write_text("")
        save_finding({"cve_id": "CVE-2025-1234"}, findings_path=findings_path)
        data = json.loads(findings_path.read_text())
        assert len(data) == 1

    def test_handles_corrupt_existing_file(self, findings_path):
        findings_path.write_text("not json")
        save_finding({"cve_id": "CVE-2025-1234"}, findings_path=findings_path)
        data = json.loads(findings_path.read_text())
        assert len(data) == 1

    def test_corrupt_file_creates_backup(self, findings_path):
        findings_path.write_text("not json")
        save_finding({"cve_id": "CVE-2025-1234"}, findings_path=findings_path)
        backup = findings_path.with_suffix(".json.bak")
        assert backup.exists()
        assert backup.read_text() == "not json"

    def test_concurrent_writes_no_loss(self, findings_path):
        """Multiple threads writing simultaneously should not lose findings."""
        n = 20
        threads = [
            threading.Thread(
                target=save_finding,
                args=({"cve_id": f"CVE-{i}"},),
                kwargs={"findings_path": findings_path},
            )
            for i in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        data = json.loads(findings_path.read_text())
        assert len(data) == n
