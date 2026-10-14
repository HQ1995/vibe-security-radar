import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import claims
import ledger_store


def legacy_claim(cid="a", owner="reviewer", slot="review"):
    return {"action": "CLAIM", "class_id": cid, "owner": owner, "slot": slot,
            "scope": "old-batch", "ts": "2000-01-01T00:00:00Z",
            "lease_until": "2000-01-02T00:00:00Z"}


def write_events(path, events):
    path.write_text("".join(json.dumps(event) + "\n" for event in events))


def acquire(log, cid="a", owner="leader", **kwargs):
    return claims.claim(log, cid, owner, scope="batch", **kwargs)


def test_boolean_occupancy_and_old_receipt_cannot_release_reacquisition(tmp_path):
    log = tmp_path / "claims.jsonl"
    assert claims.occupancy(claims.state(claims.load(log)), "a")["claimed"] is False
    first = acquire(log)
    assert claims.occupancy(claims.state(claims.load(log)), "a")["claimed"] is True
    for owner, token in [("other", first["claim_id"]), ("leader", None), ("leader", "wrong")]:
        before = log.read_bytes()
        with pytest.raises(claims.ClaimsError):
            claims.release(log, "a", owner, claim_id=token)
        assert log.read_bytes() == before
    claims.release(log, "a", "leader", claim_id=first["claim_id"])
    before = log.read_bytes()
    assert claims.release(log, "a", "leader", claim_id=first["claim_id"]) is None
    assert log.read_bytes() == before
    assert claims.occupancy(claims.state(claims.load(log)), "a")["claimed"] is False
    second = acquire(log)
    assert second["claim_id"] != first["claim_id"]
    with pytest.raises(claims.ClaimsError):
        claims.release(log, "a", "leader", claim_id=first["claim_id"])
    with pytest.raises(claims.ClaimsError):
        acquire(log, claim_id=first["claim_id"])
    assert claims.state(claims.load(log))[("a", "main")]["claim_id"] == second["claim_id"]


def test_whole_case_lock_blocks_other_owners_scopes_and_slots(tmp_path):
    log = tmp_path / "claims.jsonl"
    acquire(log)
    before = log.read_bytes()
    for owner, scope, slot in [("leader", "batch", "main"), ("other", "other", "main"),
                               ("leader", "batch", "review"), ("other", "other", "verify")]:
        with pytest.raises(claims.ClaimsError):
            claims.claim(log, "a", owner, scope=scope, slot=slot)
        assert log.read_bytes() == before
    acquire(log, cid="b", owner="other")
    with pytest.raises(claims.ClaimsError, match="slot claims are disabled"):
        acquire(log, cid="c", owner="auditor", slot="review")


def test_renewal_retains_receipt_and_original_claim_time(tmp_path):
    log = tmp_path / "claims.jsonl"
    first = acquire(log, hours=1)
    renewed = acquire(log, hours=2, claim_id=first["claim_id"])
    assert renewed["claim_id"] == first["claim_id"]
    assert renewed["claimed_at"] == first["claimed_at"]
    assert renewed["lease_until"] > first["lease_until"]
    for owner, scope in [("other", "batch"), ("leader", "other-batch")]:
        with pytest.raises(claims.ClaimsError):
            claims.claim(log, "a", owner, scope=scope, claim_id=first["claim_id"])
    claims.release(log, "a", "leader", claim_id=first["claim_id"])


@pytest.mark.parametrize("hours", [0, -1, float("nan"), float("inf"), 1e300])
def test_invalid_lease_cannot_acquire(tmp_path, hours):
    log = tmp_path / "claims.jsonl"
    with pytest.raises(claims.ClaimsError):
        acquire(log, hours=hours)
    assert claims.load(log) == []


def test_expiration_neither_releases_nor_permits_takeover(tmp_path):
    log = tmp_path / "claims.jsonl"
    event = acquire(log)
    event["lease_until"] = "2000-01-01T00:00:00Z"
    write_events(log, [event])
    current = claims.state(claims.load(log))
    assert current[("a", "main")]["expired"] is True
    assert current[("a", "main")]["claimed"] is True
    with pytest.raises(claims.ClaimsError):
        acquire(log, owner="other")
    assert ledger_store.foreign_active_claims({"a"}, "other", path=log)
    claims.release(log, "a", "leader", claim_id=event["claim_id"])
    acquire(log, owner="other")


def test_historical_slots_block_new_case_claim_until_each_holder_releases(tmp_path):
    log = tmp_path / "claims.jsonl"
    write_events(log, [legacy_claim(), legacy_claim(owner="verifier", slot="verify")])
    before = log.read_bytes()
    current = claims.state(claims.load(log))
    assert len(claims.occupancy(current, "a")["holders"]) == 2
    assert log.read_bytes() == before
    with pytest.raises(claims.ClaimsError):
        acquire(log)
    claims.close(log, "a", "reviewer", "DONE", slot="review", result="NOT_AI")
    assert claims.load(log)[-1]["action"] == "RELEASED"
    assert "result" not in claims.load(log)[-1]
    with pytest.raises(claims.ClaimsError):
        acquire(log)
    token = claims.state(claims.load(log))[("a", "verify")]["claim_id"]
    claims.release(log, "a", "verifier", slot="verify", claim_id=token)
    acquire(log)
    assert len(claims.occupancy(claims.state(claims.load(log)), "a")["holders"]) == 1


def test_legacy_done_never_bypasses_a_new_claim_receipt(tmp_path):
    log = tmp_path / "claims.jsonl"
    event = acquire(log)
    with pytest.raises(claims.ClaimsError):
        claims.close(log, "a", "leader", "DONE")
    claims.close(log, "a", "leader", "DONE", claim_id=event["claim_id"], result="ignored")
    assert claims.load(log)[-1]["action"] == "RELEASED"
    assert "result" not in claims.load(log)[-1]


@pytest.mark.parametrize("action", ["DONE", "RELEASED", "RELEASE"])
def test_historical_closures_read_as_unclaimed(action):
    event = legacy_claim()
    close = {"action": action, "class_id": "a", "slot": "review", "owner": "old-leader"}
    assert claims.occupancy(claims.state([event, close]), "a")["claimed"] is False


def test_malformed_or_unfenced_events_fail_closed(tmp_path):
    log = tmp_path / "claims.jsonl"
    event = acquire(log)
    for bad in [
        {"action": "DONE", "class_id": "a", "owner": "leader"},
        {"action": "RELEASED", "class_id": "a", "owner": "leader", "claim_id": "old"},
        {"action": "RELEASED", "class_id": "a", "owner": "other", "claim_id": event["claim_id"]},
        {**legacy_claim(owner="leader", slot="main"), "scope": "batch"},
        {"action": "UNEXPECTED", "class_id": "a"},
    ]:
        with pytest.raises(claims.ClaimsError):
            claims.state([event, bad])
    write_events(log, [event])
    with log.open("a") as fh:
        fh.write('{"action":')
    before = log.read_bytes()
    with pytest.raises(ValueError):
        acquire(log, cid="b")
    assert log.read_bytes() == before


def test_foreign_expired_legacy_claim_blocks_ledger_before_database(tmp_path, monkeypatch):
    log = tmp_path / "claims.jsonl"
    write_events(log, [legacy_claim()])
    monkeypatch.setattr(claims, "DEFAULT_CLAIMS", log)
    monkeypatch.setattr(ledger_store, "connect", lambda **kwargs: pytest.fail("must not reach database"))
    patch = tmp_path / "patch.jsonl"
    patch.write_text(json.dumps({
        "expected_revision": 1, "assessment_ids": ["as-1"],
        "row": {"class_id": "a", "status": "NOT_AI", "advisory_ids": ["X"],
                "causal_research": {"verdict": "NOT_AI"}},
    }) + "\n")
    with pytest.raises(SystemExit, match="claims block this write"):
        ledger_store.apply_updates(patch, "leader", "test", require_assessments=True)
    assert ledger_store.foreign_active_claims({"a"}, "reviewer", path=log) == []
    claims.release(log, "a", "reviewer", slot="review")
    assert ledger_store.foreign_active_claims({"a"}, "leader", path=log) == []


def test_concurrent_claims_have_exactly_one_winner(tmp_path):
    log = tmp_path / "claims.jsonl"
    child = """
import sys
sys.path.insert(0, sys.argv[1])
import claims
sys.stdin.readline()
raise SystemExit(claims.main(['--claims-file', sys.argv[2], 'claim', '--class-id', 'a',
                             '--scope', 'batch', '--owner', sys.argv[3]]))
"""
    procs = [subprocess.Popen([sys.executable, "-B", "-c", child,
                              str(Path(claims.__file__).parent), str(log), owner],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
             for owner in ("leader-a", "leader-b")]
    for proc in procs:
        proc.stdin.write("go\n")
        proc.stdin.flush()
    results = [proc.communicate(timeout=10) for proc in procs]
    assert sorted(proc.returncode for proc in procs) == [0, 1], results
    assert len(claims.load(log)) == 1
    assert len(claims.occupancy(claims.state(claims.load(log)), "a")["holders"]) == 1


def test_cli_boolean_status_and_retired_operations(tmp_path, capsys):
    log = tmp_path / "claims.jsonl"
    base = ["--claims-file", str(log)]
    assert claims.main(base + ["list", "--class-id", "a"]) == 0
    assert json.loads(capsys.readouterr().out)["claimed"] is False
    with pytest.raises(SystemExit):
        claims.main(base + ["claim", "--class-id", "a", "--owner", "leader"])
    capsys.readouterr()
    assert claims.main(base + ["claim", "--class-id", "a", "--scope", "batch", "--owner", "leader"]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["claimed"] is True
    before = log.read_bytes()
    for command in ["pick", "sweep"]:
        assert claims.main(base + [command, "--owner", "leader"]) == 1
        assert "removed" in capsys.readouterr().err
        assert log.read_bytes() == before
    args = ["--class-id", "a", "--owner", "leader"]
    assert claims.main(base + ["done"] + args) == 1
    assert "claim_id" in capsys.readouterr().err
    assert claims.main(base + ["release"] + args + ["--claim-id", receipt["claim_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["claimed"] is False
    assert claims.main(base + ["list"]) == 0
    assert capsys.readouterr().out == ""
    assert claims.main(base + ["list", "--all"]) == 0
    assert json.loads(capsys.readouterr().out)["claimed"] is False
