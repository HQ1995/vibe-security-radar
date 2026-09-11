"""Claim ledger keeps parallel agents disjoint per slot and honours leases."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import claims


ROWS = [
    {"class_id": "a", "status": "UNANALYZED", "repo": "r/a"},
    {"class_id": "b", "status": "PARTIALLY_ANALYZED", "repo": "r/b"},
    {"class_id": "c", "status": "NOT_AI", "repo": "r/c"},
    {"class_id": "d", "status": "UNANALYZED", "repo": "r/d"},
]


def _case(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("".join(json.dumps(row) + "\n" for row in ROWS), encoding="utf-8")
    return ledger, tmp_path / "claims.jsonl"


def test_pick_is_disjoint_and_slots_stay_independent(tmp_path):
    ledger, log = _case(tmp_path)
    first = [event["class_id"] for event in claims.pick(log, ledger, "w1", limit=2, scope="round18")]
    second = [event["class_id"] for event in claims.pick(log, ledger, "w2", limit=5, scope="round18")]
    assert first == ["a", "b"]
    assert second == ["d"]
    assert claims.state(claims.load(log))[("a", "main")]["owner"] == "w1"
    # same batch, a second independent auditor works the same cases in its own slot
    third = [event["class_id"] for event in claims.pick(log, ledger, "w3", limit=2, slot="B", scope="round18")]
    assert third == ["a", "b"]
    with pytest.raises(claims.ClaimsError):
        claims.claim(log, "a", "w4")


def test_active_claim_cannot_be_stolen_but_expired_lease_can(tmp_path):
    ledger, log = _case(tmp_path)
    claims.claim(log, "a", "w1", hours=1)
    with pytest.raises(claims.ClaimsError):
        claims.claim(log, "a", "w2")
    claims.claim(log, "c", "w1", hours=-1)
    takeover = claims.claim(log, "c", "w2")
    assert takeover["supersedes"] == "w1"
    assert claims.state(claims.load(log))[("c", "main")]["owner"] == "w2"


def test_close_requires_owner_and_records_history(tmp_path):
    ledger, log = _case(tmp_path)
    claims.claim(log, "a", "w1")
    with pytest.raises(claims.ClaimsError):
        claims.close(log, "a", "w2", "RELEASED")
    claims.close(log, "a", "w1", "DONE", result="AI_ROOT_CAUSE")
    assert claims.state(claims.load(log))[("a", "main")]["state"] == "DONE"
    assert claims.claim(log, "a", "w2")["prev"] == "DONE:w1"


CHILD = """
import json, sys
sys.path.insert(0, sys.argv[1])
import claims
events = claims.pick(sys.argv[2], sys.argv[3], sys.argv[4], limit=2, scope="race")
print(json.dumps([event["class_id"] for event in events]))
"""


def test_concurrent_pick_is_atomic_across_processes(tmp_path):
    """Two picks racing for the same slot must not hand out the same case."""
    ledger, log = _case(tmp_path)
    scripts = str(Path(__file__).resolve().parents[1])
    procs = [
        subprocess.Popen([sys.executable, "-c", CHILD, scripts, str(log), str(ledger), owner],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for owner in ("w1", "w2")
    ]
    groups = []
    for proc in procs:
        out, err = proc.communicate()
        assert proc.returncode == 0, err
        groups.append(json.loads(out))
    taken = [case for group in groups for case in group]
    assert sorted(taken) == ["a", "b", "d"]  # every open case claimed exactly once
