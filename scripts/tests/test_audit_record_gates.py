import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_record_gates import check_git_evidence, check_path, check_record, check_record_strict, check_text

AI_CASES = ("AI_ROOT_CAUSE", "AI_CODE_FLAWED", "AI_CAUSAL_CONTRIBUTOR")

GOOD = {
    "class_id": "alias-x",
    "verdict": "AI_ROOT_CAUSE",
    "advisory_ids": ["GHSA-1234-5678-90ab"],
    "advisory_disposition": "ACTIVE",
    "introducer_sha": "a" * 40,
    "landing_commit": "b" * 40,
    "bic_granularity": "ATOMIC",
    "fix_granularity": "ATOMIC",
    "fix_sha": "c" * 40,
    "fix_ai_marker": {"state": "ABSENT", "evidence": "no trailers on the fix"},
    "ai_on_bic": True,
    "flip_condition": "a PR page showing the tool was not used for that commit",
    "advisory_aliases": [{"id": "GHSA-1234-5678-90ab", "state": "ACTIVE"}],
}

REFUTED = {
    **GOOD, "verdict": "FALSE_POSITIVE",
    "false_positive_ground": "MECHANISM_REFUTED",
    "introducer_sha": None, "landing_commit": None, "bic_granularity": None,
    "fix_sha": None, "fix_granularity": None, "ai_on_bic": None,
    "fix_ai_marker": {"state": "UNKNOWN"},
    "evidence": "The keyed endpoint returns only a count; the claimed message body is never selected or serialized.",
}


def test_conflicting_alias_states_cannot_close_a_keyed_advisory():
    record = {**REFUTED, "advisory_disposition": "REJECTED",
              "false_positive_ground": "ADVISORY_REJECTED_ALIAS",
              "advisory_aliases": [
                  {"id": GOOD["advisory_ids"][0], "state": "ACTIVE"},
                  {"id": GOOD["advisory_ids"][0].lower(), "state": "REJECTED"}]}
    assert any("conflicting states" in p for p in check_text(json.dumps(record), strict=True))


@pytest.mark.parametrize("extra", [
    {"minimum_fix_set": ["c" * 40]}, {"introducer_parent": "d" * 40},
    {"unpatched": {"confirmed": True}},
])
def test_false_positive_nulls_cannot_mask_remaining_causal_claims(extra):
    assert check_text(json.dumps({**REFUTED, **extra}), strict=True)


@pytest.mark.parametrize("field", ["ai_marker", "fix_ai_marker"])
@pytest.mark.parametrize("ground", ["MECHANISM_REFUTED", "ADVISORY_MISATTRIBUTED", "ADVISORY_REJECTED_ALIAS"])
def test_false_positive_preserves_observed_markers_without_causal_role(field, ground):
    marker = {"state": "present", "sha": "d" * 40,
              "quote": "Co-authored-by: Copilot <copilot@example.test>"}
    record = {**REFUTED, field: marker, "false_positive_ground": ground,
              "ai_admissibility": "The observed benign change has a marker; no defect or repair is attributed."}
    if ground == "ADVISORY_REJECTED_ALIAS":
        record.update(advisory_disposition="REJECTED", advisory_aliases=[
            {"id": GOOD["advisory_ids"][0], "state": "REJECTED"}])
    assert any("null causal role" in p for p in check_text(json.dumps(record), strict=True))
    record[field] = {"state": "UNKNOWN"}
    record["evidence"] = {"finding": REFUTED["evidence"], "observed_marker": marker}
    assert check_text(json.dumps(record), strict=True) == []


@pytest.mark.parametrize("verdict", AI_CASES)
def test_contract_record_passes_both_gate_sets(verdict):
    record = {**GOOD, "verdict": verdict}
    assert check_record(record) == []
    assert check_record_strict(record) == []


IMPACT = {
    "affected": "the upload route in releases 2.1.0-2.3.4",
    "prerequisites": "any authenticated user; default configuration",
    "effect": "writes files outside the upload directory",
}


@pytest.mark.parametrize("version", [None, "2026-09-27.3", "not-a-version"])
def test_older_contract_records_do_not_need_impact(version):
    record = {**GOOD, "protocol_version": version}
    assert check_record_strict(record) == []


@pytest.mark.parametrize("verdict", (*AI_CASES, "EVIDENCE_GAP"))
def test_current_contract_records_need_the_impact_account(verdict):
    record = {**GOOD, "verdict": verdict, "protocol_version": "2026-10-14.1"}
    if verdict == "EVIDENCE_GAP":
        record.update(remaining_gap="the fix object is not public", flip_condition="the fix object is published")
    assert any("impact.affected" in p for p in check_record_strict(record))
    record["impact"] = {**IMPACT, "effect": "  "}
    assert [p for p in check_record_strict(record) if "impact" in p] == [
        "alias-x: strict: contract records need a substantive impact.effect (step 2)"]
    record["impact"] = IMPACT
    assert [p for p in check_record_strict(record) if "impact" in p] == []


def test_refuted_records_need_no_impact_account():
    assert check_record_strict({**REFUTED, "protocol_version": "2026-10-14.1"}) == []


@pytest.mark.parametrize("verdict", AI_CASES)
@pytest.mark.parametrize("field", ("advisory_ids", "introducer_sha", "fix_sha"))
def test_closed_ai_verdict_needs_causal_fields(verdict, field):
    record = {**GOOD, "verdict": verdict, field: None}
    assert any(field in problem for problem in check_record(record))


def test_contract_documents_every_gate_enforced_vocabulary():
    import audit_record_gates as gates

    skills = Path(__file__).resolve().parents[2] / ".agents" / "skills"
    contract = "\n".join(
        (skills / name).read_text()
        for name in ("radar-audit/references/record.md", "radar-audit/references/protocol.md",
                     "radar-adjudicate/references/protocol.md")
    )
    for vocabulary in (
        gates.DISPOSITIONS,
        gates.GRANULARITIES,
        gates.FIX_GRANULARITIES,
        gates.LANDING_BASIS,
        gates.FP_GROUNDS,
        gates.DISCLOSURE_STATES,
    ):
        for token in sorted(vocabulary):
            assert token in contract, f"{token} is gate-enforced but absent from the pinned contracts"
    for token in sorted({"human", "human-gh-noreply", "named-no-email", "ai_coder_bot",
                         "placeholder", "object-missing", "no-object"}):
        assert token in contract, f"{token} is gate-enforced but absent from the pinned contracts"


def test_squash_needs_decomposed_members():
    record = {**GOOD, "bic_granularity": "SQUASH_DECOMPOSED"}
    assert "decomposed_shas" in check_record_strict(record)[0]
    assert check_record_strict({**record, "decomposed_shas": ["d" * 40]}) == []


def test_landing_commit_cannot_be_its_own_bic():
    record = {**GOOD, "landing_commit": GOOD["introducer_sha"]}
    assert "own landing commit" in check_record_strict(record)[0]


@pytest.mark.parametrize("verdict", AI_CASES)
def test_closed_verdict_needs_flip_condition(verdict):
    record = {**GOOD, "verdict": verdict, "flip_condition": None}
    assert "flip_condition" in check_record_strict(record)[0]


@pytest.mark.parametrize("verdict", AI_CASES)
def test_ai_verdict_needs_a_bic_marker(verdict):
    record = {**GOOD, "verdict": verdict, "ai_on_bic": None}
    assert "ai_on_bic true" in check_record_strict(record)[0]


def test_ai_code_flawed_binds_its_marker_to_the_bic():
    record = {
        **GOOD,
        "verdict": "AI_CODE_FLAWED",
        "ai_on_bic": False,
        "ai_marker": {"state": "ABSENT", "evidence": "human author, no trailer"},
    }
    assert "needs ai_on_bic true" in check_record_strict(record)[0]
    on_candidate = {
        **record,
        "candidate_set": ["d" * 40],
        "ai_admissibility": "the qualifying evidence is the candidate commit's trailer",
    }
    assert "flaw_origin" in check_record_strict(on_candidate)[0]
    on_bic = {**record, "ai_on_bic": True, "flaw_origin": "human origin e" * 4}
    assert "ai_on_bic" not in " ".join(check_record_strict(on_bic))


def test_not_ai_needs_a_named_identity_and_the_disclosure_convention():
    record = {**GOOD, "verdict": "NOT_AI", "ai_on_bic": None}
    assert "identity_class" in check_record_strict(record)[0]
    recovered = {
        **record,
        "identity_class": "human",
        "disclosure_convention": "CONVENTION_NOT_OBSERVED",
    }
    assert check_record_strict(recovered) == []
    placeholder = {**recovered, "identity_class": "placeholder"}
    assert "EVIDENCE_GAP" in check_record_strict(placeholder)[0]
    bare_name = {**recovered, "identity_class": "named-no-email"}
    assert "EVIDENCE_GAP" in check_record_strict(bare_name)[0]


def test_present_fix_marker_needs_an_admissibility_sentence():
    record = {
        **GOOD,
        "verdict": "NOT_AI",
        "ai_on_bic": None,
        "identity_class": "human",
        "disclosure_convention": "NO_DATE",
        "fix_ai_marker": {"state": "PRESENT", "evidence": "Co-Authored-By: Claude"},
    }
    assert "ai_admissibility" in check_record_strict(record)[0]


def test_false_positive_needs_a_ground_and_squash_needs_a_carrier():
    assert "false_positive_ground" in check_record_strict(
        {**GOOD, "verdict": "FALSE_POSITIVE"}
    )[0]
    squash = {**GOOD, "bic_granularity": "SQUASH_DECOMPOSED", "decomposed_shas": ["d" * 40]}
    assert "landing_commit" in check_record_strict({**squash, "landing_commit": None})[0]


def test_unpatched_record_carries_the_no_fix_object_value():
    record = {**GOOD, "fix_granularity": "NO_FIX_OBJECT", "fix_sha": None}
    assert not [item for item in check_record_strict(record) if "fix_granularity" in item]


@pytest.mark.parametrize("verdict", AI_CASES)
def test_adjudicated_residual_cue_stops_firing(verdict):
    cue = {
        **GOOD,
        "verdict": verdict,
        "bug_semantics": "the released artifact still ships the pre-fix blob",
        "mechanism": "the packed pointer is written before the length check runs",
        "flip_condition": "the upstream PR page for that commit",
        "fix_ai_marker": {"state": "ABSENT", "evidence": "trailers checked"},
    }
    assert "residual" in check_record_strict(cue)[0]
    triaged = {
        **cue,
        "residual_triage": {
            "decision": "NOT-RESIDUAL",
            "basis": "a version range below the fix, not an unclosed surface",
        },
    }
    assert check_record_strict(triaged) == []


def test_unknown_granularities_are_explicit_open_gaps_only():
    gap = {
        **GOOD, "verdict": "EVIDENCE_GAP", "introducer_sha": None,
        "landing_commit": None, "bic_granularity": None,
        "fix_sha": None, "fix_granularity": None, "ai_on_bic": None,
        "remaining_gap": "The reporter has not identified the product source revision.",
    }
    for verdict in ("EVIDENCE_GAP", "BLOCKED"):
        assert check_text(json.dumps({**gap, "verdict": verdict}), strict=True) == []
    for change in (
        {"verdict": "NOT_AI"}, {"verdict": "AI_ROOT_CAUSE"},
        {"remaining_gap": "none"}, {"flip_condition": ""},
        {"introducer_sha": "a" * 40}, {"bic_granularity": "UNKNOWN"},
        {"fix_sha": "c" * 40}, {"direct_fix_sha": "c" * 40},
    ):
        assert check_record_strict({**gap, **change})
    for field in ("bic_granularity", "fix_granularity"):
        assert check_record_strict({k: v for k, v in gap.items() if k != field})


def test_false_positive_ground_must_match_keyed_advisory():
    record = {
        **REFUTED,
        "false_positive_ground": "ADVISORY_REJECTED_ALIAS",
        "evidence": "The other alias was rejected; the keyed advisory remains active.",
    }
    assert any("keyed advisory" in p for p in check_record_strict(record))
    assert check_record_strict({
        **record, "advisory_disposition": "REJECTED",
        "advisory_aliases": [{"id": GOOD["advisory_ids"][0], "state": "REJECTED"}],
    }) == []
    refuted = {**record, "false_positive_ground": "MECHANISM_REFUTED",
               "evidence": "The disclosed symbol belongs to a different product."}
    assert check_record(refuted) + check_record_strict(refuted) == []


def test_refuted_mechanism_needs_no_invented_introducer_or_repair():
    assert check_text(json.dumps(REFUTED), strict=True) == []
    for field in ("introducer_sha", "bic_granularity", "fix_sha", "fix_granularity"):
        assert check_record_strict({k: v for k, v in REFUTED.items() if k != field})
        assert check_record_strict({**REFUTED, field: GOOD[field]})
    for change in (
        {"landing_commit": "a" * 40}, {"decomposed_shas": ["a" * 40]},
        {"atomic_repair_sha": "b" * 40}, {"direct_fix_sha": "b" * 40},
        {"fix_shas": ["b" * 40]}, {"ai_on_bic": False}, {"ai_on_bic": True},
        {"advisory_ids": []}, {"advisory_aliases": 42},
        {"advisory_disposition": "WITHDRAWN"},
    ):
        assert check_text(json.dumps({**REFUTED, **change}), strict=True)


def test_legacy_false_positive_label_does_not_close_new_missing_evidence():
    record = {**REFUTED, "false_positive_ground": "EVIDENCE_INSUFFICIENT",
              "evidence": "The object could not be retrieved, so the claimed behavior was not inspected."}
    assert check_record(record) == []
    assert any("legacy false-positive" in p for p in check_record_strict(record))
    open_record = {**record, "verdict": "EVIDENCE_GAP",
                   "remaining_gap": "The affected endpoint implementation has not been inspected."}
    assert check_text(json.dumps(open_record), strict=True) == []


@pytest.mark.parametrize("body", [
    '{"verdict":"FALSE_POSITIVE","remaining_gap":"none","remaining_gap":"Skeleton written before probing"}',
    '{"ai_marker":{"state":"ABSENT","state":"PRESENT"}}',
])
def test_duplicate_keys_fail_file_stdin_and_lane_loading(tmp_path, body):
    from compare_slots import load

    path = tmp_path / "case.json"
    path.write_text(body + "\n")
    assert "duplicate JSON key" in " ".join(check_path(path, strict=True))
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load(tmp_path / "case.json")
    cli = Path(__file__).resolve().parents[1] / "audit_record_gates.py"
    result = subprocess.run([sys.executable, str(cli), "--strict", "--stdin"],
                            input=body, text=True, capture_output=True)
    assert result.returncode == 1
    assert "duplicate JSON key" in result.stderr and "Traceback" not in result.stderr


def test_empty_malformed_and_non_record_inputs_fail(tmp_path):
    for body in ("", "[]", "null", "{", "{}"):
        assert check_text(body, strict=True)
    path = tmp_path / "empty.json"
    path.write_text("\n")
    assert check_path(path)


def test_git_probe_catches_fix_trailer_copied_to_bic(tmp_path):
    def git(*args):
        return subprocess.run(
            ["git", "-C", str(tmp_path), *args], check=True, capture_output=True,
            text=True, env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Test Maintainer")
    git("config", "user.email", "maintainer@example.test")
    git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "feat: automation")
    bic = git("rev-parse", "HEAD")
    quote = "Co-authored-by: Claude <noreply@anthropic.com>"
    git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "Repair authorization\n\n" + quote)
    fix = git("rev-parse", "HEAD")
    record = {
        **GOOD, "introducer_sha": bic, "fix_sha": fix,
        "ai_marker": {"state": "PRESENT", "sha": bic, "quote": quote},
        "fix_ai_marker": {"state": "PRESENT", "sha": fix, "quote": quote},
    }
    failures = check_git_evidence(record, tmp_path)
    assert len(failures) == 1 and "ai_marker quote is absent" in failures[0]
    wrong_object = {**record, "ai_marker": {"state": "PRESENT", "sha": fix, "quote": quote}}
    assert any("must name its BIC object" in p for p in check_git_evidence(wrong_object, tmp_path))
    human = {
        **record, "verdict": "NOT_AI", "ai_on_bic": False,
        "ai_marker": {"state": "ABSENT"}, "identity_class": "human",
        "disclosure_convention": "CONVENTION_NOT_OBSERVED",
        "ai_admissibility": "The fix trailer records a successful repair, not defect attribution.",
    }
    assert check_git_evidence(human, tmp_path) == []
    cli = Path(__file__).resolve().parents[1] / "audit_record_gates.py"
    for example, expected in ((human, 0), (record, 1)):
        result = subprocess.run(
            [sys.executable, str(cli), "--strict", "--repo", str(tmp_path), "--stdin"],
            input=json.dumps(example), capture_output=True, text=True,
        )
        assert result.returncode == expected, result.stderr
    git("-c", "tag.gpgsign=false", "tag", "-a", "v1", "-m", "Release marker", fix)
    tag = git("rev-parse", "v1")
    assert any("not the named commit" in p for p in check_git_evidence({**human, "introducer_sha": tag}, tmp_path))
    assert any("unavailable" in p for p in check_git_evidence({**human, "introducer_sha": "f" * 40}, tmp_path))
    assert any("introducer_parent" in p for p in check_git_evidence({**human, "introducer_parent": fix}, tmp_path))
    disclosure = {
        **record, "ai_marker": {"state": "PRESENT", "source": "first_party", "sha": bic,
                                "quote": "AI assisted this change", "url": "https://example.test/pr/1"},
        "ai_admissibility": "The first-party statement identifies this exact introducing change.",
    }
    assert check_git_evidence(disclosure, tmp_path) == []
    assert check_git_evidence({**disclosure, "ai_admissibility": ""}, tmp_path)


def test_git_probe_reports_execution_failure(monkeypatch):
    def timeout(*args, **kwargs):
        assert kwargs["env"]["GIT_NO_LAZY_FETCH"] == "1"
        raise subprocess.TimeoutExpired(args[0], 30)

    monkeypatch.setattr("audit_record_gates.subprocess.run", timeout)
    assert "cannot read" in " ".join(check_git_evidence(GOOD, Path("unused")))
