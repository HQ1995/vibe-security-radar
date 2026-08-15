"""Contracts for the final NLTK XML-path adjudication."""

from __future__ import annotations

import cohort_nltk_xml_path_final_adjudication as final


def test_changed_lines_excludes_diff_headers_and_context() -> None:
    diff = """\
--- a/file.py
+++ b/file.py
 context
-old = nltk.download('wordnet')
+new = nltk.download('wordnet')
"""

    assert final._changed_lines(diff) == [
        "-old = nltk.download('wordnet')",
        "+new = nltk.download('wordnet')",
    ]


def test_activation_line_changes_only_returns_mechanism_tokens() -> None:
    diff = """\
-python = 3.11
+python = 3.12
-python -c "import nltk; nltk.download('wordnet')"
+python -c "import nltk; nltk.download('wordnet')"
"""

    assert final._activation_line_changes(diff) == [
        "-python -c \"import nltk; nltk.download('wordnet')\"",
        "+python -c \"import nltk; nltk.download('wordnet')\"",
    ]


def test_all_seven_affected_code_candidates_have_exact_scope_contracts() -> None:
    assert len(final.CODE_SCOPE_CONTRACTS) == 7
    assert {
        str(contract["scope"]) for contract in final.CODE_SCOPE_CONTRACTS.values()
    } == {"md5_hexdigest", "class Downloader", "_unzip_iter"}


def test_model_negatives_are_not_final_proof() -> None:
    assert "NO_AI_CAUSAL_ROOT" in final.FINAL_VERDICT
    assert len(final.DATA_PATH_FOLLOWUPS) == 3


def test_context_only_candidates_are_separate_from_code_candidates() -> None:
    assert not set(final.CODE_SCOPE_CONTRACTS) & final.CONTEXT_ONLY_SHAS
