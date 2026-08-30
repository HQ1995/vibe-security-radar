from recover_moved_repos_20260826 import classify_slug, github_slug_of


def test_github_slug_plain_and_prefixed() -> None:
    assert github_slug_of("lunary-ai/lunary") == "lunary-ai/lunary"
    assert github_slug_of("github.com/lunary-ai/lunary") == "lunary-ai/lunary"
    assert github_slug_of("gitlab.com/foo/bar") is None


def test_classify_false_slug_and_poc() -> None:
    assert classify_slug("orgs/spree") == "false_slug"
    assert classify_slug("users/god-mellon") == "false_slug"
    assert classify_slug("jjjjj-zr/jjjjjzr") == "pocish"
    assert classify_slug("lunary-ai/lunary") == "candidate"
