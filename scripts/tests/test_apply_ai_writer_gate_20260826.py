from apply_ai_writer_gate_20260826 import expand, identity_keys


def test_github_bare_matches_prefixed_inventory() -> None:
    writer = expand(["github.com/n8n-io/n8n"])
    assert identity_keys("n8n-io/n8n") & writer
    assert identity_keys("github.com/n8n-io/n8n") & writer


def test_kernel_aliases_collapse() -> None:
    writer = expand(["git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux"])
    assert identity_keys("git.kernel.org/pub/scm/linux/kernel/git/stable/linux") & writer
    assert identity_keys("torvalds/linux") & writer
