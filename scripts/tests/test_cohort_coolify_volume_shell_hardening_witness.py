"""Tests for the incomplete AI volume shell-hardening witness predicates."""

from __future__ import annotations

from cohort_coolify_volume_shell_hardening_witness import _evaluate_versions


def test_incomplete_volume_hardening_requires_sibling_cleanup_gap() -> None:
    baseline_preview = '''
instant_remote_process(["docker volume rm -f $storage->name"], $server, false);
instant_remote_process(["docker volume rm -f $key"], $server, false);
instant_remote_process(["docker network disconnect $key coolify-proxy"], $server, false);
instant_remote_process(["docker network rm $key"], $server, false);
'''
    candidate_preview = '''
instant_remote_process(['docker volume rm -f '.escapeshellarg($storage->name)], $server, false);
instant_remote_process(["docker volume rm -f $key"], $server, false);
instant_remote_process(["docker network disconnect $key coolify-proxy"], $server, false);
instant_remote_process(["docker network rm $key"], $server, false);
'''
    candidate_patterns = '''
public const VOLUME_NAME_PATTERN = '/safe/';
public static function volumeNameRules() {}
'''
    candidate_tests = '''
Persistent Volume Security Tests
rejects volume names with shell metacharacters
escapeshellarg neutralizes injection in docker volume rm command
'''
    repair_preview = '''
if (! preg_match(ValidationPatterns::VOLUME_NAME_PATTERN, $key)) { return; }
instant_remote_process(['docker volume rm -f '.escapeshellarg($key)], $server, false);
if (! preg_match(ValidationPatterns::DOCKER_NETWORK_PATTERN, $key)) { return; }
$k = escapeshellarg($key);
instant_remote_process(["docker network disconnect {$k} coolify-proxy"], $server, false);
instant_remote_process(["docker network rm {$k}"], $server, false);
'''
    repair_tests = '''
escapeshellarg neutralizes injection in docker volume create command
escapeshellarg neutralizes injection in docker network disconnect command
escapeshellarg neutralizes injection in docker network rm command
'''

    assert all(
        _evaluate_versions(
            baseline_preview,
            candidate_preview,
            candidate_patterns,
            candidate_tests,
            repair_preview,
            repair_tests,
        ).values()
    )
