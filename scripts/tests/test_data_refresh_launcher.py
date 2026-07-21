"""End-to-end lifecycle tests for the production data-refresh launcher."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO_ROOT / "scripts" / "run_data_refresh.sh"

_FAKE_RUNNER = r"""#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


mode = sys.argv[1]

if mode == "record":
    output = Path(sys.argv[2])
    exit_code = int(sys.argv[3])
    output.write_text(
        json.dumps(
            {
                "argv": sys.argv[4:],
                "cwd": os.getcwd(),
                "runner_pid": os.getpid(),
                "pythonhome": os.environ.get("PYTHONHOME"),
                "pythonpath": os.environ.get("PYTHONPATH"),
                "python_no_user_site": os.environ.get("PYTHONNOUSERSITE"),
            }
        ),
        encoding="utf-8",
    )
    raise SystemExit(exit_code)

if mode != "block":
    raise SystemExit(f"unexpected fixture mode: {mode}")

state_path = Path(sys.argv[2])
completion_marker = Path(sys.argv[3])
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(120)"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)


class Interrupted(BaseException):
    def __init__(self, signum: int) -> None:
        self.signum = signum


def interrupt(signum: int, _frame: object) -> None:
    raise Interrupted(signum)


def terminate_child() -> None:
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)


signal.signal(signal.SIGHUP, interrupt)
signal.signal(signal.SIGTERM, interrupt)
state_path.write_text(
    json.dumps({"runner_pid": os.getpid(), "child_pid": child.pid}),
    encoding="utf-8",
)

try:
    return_code = child.wait()
except Interrupted as exc:
    terminate_child()
    raise SystemExit(128 + exc.signum)
else:
    completion_marker.write_text(str(return_code), encoding="utf-8")
"""


@pytest.fixture
def isolated_launcher_repo(tmp_path: Path) -> Path:
    """Create an isolated repository with the real launcher and a fake runner."""

    root = tmp_path / "repo"
    scripts_dir = root / "scripts"
    interpreter_dir = root / "cve-analyzer" / ".venv" / "bin"
    scripts_dir.mkdir(parents=True)
    interpreter_dir.mkdir(parents=True)

    launcher = scripts_dir / "run_data_refresh.sh"
    shutil.copy2(_LAUNCHER, launcher)
    launcher.chmod(0o755)
    (scripts_dir / "run_data_refresh.py").write_text(
        _FAKE_RUNNER,
        encoding="utf-8",
    )
    (interpreter_dir / "python").symlink_to(sys.executable)
    return root


def _wait_for_json(path: Path, *, timeout: float = 5) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.02)
    raise AssertionError(f"timed out waiting for fixture state: {path}")


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for_process_exit(pid: int, *, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_exists(pid):
            return
        time.sleep(0.02)
    raise AssertionError(f"process {pid} survived launcher interruption")


def test_launcher_propagates_argv_cwd_pid_and_exit_status(
    isolated_launcher_repo: Path,
    tmp_path: Path,
) -> None:
    record = tmp_path / "record.json"
    launcher = isolated_launcher_repo / "scripts" / "run_data_refresh.sh"
    completed = subprocess.run(
        [
            str(launcher),
            "record",
            str(record),
            "23",
            "value with spaces",
            "--literal=*",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONHOME": "/tmp/attacker-home",
            "PYTHONPATH": "/tmp/attacker-path",
        },
        check=False,
    )

    payload = json.loads(record.read_text(encoding="utf-8"))
    assert completed.returncode == 23
    assert payload["argv"] == ["value with spaces", "--literal=*"]
    assert payload["cwd"] == str(isolated_launcher_repo)
    assert payload["pythonhome"] is None
    assert payload["pythonpath"] is None
    assert payload["python_no_user_site"] == "1"


@pytest.mark.parametrize("interrupt_signal", [signal.SIGTERM, signal.SIGHUP])
def test_launcher_interrupt_reaps_descendant_and_withholds_completion(
    isolated_launcher_repo: Path,
    tmp_path: Path,
    interrupt_signal: signal.Signals,
) -> None:
    state = tmp_path / "state.json"
    completion_marker = tmp_path / "completed.json"
    launcher = isolated_launcher_repo / "scripts" / "run_data_refresh.sh"
    process = subprocess.Popen(
        [str(launcher), "block", str(state), str(completion_marker)],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    payload = _wait_for_json(state)
    runner_pid = int(payload["runner_pid"])
    child_pid = int(payload["child_pid"])
    assert runner_pid == process.pid
    assert _process_exists(child_pid)

    os.kill(process.pid, interrupt_signal)
    assert process.wait(timeout=10) == 128 + interrupt_signal
    _wait_for_process_exit(child_pid)
    assert not completion_marker.exists()
