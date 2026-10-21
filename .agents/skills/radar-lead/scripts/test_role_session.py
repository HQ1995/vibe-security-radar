#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("role_session", Path(__file__).with_name("role_session.py"))
rs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rs)

FAKE = r'''#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv[1:]
prompt = sys.stdin.read()
mode = os.environ["FAKE_MODE"]
log = os.environ["FAKE_LOG"]
open(log, "a").write(json.dumps({"argv": args, "prompt": prompt}) + "\n")
def emit(event):
    print(json.dumps(event), flush=True)
emit({"type": "thread.started", "thread_id": "thread-1"})
if "resume" in args:
    out = os.environ["FAKE_OUT"]
    for name in ("REPORT.md", "record.json"):
        open(os.path.join(out, name), "w").write("x\n")
    emit({"type": "item.completed", "item": {"type": "agent_message", "text": "done"}})
    sys.exit(0)
if mode == "loop":
    for n in range(40):
        emit({"type": "item.started", "item": {"type": "command_execution", "command": "python3 - <<'PY'\nPY"}})
        time.sleep(0.01)
    time.sleep(30)
if mode == "slow":
    while True:
        emit({"type": "item.started", "item": {"type": "command_execution", "command": f"step {time.time()}"}})
        time.sleep(0.2)
if mode == "ok":
    out = os.environ["FAKE_OUT"]
    for name in ("REPORT.md", "record.json"):
        open(os.path.join(out, name), "w").write("x\n")
    sys.exit(0)
'''


def setup(tmp_path, monkeypatch, mode):
    fake = tmp_path / "codex"
    fake.write_text(FAKE)
    fake.chmod(0o755)
    out = tmp_path / "out"
    out.mkdir()
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("FAKE_MODE", mode)
    monkeypatch.setenv("FAKE_OUT", str(out))
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO("the assignment"))
    return fake, out, log


def calls(log):
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_settings_are_fixed_and_a_finished_session_is_left_alone(tmp_path, monkeypatch):
    fake, out, log = setup(tmp_path, monkeypatch, "ok")
    code = rs.main(["--model", "m", "--scratch", str(tmp_path / "s"), "--out", str(out), "--codex", str(fake)])
    status = json.loads((tmp_path / "s" / "session-status.json").read_text())
    first = calls(log)[0]
    assert code == 0 and status["missing"] == [] and len(calls(log)) == 1
    assert "model_reasoning_effort=xhigh" in first["argv"] and "mcp_servers.Neon.enabled=false" in first["argv"]
    assert first["prompt"] == "the assignment"


def test_effort_is_pinned_to_xhigh_whatever_the_model():
    flags = rs.CODEX_FLAGS
    pinned = [flags[i + 1] for i, f in enumerate(flags) if f == "-c" and flags[i + 1].startswith("model_reasoning_effort=")]
    assert pinned == ["model_reasoning_effort=xhigh"]


def test_the_auditor_roster_is_opus_deepseek_and_haiku():
    roster = json.loads((Path(__file__).resolve().parents[1] / "models.json").read_text())
    assert roster["auditor"] == ["claude-opus-5-5", "group/auto-deepseek-v4-1-flash", "group/auto-claude-haiku-5-5"]


def test_a_repeated_tool_call_is_stopped(tmp_path, monkeypatch):
    fake, out, log = setup(tmp_path, monkeypatch, "loop")
    code = rs.main(["--model", "m", "--scratch", str(tmp_path / "s"), "--out", str(out), "--codex", str(fake),
                    "--loop-limit", "12"])
    status = json.loads((tmp_path / "s" / "session-status.json").read_text())
    assert code == 125 and status["reason"] == "loop" and status["loop"]["repeats"] == 12


def test_a_late_session_is_resumed_once_with_the_finish_note(tmp_path, monkeypatch):
    fake, out, log = setup(tmp_path, monkeypatch, "slow")
    code = rs.main(["--model", "m", "--scratch", str(tmp_path / "s"), "--out", str(out), "--codex", str(fake),
                    "--checkpoint-minutes", "0.05"])
    status = json.loads((tmp_path / "s" / "session-status.json").read_text())
    second = calls(log)[1]
    assert code == 0 and status["checkpoint"]["missing"] == ["REPORT.md", "record.json"]
    assert second["argv"][:2] == ["exec", "resume"] and "thread-1" in second["argv"]
    assert second["prompt"].startswith("Checkpoint from the leader") and status["missing"] == []
