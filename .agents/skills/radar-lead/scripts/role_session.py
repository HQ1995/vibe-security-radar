#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

LOOP_LIMIT = 12
CHECKPOINT_MINUTES = 30
TIMEOUT_SECONDS = 4500
CODEX_FLAGS = [
    "-c", "model_provider=magpie",
    "-c", "features.memories=false",
    "-c", "model_auto_compact_token_limit=500000",
    "-c", "model_reasoning_effort=xhigh",
    "-c", "mcp_servers.Neon.enabled=false",
    "-c", "mcp_servers.openaiDeveloperDocs.enabled=false",
    "--disable", "multi_agent",
    "--disable", "goals",
    "--disable", "image_generation",
    "--skip-git-repo-check",
]
CHECKPOINT_NOTE = (
    "Checkpoint from the leader: {minutes} minutes have passed and {missing} is not written yet. "
    "Stop opening new lines of research now. Write REPORT.md from what your receipts already show, "
    "derive record.json and research.json from it (record unfinished routes as unfinished work), "
    "write SUMMARY.md, and run lint and the strict gate."
)


class Watch:
    def __init__(self, loop_limit: int):
        self.loop_limit = loop_limit
        self.last = None
        self.repeats = 0
        self.thread = None
        self.loop = None

    def feed(self, line: str) -> None:
        try:
            event = json.loads(line)
        except ValueError:
            return
        if event.get("type") == "thread.started":
            self.thread = event.get("thread_id")
        item = event.get("item") or {}
        if event.get("type") != "item.started" or item.get("type") not in ("command_execution", "mcp_tool_call"):
            return
        key = json.dumps([item.get("type"), item.get("command"), item.get("server"), item.get("tool"),
                          item.get("arguments")], sort_keys=True)
        self.repeats = self.repeats + 1 if key == self.last else 1
        self.last = key
        if self.repeats >= self.loop_limit and self.loop is None:
            self.loop = {"repeats": self.repeats, "call": item.get("command") or item.get("tool")}


def missing(out: Path | None, required: list[str]) -> list[str]:
    if out is None:
        return []
    return [name for name in required if not (out / name).is_file() or not (out / name).read_text().strip()]


def run(argv, prompt, events, log, watch, deadline, checkpoint=None):
    with events.open("a") as sink:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                                text=True, start_new_session=True)
        proc.stdin.write(prompt)
        proc.stdin.close()
        reason = ""

        def guard():
            nonlocal reason
            while proc.poll() is None:
                now = time.time()
                if now > deadline:
                    reason = "timeout"
                elif watch.loop:
                    reason = "loop"
                elif checkpoint and now > checkpoint[0] and checkpoint[1]():
                    reason = "checkpoint"
                if reason:
                    os.killpg(proc.pid, signal.SIGTERM)
                    return
                time.sleep(2)
        threading.Thread(target=guard, daemon=True).start()
        for line in proc.stdout:
            sink.write(line)
            sink.flush()
            watch.feed(line)
        code = proc.wait()
    return {"timeout": 124, "loop": 125, "checkpoint": 126}.get(reason, code), reason


def main(args_list=None) -> int:
    parser = argparse.ArgumentParser(description="Run one radar role as a Codex session with fixed settings, a loop watchdog and a checkpoint")
    parser.add_argument("--model", required=True)
    parser.add_argument("--scratch", required=True, type=Path, help="the role's scratch directory")
    parser.add_argument("--out", type=Path, help="the role's output directory, checked at the checkpoint")
    parser.add_argument("--require", nargs="*", default=["REPORT.md", "record.json"])
    parser.add_argument("--checkpoint-minutes", type=float, default=CHECKPOINT_MINUTES)
    parser.add_argument("--timeout", type=float, default=TIMEOUT_SECONDS)
    parser.add_argument("--loop-limit", type=int, default=LOOP_LIMIT)
    parser.add_argument("--codex", default="codex")
    args = parser.parse_args(args_list)
    prompt = sys.stdin.read()
    args.scratch.mkdir(parents=True, exist_ok=True)
    events, reply = args.scratch / "events.jsonl", args.scratch / "reply.md"
    start = time.time()
    deadline = start + args.timeout
    status = {"model": args.model, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start))}
    watch = Watch(args.loop_limit)
    late = lambda: bool(missing(args.out, args.require))
    tail = ["-m", args.model, "--json", "--output-last-message", str(reply)]
    with (args.scratch / "session.log").open("a") as log:
        checkpoint = (start + args.checkpoint_minutes * 60, late) if args.out else None
        code, reason = run([args.codex, "exec", *CODEX_FLAGS, *tail, "-"], prompt, events, log, watch,
                           deadline, checkpoint)
        if reason == "checkpoint" and watch.thread:
            gone = missing(args.out, args.require)
            status["checkpoint"] = {"minutes": args.checkpoint_minutes, "missing": gone}
            note = CHECKPOINT_NOTE.format(minutes=int(args.checkpoint_minutes), missing=", ".join(gone))
            code, reason = run([args.codex, "exec", "resume", *CODEX_FLAGS, *tail, watch.thread, "-"],
                               note, events, log, watch, deadline)
    status.update(exit=code, reason=reason or None, loop=watch.loop, thread=watch.thread,
                  minutes=round((time.time() - start) / 60, 1), missing=missing(args.out, args.require))
    (args.scratch / "session-status.json").write_text(json.dumps(status, indent=1) + "\n")
    print(json.dumps(status))
    return code


if __name__ == "__main__":
    sys.exit(main())
