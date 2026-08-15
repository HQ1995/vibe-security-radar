#!/usr/bin/env python3
"""Reproduce independently introduced TinyObjLoader parser paths under ASan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WitnessCase:
    case_id: str
    parent_sha: str
    candidate_sha: str
    fix_sha: str
    trigger: str
    artifact_kind: str
    claim_boundary: str


WITNESS_CASES = {
    "vt_w": WitnessCase(
        case_id="vt_w",
        parent_sha="07ba3299e3372443578a24b0f99bbdac42ed47c7",
        candidate_sha="5ef0c485a5912eec08bd95eb38e2fc3ea0d40b10",
        fix_sha="966edceaf8cdca7996c4e9a1c5ced2938de63366",
        trigger="vt 0 0 1e",
        artifact_kind="tinyobjloader_vt_w_path_extension_asan_witness",
        claim_boundary=(
            "The parent/candidate/fix ASan triplet proves that the candidate "
            "introduced the optional vt-w trigger path. It is a path-extension "
            "causal member, not the earliest root of the shared float parser defect."
        ),
    ),
    "tag_real": WitnessCase(
        case_id="tag_real",
        parent_sha="502d5ef8fd317024f3ad34f8cf0c2d19762a95d3",
        candidate_sha="ecc124e83e69cfa6eeca1c0752ca74cb44ffcd37",
        fix_sha="966edceaf8cdca7996c4e9a1c5ced2938de63366",
        trigger="t crease 0/1/0 1e",
        artifact_kind="tinyobjloader_tag_real_path_extension_asan_witness",
        claim_boundary=(
            "The parent/candidate/fix ASan triplet proves that the candidate "
            "made the real-valued tag trigger reachable. It is a path-extension "
            "causal member, not the earliest root of the shared float parser defect."
        ),
    ),
}


def _harness(trigger: str) -> str:
    return f'''\
#define TINYOBJLOADER_IMPLEMENTATION
#include "tiny_obj_loader.h"

#include <sstream>
#include <string>
#include <vector>

int main() {{
  std::istringstream input("{trigger}");
  tinyobj::attrib_t attributes;
  std::vector<tinyobj::shape_t> shapes;
  std::vector<tinyobj::material_t> materials;
  std::string warning;
  std::string error;
  (void)tinyobj::LoadObj(&attributes, &shapes, &materials, &warning, &error,
                         &input, nullptr);
  return 0;
}}
'''


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--case", choices=sorted(WITNESS_CASES), required=True)
    parser.add_argument("--compiler", default="c++")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _run(
    arguments: list[str],
    *,
    cwd: Path,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            cwd=cwd,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"cannot run {arguments[0]}: {exc}") from exc


def _git_blob(repository: Path, revision: str, path: str) -> bytes:
    completed = _run(
        ["git", "-C", str(repository), "show", f"{revision}:{path}"],
        cwd=repository,
    )
    if completed.returncode != 0 or not completed.stdout:
        reason = completed.stderr.decode("utf-8", errors="replace")[:300]
        raise SystemExit(f"cannot read {revision}:{path}: {reason}")
    return completed.stdout


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _execute_revision(
    repository: Path,
    compiler: str,
    root: Path,
    label: str,
    revision: str,
    harness: str,
) -> dict[str, object]:
    directory = root / label
    directory.mkdir()
    header = _git_blob(repository, revision, "tiny_obj_loader.h")
    (directory / "tiny_obj_loader.h").write_bytes(header)
    (directory / "witness.cc").write_text(harness, encoding="utf-8")
    binary = directory / "witness"
    compile_result = _run(
        [
            compiler,
            "-std=c++11",
            "-O1",
            "-g",
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "witness.cc",
            "-o",
            str(binary),
        ],
        cwd=directory,
    )
    if compile_result.returncode != 0:
        reason = compile_result.stderr.decode("utf-8", errors="replace")[:1000]
        raise SystemExit(f"{label} witness compile failed: {reason}")
    environment = dict(os.environ)
    environment["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
    execution = _run([str(binary)], cwd=directory, env=environment)
    stderr = execution.stderr.decode("utf-8", errors="replace")
    return {
        "label": label,
        "revision": revision,
        "source_sha256": hashlib.sha256(header).hexdigest(),
        "return_code": execution.returncode,
        "asan_heap_buffer_overflow": "AddressSanitizer: heap-buffer-overflow" in stderr,
        "stack_has_tryParseDouble": "tryParseDouble" in stderr,
        "stack_has_sr_parseReal": "sr_parseReal" in stderr,
        "stack_has_LoadObjInternal": "LoadObjInternal" in stderr,
        "stderr_sha256": hashlib.sha256(execution.stderr).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    witness_case = WITNESS_CASES[args.case]
    harness = _harness(witness_case.trigger)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    compiler_version = _run([args.compiler, "--version"], cwd=repository)
    if compiler_version.returncode != 0:
        raise SystemExit(f"compiler is unavailable: {args.compiler}")
    with tempfile.TemporaryDirectory(prefix="ai-slop-tiny-witness-") as raw_root:
        root = Path(raw_root)
        runs = [
            _execute_revision(
                repository,
                args.compiler,
                root,
                "parent",
                witness_case.parent_sha,
                harness,
            ),
            _execute_revision(
                repository,
                args.compiler,
                root,
                "candidate",
                witness_case.candidate_sha,
                harness,
            ),
            _execute_revision(
                repository,
                args.compiler,
                root,
                "fixed",
                witness_case.fix_sha,
                harness,
            ),
        ]
    parent, candidate, fixed = runs
    witness_passed = (
        parent["return_code"] == 0
        and parent["asan_heap_buffer_overflow"] is False
        and candidate["return_code"] != 0
        and candidate["asan_heap_buffer_overflow"] is True
        and candidate["stack_has_tryParseDouble"] is True
        and candidate["stack_has_sr_parseReal"] is True
        and candidate["stack_has_LoadObjInternal"] is True
        and fixed["return_code"] == 0
        and fixed["asan_heap_buffer_overflow"] is False
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": witness_case.artifact_kind,
        "witness_case": witness_case.case_id,
        "repository_identity": "github.com/tinyobjloader/tinyobjloader",
        "parent_sha": witness_case.parent_sha,
        "candidate_sha": witness_case.candidate_sha,
        "fix_sha": witness_case.fix_sha,
        "trigger": witness_case.trigger,
        "compiler": compiler_version.stdout.decode("utf-8", errors="replace")
        .splitlines()[0]
        .strip(),
        "runs": runs,
        "witness_passed": witness_passed,
        "claim_boundary": witness_case.claim_boundary,
    }
    _atomic_json(args.output, payload)
    print("TinyObjLoader path-extension witness frozen")
    print(f"  parent safe    : {parent['return_code'] == 0}")
    print(f"  candidate ASan : {candidate['asan_heap_buffer_overflow']}")
    print(f"  fixed safe     : {fixed['return_code'] == 0}")
    print(f"  witness        : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output         : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
