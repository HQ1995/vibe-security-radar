#!/usr/bin/env python3
"""Independently review the frozen ChurchCRM compositional witness with an LLM."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cohort_churchcrm_setup_password_compositional_witness import (
    ACTIVATION_SHA,
    CONFIG_TEMPLATE_PATH,
    LATENT_AI_SHA,
    PRE_ACTIVATION_AI_SHA,
    RAW_PASSWORD_SHA,
    SETUP_PATH,
)


DEFAULT_API_BASE = "http://127.0.0.1:8317/v1"
DEFAULT_API_CONFIG = Path.home() / "cliproxyapi" / "config.yaml"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
VERDICTS = {
    "confirmed_compositional_contributor",
    "possible_compositional_contributor",
    "not_supported",
    "insufficient",
}
TERNARY = {"yes", "no", "insufficient"}
REVIEW_KEYS = {
    "verdict",
    "independent_ai_root",
    "latent_ai_primitive",
    "human_activation_required",
    "counterfactual",
    "causal_chain",
    "missing_evidence",
}

SYSTEM_PROMPT = """\
You are an independent software-security provenance reviewer. False negatives
are costly, but causal labels must respect the evidence. A commit can be a
compositional contributor even when its own revision is not exploitable: it may
introduce a latent unsafe primitive that a later human commit activates. Keep
that distinct from an independently exploitable AI-authored root, mere ancestry,
and unchanged vulnerable code. Evaluate the supplied state transitions, exact
diffs, ancestry, and line origins. Return only the requested JSON object.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--witness", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--reasoning-effort", choices=("low", "medium", "high"), required=True)
    parser.add_argument("--max-output-tokens", type=int, default=6000)
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--api-key-env", default="CLIPROXY_API_KEY")
    parser.add_argument("--api-key-config", type=Path, default=DEFAULT_API_CONFIG)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain one JSON object")
    return value


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _loopback(api_base: str) -> bool:
    hostname = urlsplit(api_base).hostname
    if not hostname:
        return False
    if hostname.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _api_key(environment_name: str, config_path: Path) -> str:
    environment_value = os.environ.get(environment_name, "").strip()
    if environment_value:
        return environment_value
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SystemExit(
            f"{environment_name} is unset and PyYAML is unavailable for {config_path}"
        ) from exc
    try:
        value = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SystemExit(f"cannot read CLIProxyAPI config {config_path}: {exc}") from exc
    keys = value.get("api-keys") if isinstance(value, dict) else None
    if not isinstance(keys, list) or not keys or not isinstance(keys[0], str):
        raise SystemExit(f"CLIProxyAPI config has no usable api-keys entry: {config_path}")
    key = keys[0].strip()
    if not key:
        raise SystemExit(f"CLIProxyAPI config has an empty api-keys entry: {config_path}")
    return key


def _request_json(
    url: str,
    api_key: str,
    *,
    method: str = "GET",
    body: Mapping[str, object] | None = None,
    timeout: float,
) -> dict[str, object]:
    encoded = None
    headers = {"Authorization": f"Bearer {api_key}"}
    if body is not None:
        encoded = json.dumps(body, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=encoded, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SystemExit(f"CLIProxyAPI request failed: {type(exc).__name__}: {exc}") from exc
    if len(payload) > MAX_RESPONSE_BYTES:
        raise SystemExit("CLIProxyAPI response exceeded the byte limit")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"CLIProxyAPI returned invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit("CLIProxyAPI response is not an object")
    return value


def _require_model(api_base: str, api_key: str, model: str, timeout: float) -> None:
    response = _request_json(
        f"{api_base.rstrip('/')}/models", api_key, timeout=min(timeout, 30.0)
    )
    data = response.get("data")
    ids = [
        str(row.get("id") or "")
        for row in data
        if isinstance(row, Mapping)
    ] if isinstance(data, list) else []
    if ids.count(model) != 1:
        raise SystemExit(f"CLIProxyAPI must expose model {model!r} exactly once")


def _git(repository: Path, arguments: list[str]) -> str:
    environment = dict(os.environ)
    environment["GIT_NO_LAZY_FETCH"] = "1"
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        raise SystemExit(
            f"git {' '.join(arguments)} failed: {completed.stderr[:400]}"
        )
    return completed.stdout


def _commit_diff(repository: Path, sha: str) -> str:
    return _git(
        repository,
        [
            "show",
            "--format=commit %H%nsubject: %s%nauthor: %an <%ae>%nbody:%n%B",
            "--no-ext-diff",
            "--no-renames",
            "--unified=5",
            sha,
            "--",
            SETUP_PATH,
        ],
    ).strip()


def _relevant_source(repository: Path, revision: str) -> dict[str, str]:
    setup = _git(repository, ["show", f"{revision}:{SETUP_PATH}"])
    template = _git(repository, ["show", f"{revision}:{CONFIG_TEMPLATE_PATH}"])
    setup_lines = setup.splitlines()
    relevant = "\n".join(
        f"{index + 1:04d}: {line}"
        for index, line in enumerate(setup_lines)
        if 40 <= index + 1 <= 140
    )
    template_lines = template.splitlines()
    template_relevant = "\n".join(
        f"{index + 1:04d}: {line}"
        for index, line in enumerate(template_lines)
        if "DB_PASSWORD" in line
    )
    return {"setup": relevant, "config_template": template_relevant}


def _neutral_witness(witness: Mapping[str, object]) -> dict[str, object]:
    runs = witness.get("runs")
    neutral_runs: list[dict[str, object]] = []
    if isinstance(runs, list):
        for raw in runs:
            if not isinstance(raw, Mapping):
                continue
            neutral_runs.append(
                {
                    "label": raw.get("label"),
                    "revision": raw.get("revision"),
                    "resolved_commit": raw.get("resolved_commit"),
                    "evaluation": raw.get("evaluation"),
                }
            )
    metadata = witness.get("commit_metadata")
    neutral_metadata: dict[str, object] = {}
    if isinstance(metadata, Mapping):
        for sha, raw in metadata.items():
            if not isinstance(raw, Mapping):
                continue
            neutral_metadata[str(sha)] = {
                "sha": raw.get("sha"),
                "parents": raw.get("parents"),
                "author_name": raw.get("author_name"),
                "author_email": raw.get("author_email"),
                "authored_at": raw.get("authored_at"),
                "message": raw.get("message"),
                "direct_copilot_signal": raw.get("direct_copilot_signal"),
            }
    return {
        "advisory": witness.get("advisory"),
        "repository_identity": witness.get("repository_identity"),
        "witness_password": witness.get("witness_password"),
        "ancestry": witness.get("ancestry"),
        "commit_metadata": neutral_metadata,
        "line_origins_at_activation": witness.get("line_origins_at_activation"),
        "state_transitions": neutral_runs,
    }


def _build_prompt(repository: Path, witness: Mapping[str, object]) -> str:
    neutral = _neutral_witness(witness)
    diffs = {
        "latent_copilot_helper_delta": _commit_diff(repository, LATENT_AI_SHA),
        "raw_password_delta": _commit_diff(repository, RAW_PASSWORD_SHA),
        "copilot_refactor_delta": _commit_diff(repository, PRE_ACTIVATION_AI_SHA),
        "human_activation_delta": _commit_diff(repository, ACTIVATION_SHA),
    }
    source = _relevant_source(repository, ACTIVATION_SHA)
    return f"""\
Question: Does the directly Copilot-co-authored commit {LATENT_AI_SHA} make a
genuine compositional causal contribution to the setup-password PHP injection
path, even though a later human commit {ACTIVATION_SHA} is required to make the
path run? Keep this separate from whether the AI commit is an independently
exploitable root.

Known vulnerability mechanism to evaluate: attacker-controlled DB_PASSWORD can
break out of a single-quoted assignment when copied without escaping into the
generated PHP Config.php. The payload below is deliberately harmless: it emits
only a second PHP variable assignment and does not invoke a command, network, or
file primitive.

## Mechanically extracted state evidence
```json
{json.dumps(neutral, indent=2, sort_keys=True, ensure_ascii=False)}
```

## Exact parent-to-commit deltas
```text
{json.dumps(diffs, indent=2, sort_keys=True, ensure_ascii=False)}
```

## Activated revision source excerpt
```text
{json.dumps(source, indent=2, sort_keys=True, ensure_ascii=False)}
```

Return exactly this JSON schema:
{{
  "verdict": "confirmed_compositional_contributor" | "possible_compositional_contributor" | "not_supported" | "insufficient",
  "independent_ai_root": "yes" | "no" | "insufficient",
  "latent_ai_primitive": "yes" | "no" | "insufficient",
  "human_activation_required": "yes" | "no" | "insufficient",
  "counterfactual": "at most 120 words: what happens without the AI helper and what happens without the human activation",
  "causal_chain": ["at most five concise evidence-grounded steps"],
  "missing_evidence": ["zero or more facts needed for a stronger claim"]
}}
"""


def _response_text(response: Mapping[str, object]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
        return ""
    message = choices[0].get("message")
    return str(message.get("content") or "").strip() if isinstance(message, Mapping) else ""


def _parse_review(text: str) -> dict[str, object]:
    value = text.strip()
    if value.startswith("```"):
        lines = value.splitlines()
        value = "\n".join(line for line in lines if not line.startswith("```")).strip()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"review response is not JSON: {exc}") from exc
    if not isinstance(parsed, dict) or set(parsed) != REVIEW_KEYS:
        observed = sorted(parsed) if isinstance(parsed, dict) else type(parsed).__name__
        raise ValueError(f"review response keys are invalid: {observed}")
    if parsed["verdict"] not in VERDICTS:
        raise ValueError("review verdict is invalid")
    for field in ("independent_ai_root", "latent_ai_primitive", "human_activation_required"):
        if parsed[field] not in TERNARY:
            raise ValueError(f"review field {field} is invalid")
    if not isinstance(parsed["counterfactual"], str) or not parsed["counterfactual"].strip():
        raise ValueError("review counterfactual is invalid")
    for field in ("causal_chain", "missing_evidence"):
        if not isinstance(parsed[field], list) or not all(
            isinstance(item, str) and item.strip() for item in parsed[field]
        ):
            raise ValueError(f"review field {field} is invalid")
    if len(parsed["causal_chain"]) > 5:
        raise ValueError("review causal_chain exceeds five steps")
    return parsed


def _usage(response: Mapping[str, object]) -> dict[str, int]:
    raw = response.get("usage")
    if not isinstance(raw, Mapping):
        return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    def integer(*names: str) -> int:
        for name in names:
            if name in raw:
                try:
                    return max(0, int(raw[name] or 0))
                except (TypeError, ValueError):
                    return 0
        return 0
    input_tokens = integer("input_tokens", "prompt_tokens")
    output_tokens = integer("output_tokens", "completion_tokens")
    total_tokens = integer("total_tokens") or input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.max_output_tokens < 1 or args.timeout <= 0:
        raise SystemExit("output-token and timeout bounds must be positive")
    if not _loopback(args.api_base):
        raise SystemExit("compositional review requires a loopback CLIProxyAPI endpoint")
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    witness = _load_json(args.witness)
    if witness.get("artifact_kind") != "churchcrm_setup_password_compositional_witness":
        raise SystemExit("unexpected witness artifact kind")
    if witness.get("witness_passed") is not True:
        raise SystemExit("mechanical witness did not pass")

    api_key = _api_key(args.api_key_env, args.api_key_config)
    _require_model(args.api_base, api_key, args.model, args.timeout)
    prompt = _build_prompt(repository, witness)
    witness_bytes = args.witness.read_bytes()
    spec = {
        "schema_version": 1,
        "artifact_kind": "churchcrm_compositional_ai_independent_review",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "max_output_tokens": args.max_output_tokens,
        "witness_sha256": hashlib.sha256(witness_bytes).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "prompt_chars": len(prompt) + len(SYSTEM_PROMPT),
        "estimated_input_tokens_chars_div_4": (len(prompt) + len(SYSTEM_PROMPT) + 3) // 4,
        "negative_disposition": "RETAIN_FOR_HUMAN_REVIEW_NOT_DELETE",
    }
    args.output_dir.mkdir(parents=True)
    _atomic_json(args.output_dir / "spec.json", spec)
    _atomic_json(
        args.output_dir / "prompt.json",
        {"system_prompt": SYSTEM_PROMPT, "user_prompt": prompt},
    )
    response = _request_json(
        f"{args.api_base.rstrip('/')}/chat/completions",
        api_key,
        method="POST",
        body={
            "model": args.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "reasoning_effort": args.reasoning_effort,
            "max_tokens": args.max_output_tokens,
        },
        timeout=args.timeout,
    )
    _atomic_json(args.output_dir / "response.json", response)
    text = _response_text(response)
    result: dict[str, object] = {
        **spec,
        "observed_model": str(response.get("model") or ""),
        "finish_reason": "",
        "result_status": "parse_error",
        "usage": _usage(response),
        "review": {},
        "parse_error": "",
    }
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], Mapping):
        result["finish_reason"] = str(choices[0].get("finish_reason") or "")
    try:
        result["review"] = _parse_review(text)
    except ValueError as exc:
        result["parse_error"] = str(exc)
    else:
        result["result_status"] = "completed"
    _atomic_json(args.output_dir / "result.json", result)
    print("ChurchCRM compositional AI review complete")
    print(f"  model        : {args.model}")
    print(f"  effort       : {args.reasoning_effort}")
    print(f"  prompt chars : {spec['prompt_chars']}")
    print(f"  status       : {result['result_status']}")
    print(f"  usage        : {result['usage']}")
    if result["result_status"] == "completed":
        review = result["review"]
        assert isinstance(review, Mapping)
        print(f"  verdict      : {review['verdict']}")
    else:
        print(f"  parse error  : {result['parse_error']}")
    print(f"  output       : {args.output_dir}")
    return 0 if result["result_status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
