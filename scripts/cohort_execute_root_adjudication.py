#!/usr/bin/env python3
"""Execute a frozen blinded root-adjudication pilot through local CLIProxyAPI."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from cohort.root_adjudication import (
    RootAdjudicationContractError,
    canonical_sha256,
    parse_model_decision,
    validate_packet,
)


DEFAULT_ENDPOINT = "http://127.0.0.1:8317/v1"
DEFAULT_MODEL = "gpt-5.6-luna"
SYSTEM_PROMPT = """\
You are performing blinded, recall-first triage of possible vulnerability-fixing
commits. The candidate set is intentionally noisy. Select every candidate whose
message, changed paths, and patch plausibly repair the described vulnerability.
Do not assume that exactly one candidate is correct or that any candidate is
correct. Prefer a small superset over omitting a plausible fix. If the supplied
evidence cannot support a decision, abstain or mark blocked instead of guessing.

Return one JSON object with exactly these keys:
{"decision":"select|abstain|blocked","selected_ids":["C01"],
 "confidence":"low|medium|high","rationale":"concise explanation",
 "missing_evidence":"what is needed, or empty"}
Do not include markdown or any additional keys.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", type=Path, required=True)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument(
        "--api-key", default=os.environ.get("COHORT_LLM_KEY", "sk-ant-grok-4")
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--max-calls", type=int, required=True)
    parser.add_argument("--max-output-tokens", type=int, default=1200)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _atomic_write(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _jsonl_text(rows: list[dict[str, object]]) -> str:
    return "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
    )


def _require_loopback(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    hostname = parsed.hostname
    if not hostname:
        raise SystemExit("CLIProxyAPI endpoint has no hostname")
    if hostname.casefold() != "localhost":
        try:
            if not ipaddress.ip_address(hostname).is_loopback:
                raise SystemExit("refusing to send repository evidence off loopback")
        except ValueError as exc:
            raise SystemExit("refusing to send repository evidence off loopback") from exc
    return endpoint.rstrip("/")


def _model_ids(
    client: httpx.Client, endpoint: str, headers: dict[str, str], timeout: float
) -> list[str]:
    response = client.get(f"{endpoint}/models", headers=headers, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise SystemExit("CLIProxyAPI model list is malformed")
    return sorted(
        str(row.get("id") or "")
        for row in rows
        if isinstance(row, dict) and str(row.get("id") or "")
    )


def _content_text(raw: object) -> str:
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, list):
        parts: list[str] = []
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(str(item["text"]))
        return "".join(parts).strip()
    return ""


def _parse_json_text(text: str) -> object:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return json.loads(cleaned)


def _prompt(packet: dict[str, object]) -> str:
    return (
        "Evaluate this blinded packet. Candidate IDs are opaque and carry no rank.\n\n"
        + json.dumps(packet, indent=2, sort_keys=True, ensure_ascii=False)
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if min(args.max_calls, args.max_output_tokens, args.timeout) <= 0:
        raise SystemExit("execution limits must be positive")
    endpoint = _require_loopback(args.endpoint)
    packets: dict[str, dict[str, object]] = {}
    try:
        for raw in _load_jsonl(args.packet_dir / "packets.jsonl"):
            packet = validate_packet(raw)
            identifier = str(packet["packet_id"])
            if identifier in packets:
                raise RootAdjudicationContractError("duplicate packet ID")
            packets[identifier] = packet
    except RootAdjudicationContractError as exc:
        raise SystemExit(f"blinded packet contract failed: {exc}") from exc
    pilot = _load_json(args.packet_dir / "pilot.json")
    if not isinstance(pilot, dict) or pilot.get("artifact_kind") != (
        "blinded_root_adjudication_pilot_spec"
    ):
        raise SystemExit("pilot specification is malformed")
    selected = pilot.get("selected")
    if not isinstance(selected, list) or any(not isinstance(row, dict) for row in selected):
        raise SystemExit("pilot selected rows are malformed")
    if len(selected) != args.max_calls:
        raise SystemExit("max-calls must exactly match the frozen pilot call count")
    selected_ids = [str(row.get("packet_id") or "") for row in selected]
    if len(selected_ids) != len(set(selected_ids)) or not set(selected_ids) <= set(
        packets
    ):
        raise SystemExit("pilot references duplicate or unknown packets")

    headers = {
        "Authorization": f"Bearer {args.api_key}",
        "Content-Type": "application/json",
    }
    results: list[dict[str, object]] = []
    args.output_dir.mkdir(parents=True, exist_ok=False)
    with httpx.Client() as client:
        model_ids = _model_ids(client, endpoint, headers, args.timeout)
        if model_ids.count(args.model) != 1:
            raise SystemExit(f"CLIProxyAPI does not expose model exactly once: {args.model}")
        for spec in selected:
            identifier = str(spec["packet_id"])
            effort = str(spec.get("reasoning_effort") or "")
            if effort not in {"medium", "high"}:
                raise SystemExit("pilot reasoning effort is invalid")
            packet = packets[identifier]
            user_prompt = _prompt(packet)
            body = {
                "model": args.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": args.max_output_tokens,
                "reasoning_effort": effort,
                "response_format": {"type": "json_object"},
            }
            started = datetime.now(timezone.utc)
            result: dict[str, object] = {
                "packet_id": identifier,
                "request_model": args.model,
                "reasoning_effort": effort,
                "request_sha256": canonical_sha256(body),
                "prompt_char_count": len(user_prompt) + len(SYSTEM_PROMPT),
                "started_at_utc": started.isoformat(),
                "status": "BLOCKED",
                "error": "",
                "observed_model": "",
                "usage": {},
                "model_content": "",
                "decision": {},
            }
            try:
                response = client.post(
                    f"{endpoint}/chat/completions",
                    headers=headers,
                    json=body,
                    timeout=args.timeout,
                )
                response.raise_for_status()
                payload = response.json()
                choices = payload.get("choices") if isinstance(payload, dict) else None
                if (
                    not isinstance(choices, list)
                    or not choices
                    or not isinstance(choices[0], dict)
                    or not isinstance(choices[0].get("message"), dict)
                ):
                    raise ValueError("chat completion choices are malformed")
                content = _content_text(choices[0]["message"].get("content"))
                parsed = _parse_json_text(content)
                if not isinstance(parsed, dict):
                    raise ValueError("model decision is not an object")
                candidate_ids = {
                    str(row["candidate_id"]) for row in packet["candidates"]
                }
                decision = parse_model_decision(parsed, candidate_ids)
                usage = payload.get("usage", {})
                result.update(
                    {
                        "status": "RESOLVED",
                        "observed_model": str(payload.get("model") or ""),
                        "usage": usage if isinstance(usage, dict) else {},
                        "model_content": content,
                        "decision": decision,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - conserve failed calls
                result["error"] = f"{type(exc).__name__}:{str(exc)[:300]}"
            result["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
            results.append(result)
            _atomic_write(args.output_dir / "responses.jsonl", _jsonl_text(results))

    usage_totals: Counter[str] = Counter()
    for row in results:
        usage = row.get("usage")
        if not isinstance(usage, dict):
            continue
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage.get(key, 0)
            if isinstance(value, int) and not isinstance(value, bool):
                usage_totals[key] += value
        details = usage.get("completion_tokens_details")
        if isinstance(details, dict):
            value = details.get("reasoning_tokens", 0)
            if isinstance(value, int) and not isinstance(value, bool):
                usage_totals["reasoning_tokens"] += value
    summary = {
        "schema_version": 1,
        "artifact_kind": "blinded_root_adjudication_execution",
        "pilot_id": pilot["pilot_id"],
        "endpoint_host": urlsplit(endpoint).hostname,
        "request_model": args.model,
        "model_list_count": len(model_ids),
        "call_count": len(results),
        "resolved_call_count": sum(row["status"] == "RESOLVED" for row in results),
        "blocked_call_count": sum(row["status"] == "BLOCKED" for row in results),
        "usage": dict(sorted(usage_totals.items())),
        "response_status_counts": dict(
            sorted(Counter(str(row["status"]) for row in results).items())
        ),
        "responses_sha256": canonical_sha256(results),
        "packet_input_sha256": canonical_sha256(
            [packets[identifier] for identifier in selected_ids]
        ),
        "pilot_spec_sha256": canonical_sha256(pilot),
        "sealed_map_read_by_executor": False,
        "non_loopback_evidence_transfer": False,
    }
    _atomic_write(args.output_dir / "summary.json", _json_text(summary))
    print("blinded root-adjudication pilot executed")
    print(f"  model                 : {args.model}")
    print(f"  calls                 : {len(results)}")
    print(f"  resolved              : {summary['resolved_call_count']}")
    print(f"  blocked               : {summary['blocked_call_count']}")
    print(f"  prompt tokens         : {usage_totals['prompt_tokens']:,}")
    print(f"  completion tokens     : {usage_totals['completion_tokens']:,}")
    print(f"  reasoning tokens      : {usage_totals['reasoning_tokens']:,}")
    print(f"  output                : {args.output_dir}")
    return 0 if summary["blocked_call_count"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
