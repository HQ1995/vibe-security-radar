"""Generate web/src/lib/types.generated.ts from the JSON Schema in schema.py.

schema.py's DEFS are the single source of truth for the published data
contract; this module renders them as TypeScript interfaces so the web side
cannot drift from the Python producer silently.  Run directly:

    python3 scripts/web_data/ts_types.py           # rewrite types.generated.ts
    python3 scripts/web_data/ts_types.py --check   # exit 1 if stale (CI gate)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running as a plain script (python3 scripts/web_data/ts_types.py).
if __package__ in (None, ""):
    _SCRIPTS_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _SCRIPTS_ROOT not in sys.path:
        sys.path.insert(0, _SCRIPTS_ROOT)

from web_data.schema import DEFS  # noqa: E402

_GENERATED_PATH = (
    Path(__file__).resolve().parents[2] / "web" / "src" / "lib" / "types.generated.ts"
)

_HEADER = """\
// AUTO-GENERATED from scripts/web_data/schema.py by scripts/web_data/ts_types.py.
// Do not edit by hand — regenerate with `python3 scripts/web_data/ts_types.py`
// (`--check` exits 1 when this file is stale)."""

_PRIMITIVE_TS = {
    "string": "string",
    "number": "number",
    "integer": "number",
    "boolean": "boolean",
    "null": "null",
}


def _ts_type(schema: dict, indent: int) -> str:
    """Map a JSON Schema fragment to a TypeScript type expression."""
    if "$ref" in schema:
        return schema["$ref"].removeprefix("#/$defs/")
    if "anyOf" in schema:
        return " | ".join(_ts_type(option, indent) for option in schema["anyOf"])
    if "enum" in schema:
        return " | ".join(json.dumps(value) for value in schema["enum"])
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        return " | ".join(_ts_type({"type": t}, indent) for t in schema_type)
    if schema_type in _PRIMITIVE_TS:
        return _PRIMITIVE_TS[schema_type]
    if schema_type == "array":
        item = _ts_type(schema["items"], indent)
        if " | " in item:
            item = f"({item})"
        return f"readonly {item}[]"
    if schema_type == "object":
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            return f"Readonly<Record<string, {_ts_type(additional, indent)}>>"
        return _ts_object_body(schema, indent)
    raise ValueError(f"unsupported schema fragment: {schema!r}")


def _ts_object_body(schema: dict, indent: int) -> str:
    """Render an object schema as a TS interface body ({ ... })."""
    pad = "  " * indent
    prop_pad = "  " * (indent + 1)
    required = set(schema.get("required", []))
    lines = ["{"]
    for key, subschema in schema.get("properties", {}).items():
        optional = "" if key in required else "?"
        lines.append(
            f"{prop_pad}readonly {key}{optional}: {_ts_type(subschema, indent + 1)};"
        )
    lines.append(f"{pad}}}")
    return "\n".join(lines)


def render_ts() -> str:
    """Render all DEFS as TypeScript interfaces, in definition order."""
    chunks = [_HEADER]
    for name, schema in DEFS.items():
        chunks.append(f"export interface {name} {_ts_object_body(schema, 0)}")
    return "\n\n".join(chunks) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Write types.generated.ts, or verify it is current with --check."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 without writing if types.generated.ts is stale",
    )
    args = parser.parse_args(argv)

    content = render_ts()
    if args.check:
        current = (
            _GENERATED_PATH.read_text(encoding="utf-8")
            if _GENERATED_PATH.exists()
            else ""
        )
        if current != content:
            print(
                f"{_GENERATED_PATH} is stale — "
                f"regenerate with `python3 scripts/web_data/ts_types.py`",
                file=sys.stderr,
            )
            return 1
        print(f"{_GENERATED_PATH} is up to date.")
        return 0

    _GENERATED_PATH.write_text(content, encoding="utf-8")
    print(f"Wrote {_GENERATED_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
