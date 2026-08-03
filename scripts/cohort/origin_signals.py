"""Conservative origin-signal primitives that never define the recall floor."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


class OriginSignalContractError(ValueError):
    """A diff or origin signal cannot be represented safely."""


_OLD_FILE_RE = re.compile(r"^--- a/(.*)$")
_NEW_FILE_RE = re.compile(r"^\+\+\+ b/(.*)$")
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_GUARD_RE = re.compile(
    r"(?:\b(?:assert|auth(?:enticate|entication|orize|orization)?|bounds?|"
    r"check|csrf|deny|escape|forbid|guard|middleware|null|permission|policy|"
    r"privilege|range|rate.?limit|require|role|sanitize|validate|validation)\b|"
    r"\bif\s+|\bunless\s+|\bthrow\s+new\b|\braise\s+\w+)",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"(?<![\w$])(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?![\w$])")
_TOKEN_STOPWORDS = {
    "and",
    "async",
    "await",
    "bool",
    "boolean",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "def",
    "default",
    "else",
    "except",
    "false",
    "finally",
    "float",
    "from",
    "function",
    "import",
    "instanceof",
    "integer",
    "interface",
    "lambda",
    "none",
    "null",
    "package",
    "pass",
    "private",
    "protected",
    "public",
    "raise",
    "request",
    "return",
    "self",
    "static",
    "string",
    "struct",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "undefined",
    "void",
    "while",
    "with",
    "yield",
}

DIRECT_SIGNAL_ORDER = (
    "squash_pr_member_relation",
    "add_context_blame",
    "enclosing_function_history",
    "pickaxe_token_history",
    "cross_file_security_bridge",
    "cross_file_surface_history",
    "szz_copy_aware",
    "szz_file_local",
)
_DIRECT_SIGNALS = frozenset(DIRECT_SIGNAL_ORDER)
AI_ANCESTRY_FALLBACK_SIGNAL = "ai_ancestry_fallback"
ATTRIBUTION_UNKNOWN_FAIL_OPEN_SIGNAL = "attribution_unknown_fail_open"
SQUASH_PR_MEMBER_SIGNAL = "squash_pr_member_relation"
SQUASH_INTERNAL_BLAME_SIGNAL = "squash_internal_fix_context_blame"


@dataclass(frozen=True)
class OriginHunk:
    """One zero-context diff hunk in parent and child coordinates."""

    parent_path: str | None
    path: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    added_lines: tuple[str, ...]

    @property
    def deleted_span(self) -> tuple[int, int] | None:
        if self.parent_path is None or self.old_count < 1:
            return None
        return (self.old_start, self.old_start + self.old_count - 1)

    @property
    def insertion_points(self) -> tuple[int, ...]:
        """Parent lines that anchor added code on both sides of a replacement."""

        if self.parent_path is None or not self.added_lines:
            return ()
        if self.old_count < 1:
            return (self.old_start,)
        return tuple(range(self.old_start, self.old_start + self.old_count))

    @property
    def is_guard_like(self) -> bool:
        return bool(_GUARD_RE.search("\n".join(self.added_lines)))

    @property
    def needs_add_check_history(self) -> bool:
        """Whether the hunk needs insertion-side history in addition to SZZ."""

        return bool(self.added_lines) and (self.old_count == 0 or self.is_guard_like)


def parse_origin_hunks(patch: str) -> list[OriginHunk]:
    """Parse every zero-context hunk without treating deleted lines as a gate."""

    result: list[OriginHunk] = []
    parent_path: str | None = None
    child_path = ""
    current: dict[str, object] | None = None

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        result.append(
            OriginHunk(
                parent_path=current["parent_path"],  # type: ignore[arg-type]
                path=str(current["path"]),
                old_start=int(current["old_start"]),
                old_count=int(current["old_count"]),
                new_start=int(current["new_start"]),
                new_count=int(current["new_count"]),
                added_lines=tuple(current["added_lines"]),  # type: ignore[arg-type]
            )
        )
        current = None

    for line in patch.splitlines():
        old_match = _OLD_FILE_RE.match(line)
        if old_match:
            flush()
            parent_path = old_match.group(1)
            child_path = parent_path
            continue
        if line == "--- /dev/null":
            flush()
            parent_path = None
            child_path = ""
            continue
        new_match = _NEW_FILE_RE.match(line)
        if new_match:
            child_path = new_match.group(1)
            continue
        hunk_match = _HUNK_RE.match(line)
        if hunk_match:
            flush()
            if not child_path and parent_path is None:
                raise OriginSignalContractError("hunk has no representable file path")
            current = {
                "parent_path": parent_path,
                "path": child_path or parent_path or "",
                "old_start": int(hunk_match.group(1)),
                "old_count": int(hunk_match.group(2) or 1),
                "new_start": int(hunk_match.group(3)),
                "new_count": int(hunk_match.group(4) or 1),
                "added_lines": [],
            }
            continue
        if current is not None and line.startswith("+") and not line.startswith("+++"):
            added_lines = current["added_lines"]
            assert isinstance(added_lines, list)
            added_lines.append(line[1:])
    flush()
    return result


def deleted_line_ranges(patch: str) -> dict[str, list[tuple[int, int]]]:
    """Parse parent-coordinate spans removed or replaced by one commit."""

    result: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    for hunk in parse_origin_hunks(patch):
        if hunk.parent_path is not None and hunk.deleted_span is not None:
            result[hunk.parent_path].append(hunk.deleted_span)
    return dict(result)


def history_search_tokens(text: str) -> list[str]:
    """Extract broad, deterministic identifiers for recall-oriented -S/-G history."""

    tokens: dict[str, str] = {}
    for match in _TOKEN_RE.finditer(text):
        raw = match.group(0)
        candidates = [raw, *raw.split(".")]
        for token in candidates:
            folded = token.casefold()
            if len(token) < 4 or folded in _TOKEN_STOPWORDS:
                continue
            tokens.setdefault(folded, token)
    return sorted(
        tokens.values(), key=lambda token: (-len(token), token.casefold(), token)
    )


def history_token_regex_chunks(
    tokens: Iterable[str],
    *,
    max_pattern_chars: int = 3000,
) -> list[str]:
    """Pack every token into bounded regex queries without a token-count cap."""

    if max_pattern_chars < 16:
        raise OriginSignalContractError("pickaxe regex chunks need at least 16 chars")
    chunks: list[str] = []
    current: list[str] = []
    current_chars = 2  # POSIX ERE group wrapper: (...)
    for token in tokens:
        escaped = re.escape(str(token))
        if not escaped:
            continue
        additional = len(escaped) + (1 if current else 0)
        if current and current_chars + additional > max_pattern_chars:
            chunks.append("(" + "|".join(current) + ")")
            current = []
            current_chars = 2
            additional = len(escaped)
        current.append(escaped)
        current_chars += additional
    if current:
        chunks.append("(" + "|".join(current) + ")")
    return chunks


def candidate_signal_row(
    *,
    sha: str,
    in_copy_aware_szz: bool,
    in_file_local_szz: bool,
    in_file_history: bool,
    observed_ai_unit: bool,
    in_add_context_blame: bool = False,
    in_function_history: bool = False,
    in_pickaxe_history: bool = False,
    in_cross_file_security_bridge: bool = False,
    in_cross_file_surface_history: bool = False,
    in_ai_ancestry_fallback: bool = False,
    in_attribution_unknown_fail_open: bool = False,
) -> dict[str, object]:
    if len(sha) != 40 or not (
        in_copy_aware_szz
        or in_file_local_szz
        or in_file_history
        or in_add_context_blame
        or in_function_history
        or in_pickaxe_history
        or in_cross_file_security_bridge
        or in_cross_file_surface_history
        or in_ai_ancestry_fallback
        or in_attribution_unknown_fail_open
    ):
        raise OriginSignalContractError(
            "materialized origin candidates need a full SHA and at least one signal"
        )
    return {
        "sha": sha,
        "signals": sorted(
            signal
            for signal, present in (
                ("szz_copy_aware", in_copy_aware_szz),
                ("szz_file_local", in_file_local_szz),
                ("affected_file_history", in_file_history),
                ("add_context_blame", in_add_context_blame),
                ("enclosing_function_history", in_function_history),
                ("pickaxe_token_history", in_pickaxe_history),
                ("cross_file_security_bridge", in_cross_file_security_bridge),
                ("cross_file_surface_history", in_cross_file_surface_history),
                (AI_ANCESTRY_FALLBACK_SIGNAL, in_ai_ancestry_fallback),
                (
                    ATTRIBUTION_UNKNOWN_FAIL_OPEN_SIGNAL,
                    in_attribution_unknown_fail_open,
                ),
            )
            if present
        ),
        "observed_ai_unit": observed_ai_unit,
        "retained": True,
    }


def prioritize_candidate_rows(
    rows: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Build a lane-fair queue so one prolific signal cannot crowd out add checks."""

    materialized: dict[str, dict[str, object]] = {}
    for source in rows:
        row = dict(source)
        sha = str(row.get("sha") or "")
        signals = row.get("signals")
        if len(sha) != 40 or not isinstance(signals, list) or not signals:
            raise OriginSignalContractError("priority rows need a full SHA and signals")
        if sha in materialized:
            raise OriginSignalContractError(f"duplicate priority candidate: {sha}")
        materialized[sha] = row

    def direct(row: Mapping[str, object]) -> bool:
        signals = row.get("signals")
        assert isinstance(signals, list)
        return bool(set(signals) & _DIRECT_SIGNALS)

    def ai_exposure_supported(row: Mapping[str, object]) -> bool:
        """Return whether direct or carrier-level evidence supports AI exposure.

        A recovered PR member may carry no attribution trailer of its own even
        though the landed squash does.  Treating that as an ordinary unknown
        would bury precisely the atomic commits decomposition exists to
        recover.  The separate ``origin_observed_in_cohort`` field keeps the
        member-level claim honest while this predicate controls ranking only.
        """

        return bool(
            row.get("observed_ai_unit") is True
            or row.get("ai_exposure_supported") is True
        )

    def has_signal(row: Mapping[str, object], signal: str) -> bool:
        signals = row.get("signals")
        assert isinstance(signals, list)
        return signal in signals

    def squash_member_queue(
        member_rows: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Round-robin carriers while taking each PR's best member first."""

        by_carrier: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
        for row in member_rows:
            raw_groups = row.get("squash_group_ids")
            groups = (
                sorted(str(value) for value in raw_groups)
                if isinstance(raw_groups, list) and raw_groups
                else [str(row.get("sha") or "")]
            )
            by_carrier[groups[0]].append(row)

        def member_key(row: Mapping[str, object]) -> tuple[object, ...]:
            return (
                -int(row.get("squash_internal_blame_line_count") or 0),
                -int(row.get("fix_code_file_overlap_count") or 0),
                -int(row.get("fix_file_overlap_count") or 0),
                row.get("empty_commit") is True,
                -len(row.get("code_files_changed") or []),
                -(1 if row.get("origin_observed_in_cohort") is True else 0),
                -min(
                    int(row.get("additions") or 0) + int(row.get("deletions") or 0),
                    10_000,
                ),
                str(row.get("sha") or ""),
            )

        for rows in by_carrier.values():
            rows.sort(key=member_key)
        carrier_order = sorted(
            by_carrier,
            key=lambda carrier: (
                min(
                    int(row.get("parent_priority_rank") or 0)
                    for row in by_carrier[carrier]
                ),
                carrier,
            ),
        )
        ordered: list[dict[str, object]] = []
        for member_index in range(
            max((len(rows) for rows in by_carrier.values()), default=0)
        ):
            for carrier in carrier_order:
                rows = by_carrier[carrier]
                if member_index < len(rows):
                    ordered.append(rows[member_index])
        return ordered

    groups = (
        (
            "DIRECT_SIGNAL",
            [row for row in materialized.values() if direct(row)],
        ),
        (
            "P2_OBSERVED_AI_AFFECTED_FILE_HISTORY",
            [
                row
                for row in materialized.values()
                if not direct(row)
                and ai_exposure_supported(row)
                and not has_signal(row, AI_ANCESTRY_FALLBACK_SIGNAL)
            ],
        ),
        (
            "P3_AFFECTED_FILE_HISTORY",
            [
                row
                for row in materialized.values()
                if not direct(row)
                and not ai_exposure_supported(row)
                and not has_signal(row, ATTRIBUTION_UNKNOWN_FAIL_OPEN_SIGNAL)
            ],
        ),
        (
            "P4_OBSERVED_AI_ANCESTRY_FALLBACK",
            [
                row
                for row in materialized.values()
                if not direct(row) and has_signal(row, AI_ANCESTRY_FALLBACK_SIGNAL)
            ],
        ),
        (
            "P5_ATTRIBUTION_UNKNOWN_FAIL_OPEN",
            [
                row
                for row in materialized.values()
                if not direct(row)
                and has_signal(row, ATTRIBUTION_UNKNOWN_FAIL_OPEN_SIGNAL)
            ],
        ),
    )

    ranked: list[dict[str, object]] = []
    within_class_ranks: defaultdict[str, int] = defaultdict(int)
    for priority_class, group in groups:
        remaining = {str(row["sha"]): row for row in group}
        lane_queues = {
            lane: (
                squash_member_queue(
                    [row for row in group if lane in row.get("signals", [])]
                )
                if lane == SQUASH_PR_MEMBER_SIGNAL
                else sorted(
                    (row for row in group if lane in row.get("signals", [])),
                    key=lambda row: str(row["sha"]),
                )
            )
            for lane in DIRECT_SIGNAL_ORDER
        }
        ordered: list[dict[str, object]] = []
        if priority_class == "DIRECT_SIGNAL":
            while remaining:
                made_progress = False
                for lane in DIRECT_SIGNAL_ORDER:
                    queue = lane_queues[lane]
                    while queue and str(queue[0]["sha"]) not in remaining:
                        queue.pop(0)
                    if not queue:
                        continue
                    row = queue.pop(0)
                    ordered.append(remaining.pop(str(row["sha"])))
                    made_progress = True
                if not made_progress:
                    ordered.extend(remaining[sha] for sha in sorted(remaining))
                    remaining.clear()
        else:
            ordered = [remaining[sha] for sha in sorted(remaining)]

        for row in ordered:
            signals = row["signals"]
            assert isinstance(signals, list)
            row_priority_class = priority_class
            if priority_class == "DIRECT_SIGNAL":
                row_priority_class = (
                    "P0_OBSERVED_AI_CAUSAL_SIGNAL"
                    if ai_exposure_supported(row)
                    else "P1_CAUSAL_SIGNAL"
                )
            within_class_ranks[row_priority_class] += 1
            row["priority_class"] = row_priority_class
            row["within_priority_class_rank"] = within_class_ranks[
                row_priority_class
            ]
            row["primary_lane"] = next(
                (lane for lane in DIRECT_SIGNAL_ORDER if lane in signals),
                (
                    AI_ANCESTRY_FALLBACK_SIGNAL
                    if AI_ANCESTRY_FALLBACK_SIGNAL in signals
                    else (
                        ATTRIBUTION_UNKNOWN_FAIL_OPEN_SIGNAL
                        if ATTRIBUTION_UNKNOWN_FAIL_OPEN_SIGNAL in signals
                        else "affected_file_history"
                    )
                ),
            )
            ranked.append(row)

    for priority_rank, row in enumerate(ranked, start=1):
        row["priority_rank"] = priority_rank
    return ranked
