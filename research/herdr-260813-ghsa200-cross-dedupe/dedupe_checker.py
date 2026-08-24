#!/usr/bin/env python3
"""Deterministic cross-shard collision checker for the GHSA-200 strict ledger lane.

Stdlib-only. This lane never promotes a case, never edits canonical/publication
files, and never counts anything. It only vetoes, narrows, or routes duplicate
and release-failure proposals back to the leader.

Two modes:

  audit       -- audit the frozen fp211 public-ID projection for the four
                 collision classes and for release-containment failures.

  check       -- ingest terminal fresh/upgrade/remediation proposal rows and a
                 reference corpus, then classify every colliding pair as
                 DISTINCT, DUPLICATE, ALIAS_SAME_COMPONENT, CONFLICT, or
                 UNKNOWN, and run the per-row release-containment check.

  self-test   -- run built-in negative controls that pin the dedupe policy.

Dedupe policy (authoritative; see ACCEPTANCE_CORRECTION below):

  * Shared SHA (candidate / carrier / fix) ALONE NEVER implies DUPLICATE. One
    umbrella commit can introduce or fix several distinct vulnerabilities.
  * A pre-existing mechanism_key ALONE NEVER implies DUPLICATE.
  * DUPLICATE requires BOTH:
      (1) an exact SHA-free semantic mechanism match (identical repository +
          source + sink + invariant), AND
      (2) formal first-party alias/component identity (same public ID, a
          formal CVE<->GHSA alias, or a declared duplicate_of linkage).
    The "independently demonstrated exact same source/sink/invariant/affected
    range/PoC with publication equivalence" path is surfaced as CONFLICT with
    reasons, never auto-merged without a formal identity link.
  * Same mechanism under different non-aliased IDs -> CONFLICT (route), never
    silent merge and never silent double-count.
  * Same advisory split into distinct mechanism rows -> ALIAS_SAME_COMPONENT.
  * Release tags must contain the candidate, precede the fixed tag, and fall
    within the advisory affected range.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA_VERSION = 2

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")

# Formal first-party alias relations recorded by the frozen audit / canonical overlay.
FORMAL_ALIAS_RELATIONS = {
    "FORMAL_ALIAS",
    "formal_alias",
    "CNA_POINTS_AT_GHSA",
    "GLOBAL_UNREVIEWED_FORMAL_ALIAS",
    "global_alias_repo_ghsa_only",
    "FIRST_PARTY_GHSA_NO_CVE",
    "GHSA_ONLY",
    "ghsa_only",
    "repo_ghsa_only",
}


def compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def norm_id(value) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().upper()


def norm_repo(value) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip().lower()
    return value[:-4] if value.endswith(".git") else value


def norm_text(value) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())


def norm_key(value) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def parse_sha(value) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip().lower()
    return value if SHA_RE.match(value) else ""


def _sha_set(values) -> set[str]:
    out: set[str] = set()
    if values is None:
        return out
    if isinstance(values, str):
        values = [values]
    for value in values:
        sha = parse_sha(value)
        if sha:
            out.add(sha)
    return out


def first_value(row: dict, *keys, default=None):
    for key in keys:
        if key in row and row[key] not in (None, "", [], {}):
            return row[key]
    return default


def list_str(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def extract_ids(row: dict) -> set[str]:
    ids: set[str] = set()
    for key in ("case_id", "primary_id", "public_ids", "declared_public_ids", "aliases", "id"):
        for value in list_str(row.get(key)):
            value = norm_id(value)
            if value.startswith("GHSA-") or value.startswith("CVE-"):
                ids.add(value)
    return ids


def parse_mechanism_text(text: str) -> tuple[str, str, str]:
    """Best-effort source/sink/invariant extraction from a mechanism sentence."""
    if not text:
        return "", "", ""
    source, sink, invariant = "", "", ""
    inv_split = re.split(r";\s*invariant\s*:", text, maxsplit=1, flags=re.IGNORECASE)
    body = inv_split[0]
    if len(inv_split) == 2:
        invariant = norm_text(inv_split[1])
    arrow = re.split(r"\s*->\s*", body, maxsplit=1)
    if len(arrow) == 2:
        source = norm_text(arrow[0])
        sink = norm_text(arrow[1])
    else:
        source = norm_text(body)
    return source, sink, invariant


def _edge_shas(row: dict) -> tuple[set[str], set[str], set[str]]:
    candidates: set[str] = set()
    carriers: set[str] = set()
    fixes: set[str] = set()
    for edge in row.get("candidate_fix_edges", []) or []:
        if not isinstance(edge, dict):
            continue
        candidates |= _sha_set(edge.get("candidate_sha"))
        carriers |= _sha_set(edge.get("carrier_sha"))
        fixes |= _sha_set(edge.get("fix_sha"))
    return candidates, carriers, fixes


class RowView:
    """Normalized, SHA-free view of a single proposal/reference row."""

    def __init__(self, row: dict, label: str = ""):
        self.raw = row
        self.label = label or str(
            row.get("row_key")
            or row.get("case_id")
            or row.get("canonical_component_id")
            or ""
        )
        self.component_id = norm_text(first_value(row, "canonical_component_id", ""))
        self.duplicate_of = norm_text(first_value(row, "duplicate_of", ""))

        self.ids = extract_ids(row)
        self.ghsa_ids = {i for i in self.ids if GHSA_RE.match(i)}
        self.cve_ids = {i for i in self.ids if CVE_RE.match(i)}
        self.repo = norm_repo(first_value(row, "repository", "repo"))
        self.key = norm_key(first_value(row, "mechanism_key", "mechanismKey"))
        self.text = norm_text(
            first_value(row, "mechanism", "scope_statement", "mechanism_text")
        ).lower()

        source = norm_text(first_value(row, "source", "attacker_input"))
        sink = norm_text(first_value(row, "sink"))
        invariant = norm_text(first_value(row, "invariant"))
        if not source and not sink and not invariant and self.text:
            source, sink, invariant = parse_mechanism_text(self.text)
        self.source = source.lower()
        self.sink = sink.lower()
        self.invariant = invariant.lower()

        cand_a, carr_a, fix_a = _edge_shas(row)
        self.candidates = _sha_set(first_value(row, "candidate_set", "candidate_sha")) | cand_a
        self.carriers = _sha_set(first_value(row, "carrier_set", "carrier_sha")) | carr_a
        self.fixes = _sha_set(
            first_value(row, "minimum_fix_set", "release_fix_sha", "minimum_security_closure_sha")
        ) | _sha_set(first_value(row, "proposed_fixes")) | fix_a

        self.identity_relation = norm_text(first_value(row, "identity_relation", ""))
        self.related = set(norm_id(v) for v in list_str(first_value(row, "related_case_ids", default=[])))
        self.source_tier = norm_text(first_value(row, "source_tier", ""))

        self.release = self._release_view(row)
        self.adv_vulnerable = self.release["adv_vulnerable"]
        self.adv_fixed = self.release["adv_fixed"]

    @staticmethod
    def _release_view(row: dict) -> dict:
        ev = row.get("release_evidence") or row.get("release_boundary") or row.get("release") or {}
        if not isinstance(ev, dict):
            ev = {}
        return {
            "vulnerable": first_value(
                ev, "vulnerable_tag", "vulnerable_version", "first_vulnerable_tag",
                "last_vulnerable_tag",
            ),
            "fixed": first_value(ev, "fixed_tag", "fixed_version"),
            "candidate_sha": first_value(
                ev, "candidate_sha", "candidate_member_sha", "semantic_origin_sha"
            ),
            "fix_sha": first_value(
                ev, "fix_sha", "minimum_security_closure_sha", "fix_member_sha"
            ),
            "adv_vulnerable": first_value(ev, "advisory_vulnerable_version"),
            "adv_fixed": first_value(ev, "advisory_fixed_version"),
            "candidate_in_vulnerable": ev.get("candidate_in_vulnerable"),
            "fix_in_fixed": ev.get("fix_in_fixed"),
            "fix_in_vulnerable": ev.get("fix_in_vulnerable"),
            "kind": first_value(ev, "kind"),
        }

    @property
    def has_semantic_core(self) -> bool:
        return bool(self.source or self.sink or self.invariant)

    def semantic_fingerprint(self) -> str:
        """SHA-free fingerprint over repository + source + sink + invariant.

        mechanism_key is deliberately EXCLUDED: it is a weak pre-existing label
        and must never be sufficient for a duplicate verdict.
        """
        payload = {
            "repo": self.repo,
            "source": self.source,
            "sink": self.sink,
            "invariant": self.invariant,
        }
        return sha256_bytes(compact_json(payload).encode())

    @property
    def semantic_empty(self) -> bool:
        return not self.has_semantic_core and not self.key and not self.text

    @property
    def identity_empty(self) -> bool:
        return not self.ids


# --------------------------------------------------------------------------- #
# Collision classification
# --------------------------------------------------------------------------- #

def identity_predicate(a: RowView, b: RowView, alias_map: dict[str, str]) -> str:
    """SAME_ID | ALIAS | NONE.

    ALIAS is only a first-party ID co-occurrence (the frozen alias map links an
    ID of a and an ID of b to one advisory) or an explicit related_case_ids
    cross-reference. A row-local identity_relation (e.g. FORMAL_ALIAS between
    that row's own CVE and GHSA) is NOT cross-row evidence.
    """
    if a.ids & b.ids:
        return "SAME_ID"
    for ia in a.ids:
        for ib in b.ids:
            if alias_map.get(ia) and alias_map.get(ia) == alias_map.get(ib):
                return "ALIAS"
    if (a.related & b.ids) or (b.related & a.ids):
        return "ALIAS"
    return "NONE"


def mechanism_predicate(a: RowView, b: RowView) -> str:
    """SAME | KEY | TEXT | NONE.

    SAME requires an exact SHA-free source/sink/invariant match. A matching
    mechanism_key alone is only KEY and is never treated as SAME.
    """
    if a.has_semantic_core and b.has_semantic_core:
        if a.semantic_fingerprint() == b.semantic_fingerprint():
            return "SAME"
    if a.key and b.key and a.key == b.key:
        return "KEY"
    if a.text and b.text and a.text == b.text:
        return "TEXT"
    return "NONE"


def shared_shas(a: RowView, b: RowView) -> dict:
    return {
        "candidate": sorted(a.candidates & b.candidates),
        "carrier": sorted(a.carriers & b.carriers),
        "fix": sorted(a.fixes & b.fixes),
    }


def declared_duplicate_link(a: RowView, b: RowView) -> bool:
    """First-party duplicate_of linkage between the two rows."""
    if not (a.duplicate_of and b.duplicate_of):
        return False
    targets = {a.label, a.component_id, b.label, b.component_id}
    return (a.duplicate_of in targets) or (b.duplicate_of in targets) or a.duplicate_of == b.duplicate_of


def affected_range_equal(a: RowView, b: RowView) -> bool:
    return bool(
        a.adv_vulnerable and b.adv_vulnerable and a.adv_fixed and b.adv_fixed
        and version_key(a.adv_vulnerable) == version_key(b.adv_vulnerable)
        and version_key(a.adv_fixed) == version_key(b.adv_fixed)
    )


def classify(a: RowView, b: RowView, alias_map: dict[str, str]) -> dict:
    """Deterministic collision verdict. Precedence order."""
    identity = identity_predicate(a, b, alias_map)
    mechanism = mechanism_predicate(a, b)
    shas = shared_shas(a, b)
    any_sha = bool(shas["candidate"] or shas["carrier"] or shas["fix"])

    reasons: list[str] = []

    if a.identity_empty or b.identity_empty or a.semantic_empty or b.semantic_empty:
        verdict = "UNKNOWN"
        reasons.append("insufficient identity or mechanism evidence")

    elif mechanism == "SAME":
        if identity in ("SAME_ID", "ALIAS"):
            verdict = "DUPLICATE"
            reasons.append("exact source/sink/invariant match + formal first-party identity (same ID or alias)")
        elif declared_duplicate_link(a, b):
            verdict = "DUPLICATE"
            reasons.append("exact source/sink/invariant match + first-party duplicate_of linkage")
        else:
            # Same mechanism under different non-aliased IDs. Shared SHA or an
            # identical affected range alone is NOT publication equivalence:
            # one umbrella commit can introduce/fix several vulnerabilities.
            verdict = "CONFLICT"
            reasons.append("exact source/sink/invariant match under different non-aliased IDs without formal identity link")
            if any_sha:
                reasons.append("shared SHA is not duplicate-proof (umbrella commit)")
            if affected_range_equal(a, b):
                reasons.append("identical affected range requires human publication-equivalence adjudication")

    elif mechanism in ("KEY", "TEXT"):
        if identity in ("SAME_ID", "ALIAS"):
            verdict = "ALIAS_SAME_COMPONENT"
            reasons.append("same advisory/component with overlapping but non-identical mechanism")
        else:
            verdict = "CONFLICT"
            reasons.append("pre-existing mechanism_key/text match under different non-aliased IDs; never merge on key alone")

    elif identity in ("SAME_ID", "ALIAS"):
        verdict = "ALIAS_SAME_COMPONENT"
        reasons.append("same advisory split into distinct mechanism rows (one case, multiple mechanisms)")

    elif any_sha:
        verdict = "DISTINCT"
        reasons.append("shared SHA only; distinct mechanism and distinct advisory (never duplicate by SHA)")

    else:
        verdict = "DISTINCT"
        reasons.append("distinct advisory and distinct mechanism")

    return {
        "verdict": verdict,
        "identity": identity,
        "mechanism": mechanism,
        "shared_shas": shas,
        "affected_range_equal": affected_range_equal(a, b),
        "reasons": reasons,
        "left": a.label,
        "right": b.label,
        "left_ids": sorted(a.ids),
        "right_ids": sorted(b.ids),
        "left_repo": a.repo,
        "right_repo": b.repo,
        "left_key": a.key,
        "right_key": b.key,
    }


# --------------------------------------------------------------------------- #
# Release containment check
# --------------------------------------------------------------------------- #

VERSION_PART = re.compile(r"(\d+)")


def version_key(tag) -> tuple:
    if not isinstance(tag, str):
        return tuple()
    value = tag.strip().lstrip("vV")
    parts = [int(p) for p in VERSION_PART.findall(value)]
    return tuple(parts) if parts else tuple(value)


def release_check(view: RowView) -> dict:
    rel = view.release
    vuln = rel["vulnerable"]
    fixed = rel["fixed"]
    candidate = parse_sha(rel["candidate_sha"]) or (sorted(view.candidates)[0] if view.candidates else "")
    fix = parse_sha(rel["fix_sha"]) or (sorted(view.fixes)[0] if view.fixes else "")

    is_release_tier = bool(vuln) or bool(fixed) or (
        view.source_tier and view.source_tier.endswith("_RELEASED")
    )
    if not is_release_tier:
        return {"verdict": "NA", "reasons": ["not a released-tier row"]}

    missing = []
    if not vuln:
        missing.append("vulnerable tag/version")
    if not fixed:
        missing.append("fixed tag/version")
    if not candidate:
        missing.append("candidate sha")
    if not fix:
        missing.append("fix sha")
    if missing:
        return {"verdict": "MISSING", "reasons": ["missing: " + ", ".join(missing)]}

    failures = []
    if version_key(vuln) >= version_key(fixed):
        failures.append(f"vulnerable {vuln} does not precede fixed {fixed}")
    if candidate == fix:
        failures.append("candidate sha equals fix sha")
    if rel["candidate_in_vulnerable"] is False:
        failures.append("declared candidate_in_vulnerable=false")
    if rel["fix_in_fixed"] is False:
        failures.append("declared fix_in_fixed=false")
    if rel["fix_in_vulnerable"] is True:
        failures.append("declared fix_in_vulnerable=true")

    adv_vuln = rel["adv_vulnerable"]
    adv_fixed = rel["adv_fixed"]
    if adv_vuln and version_key(vuln) < version_key(adv_vuln):
        failures.append(f"vulnerable {vuln} below advisory introduced {adv_vuln}")
    if adv_fixed and version_key(fixed) < version_key(adv_fixed):
        failures.append(f"fixed {fixed} below advisory fixed {adv_fixed}")
    if failures:
        return {"verdict": "FAIL", "reasons": failures}
    return {"verdict": "PASS", "reasons": []}


# --------------------------------------------------------------------------- #
# Alias map construction (first-party identity evidence)
# --------------------------------------------------------------------------- #

def _merge_alias_groups(groups: list[set[str]]) -> dict[str, str]:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for group in groups:
        ids = sorted(i for i in group if i.startswith("GHSA-") or i.startswith("CVE-"))
        if not ids:
            continue
        for other in ids[1:]:
            union(ids[0], other)
    return {key: find(key) for key in parent}


def build_alias_map(rows: list[dict]) -> dict[str, str]:
    groups: list[set[str]] = []
    for row in rows:
        ids: set[str] = set()
        for key in ("case_id", "primary_id"):
            value = norm_id(first_value(row, key, default=""))
            if value.startswith("GHSA-"):
                ids.add(value)
        for key in ("aliases", "public_ids", "declared_public_ids"):
            for value in list_str(row.get(key)):
                value = norm_id(value)
                if value.startswith("GHSA-") or value.startswith("CVE-"):
                    ids.add(value)
        if ids:
            groups.append(ids)
    return _merge_alias_groups(groups)


def build_alias_map_from_dispositions(dispositions: list[dict]) -> dict[str, str]:
    groups: list[set[str]] = []
    for row in dispositions:
        ids = {norm_id(row.get("public_id", ""))}
        for value in list_str(row.get("case_ids")):
            ids.add(norm_id(value))
        if ids:
            groups.append(ids)
    return _merge_alias_groups(groups)


# --------------------------------------------------------------------------- #
# Audit mode
# --------------------------------------------------------------------------- #

def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def audit(project_root: Path) -> dict:
    audit_dir = project_root / "autoresearch/orchestrator-260813-fp211-audit"
    canonical_ledger = project_root / "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl"

    mechanisms = load_jsonl(audit_dir / "final_mechanisms.jsonl")
    cases = load_jsonl(audit_dir / "public_cases.jsonl")
    dispositions = load_jsonl(audit_dir / "public_id_dispositions.jsonl")
    ledger = load_jsonl(canonical_ledger)

    # ---- A. Alias-class duplicates ----
    cve_to_cases: dict[str, set[str]] = defaultdict(set)
    for case in cases:
        for alias in case.get("aliases", []) or []:
            cve_to_cases[norm_id(alias)].add(case["case_id"])
    cve_multi = {k: sorted(v) for k, v in cve_to_cases.items() if len(v) > 1}
    multi_case_disposition = [
        d["public_id"] for d in dispositions if len(d.get("case_ids", []) or []) > 1
    ]
    case_ids = {c["case_id"] for c in cases}
    ghsa_as_alias = sorted(
        case_ids & {norm_id(a) for c in cases for a in (c.get("aliases") or [])}
    )

    # ---- B. Same-advisory split rows ----
    case_id_dups = {k: v for k, v in Counter(c["case_id"] for c in cases).items() if v > 1}
    key_per_case: dict[str, set[str]] = defaultdict(set)
    for c in cases:
        if c.get("mechanism_key"):
            key_per_case[c["case_id"]].add(c["mechanism_key"])
    multi_key_cases = {k: sorted(v) for k, v in key_per_case.items() if len(v) > 1}

    # ---- C. Same candidate/fix but distinct mechanisms ----
    cand_ords: dict[str, set[int]] = defaultdict(set)
    fix_ords: dict[str, set[int]] = defaultdict(set)
    carr_ords: dict[str, set[int]] = defaultdict(set)
    for m in mechanisms:
        o = m["ordinal"]
        for s in m.get("candidate_set", []) or []:
            cand_ords[s].add(o)
        for s in m.get("minimum_fix_set", []) or []:
            fix_ords[s].add(o)
        for s in m.get("carrier_set", []) or []:
            carr_ords[s].add(o)
    cand_shared = {k: sorted(v) for k, v in cand_ords.items() if len(v) > 1}
    fix_shared = {k: sorted(v) for k, v in fix_ords.items() if len(v) > 1}
    carr_shared = {k: sorted(v) for k, v in carr_ords.items() if len(v) > 1}

    cand_fix_shared = {}
    seen_clusters = set()
    for csha, c_ords in cand_shared.items():
        for fsha, f_ords in fix_shared.items():
            inter = set(c_ords) & set(f_ords)
            if len(inter) > 1:
                key = frozenset(inter)
                if key not in seen_clusters:
                    seen_clusters.add(key)
                    cand_fix_shared[f"{csha[:12]}..|{fsha[:12]}.."] = {
                        "candidate_sha": csha,
                        "fix_sha": fsha,
                        "ordinals": sorted(inter),
                    }

    # ---- D. Same mechanism under different IDs ----
    mech_key_to_cases: dict[str, set[str]] = defaultdict(set)
    for c in cases:
        if c.get("mechanism_key"):
            mech_key_to_cases[c["mechanism_key"]].add(c["case_id"])
    mech_key_multi = {k: sorted(v) for k, v in mech_key_to_cases.items() if len(v) > 1}

    # ---- canonical overlay SHA-free fingerprint collisions ----
    alias_map = build_alias_map(ledger)
    component_rows = [
        RowView(r, label=str(r.get("row_key") or r.get("canonical_component_id") or ""))
        for r in ledger
        if r.get("record_kind") == "COMPONENT_ROW"
    ]
    fp_owners: dict[str, list[str]] = defaultdict(list)
    for rv in component_rows:
        if rv.has_semantic_core:
            fp_owners[rv.semantic_fingerprint()].append(rv.label)
    fp_collisions = {fp: owners for fp, owners in fp_owners.items() if len(owners) > 1}

    audit_duplicates = [
        {
            "ordinal": m["ordinal"],
            "verdict": m["verdict"],
            "duplicate_of": m["duplicate_of"],
            "false_positive_class": m.get("false_positive_class"),
        }
        for m in mechanisms
        if m.get("duplicate_of")
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "inputs": {
            "final_mechanisms.jsonl": str(audit_dir / "final_mechanisms.jsonl"),
            "public_cases.jsonl": str(audit_dir / "public_cases.jsonl"),
            "public_id_dispositions.jsonl": str(audit_dir / "public_id_dispositions.jsonl"),
            "canonical_ledger.jsonl": str(canonical_ledger),
        },
        "counts": {
            "mechanisms": len(mechanisms),
            "public_cases": len(cases),
            "dispositions": len(dispositions),
            "canonical_component_rows": len(component_rows),
        },
        "A_alias_class_duplicates": {
            "cve_claimed_by_multiple_ghsa": cve_multi,
            "disposition_rows_with_multiple_cases": multi_case_disposition,
            "case_id_also_used_as_alias": ghsa_as_alias,
        },
        "B_same_advisory_split_rows": {
            "duplicate_case_id_rows": case_id_dups,
            "cases_with_multiple_mechanism_keys": multi_key_cases,
        },
        "C_same_candidate_fix_distinct_mechanisms": {
            "candidate_sha_shared_count": len(cand_shared),
            "fix_sha_shared_count": len(fix_shared),
            "carrier_sha_shared_count": len(carr_shared),
            "candidate_sha_shared": cand_shared,
            "fix_sha_shared": fix_shared,
            "candidate_and_fix_shared_clusters": cand_fix_shared,
        },
        "D_same_mechanism_different_ids": {
            "mechanism_key_multi_case": mech_key_multi,
            "audit_duplicate_of_rows": audit_duplicates,
        },
        "canonical_overlay": {
            "semantic_fingerprint_collisions": fp_collisions,
            "component_rows": len(component_rows),
        },
        "alias_map_size": len(alias_map),
    }


# --------------------------------------------------------------------------- #
# Check mode
# --------------------------------------------------------------------------- #

def load_rows(path: Path) -> list[dict]:
    text = path.read_text().strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass
    return load_jsonl(path)


def check(proposals: list[dict], reference: list[dict], alias_map: dict[str, str]) -> dict:
    prop_views = [RowView(r, label=str(r.get("row_key") or r.get("case_id") or i)) for i, r in enumerate(proposals)]
    ref_views = [RowView(r, label=str(r.get("row_key") or r.get("case_id") or r.get("canonical_component_id") or i)) for i, r in enumerate(reference)]

    release = [{"row": v.label, **release_check(v)} for v in prop_views]

    relations = []
    verdict_counter = Counter()

    for i in range(len(prop_views)):
        for j in range(i + 1, len(prop_views)):
            rel = classify(prop_views[i], prop_views[j], alias_map)
            rel["scope"] = "proposal_vs_proposal"
            relations.append(rel)
            verdict_counter[rel["verdict"]] += 1

    for pv in prop_views:
        for rv in ref_views:
            rel = classify(pv, rv, alias_map)
            rel["scope"] = "proposal_vs_reference"
            relations.append(rel)
            verdict_counter[rel["verdict"]] += 1

    collisions = [
        r for r in relations
        if r["verdict"] != "DISTINCT"
        or any(r["shared_shas"][k] for k in ("candidate", "carrier", "fix"))
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "proposal_rows": len(prop_views),
        "reference_rows": len(ref_views),
        "release_checks": release,
        "release_tally": dict(Counter(r["verdict"] for r in release)),
        "relations_total": len(relations),
        "collisions": collisions,
        "collision_tally": dict(verdict_counter),
    }


# --------------------------------------------------------------------------- #
# Negative controls (self-test)
# --------------------------------------------------------------------------- #

def _row(**kw) -> dict:
    return kw


def self_test() -> dict:
    """Pin the dedupe policy with synthetic negative controls."""
    alias_map: dict[str, str] = {}
    results = {}

    def verdict(label, a, b):
        results[label] = classify(RowView(a, label="A"), RowView(b, label="B"), alias_map)["verdict"]

    # NC1: shared candidate + shared fix, distinct mechanisms -> DISTINCT (never DUPLICATE).
    verdict(
        "nc1_shared_sha_distinct_mechanism",
        _row(case_id="GHSA-1111-1111-1111", repository="x/y",
             candidate_set=["a" * 40], minimum_fix_set=["b" * 40],
             source="src A", sink="sink A", invariant="inv A"),
        _row(case_id="GHSA-2222-2222-2222", repository="x/y",
             candidate_set=["a" * 40], minimum_fix_set=["b" * 40],
             source="src B", sink="sink B", invariant="inv B"),
    )

    # NC2: same mechanism + shared candidate/fix but NO alias identity -> CONFLICT (umbrella commit).
    verdict(
        "nc2_same_mechanism_shared_sha_no_identity",
        _row(case_id="GHSA-3333-3333-3333", repository="x/y",
             candidate_set=["a" * 40], minimum_fix_set=["b" * 40],
             source="same src", sink="same sink", invariant="same inv"),
        _row(case_id="GHSA-4444-4444-4444", repository="x/y",
             candidate_set=["a" * 40], minimum_fix_set=["b" * 40],
             source="same src", sink="same sink", invariant="same inv"),
    )

    # NC3: same mechanism_key, different IDs, no alias -> CONFLICT (never merge on key alone).
    verdict(
        "nc3_same_mechanism_key_no_identity",
        _row(case_id="GHSA-5555-5555-5555", repository="x/y", mechanism_key="foo",
             source="src A", sink="sink A", invariant="inv A"),
        _row(case_id="GHSA-6666-6666-6666", repository="x/y", mechanism_key="foo",
             source="src B", sink="sink B", invariant="inv B"),
    )

    # NC4: same public ID + same mechanism -> DUPLICATE.
    verdict(
        "nc4_same_id_same_mechanism",
        _row(case_id="GHSA-7777-7777-7777", repository="x/y",
             source="same src", sink="same sink", invariant="same inv"),
        _row(case_id="GHSA-7777-7777-7777", repository="x/y",
             source="same src", sink="same sink", invariant="same inv"),
    )

    # NC5: formal alias (same case via aliases) + same mechanism -> DUPLICATE.
    verdict(
        "nc5_formal_alias_same_mechanism",
        _row(case_id="GHSA-8888-8888-8888", aliases=["CVE-2026-9999"], repository="x/y",
             source="same src", sink="same sink", invariant="same inv"),
        _row(case_id="GHSA-8888-8888-8888", aliases=["CVE-2026-9999"], repository="x/y",
             source="same src", sink="same sink", invariant="same inv"),
    )

    # NC6: same public ID, distinct mechanisms -> ALIAS_SAME_COMPONENT (split rows).
    verdict(
        "nc6_same_id_distinct_mechanism",
        _row(case_id="GHSA-9999-9999-9999", repository="x/y",
             source="src A", sink="sink A", invariant="inv A"),
        _row(case_id="GHSA-9999-9999-9999", repository="x/y",
             source="src B", sink="sink B", invariant="inv B"),
    )

    # NC7: two different advisories in the same repo, each with a row-local
    # FORMAL_ALIAS relation to its OWN ids -> NOT aliases of each other -> DISTINCT.
    verdict(
        "nc7_row_local_formal_alias_not_cross_row",
        _row(case_id="GHSA-AAAA-AAAA-AAAA", aliases=["CVE-2026-1111"], repository="x/y",
             identity_relation="FORMAL_ALIAS",
             source="src A", sink="sink A", invariant="inv A"),
        _row(case_id="GHSA-BBBB-BBBB-BBBB", aliases=["CVE-2026-2222"], repository="x/y",
             identity_relation="FORMAL_ALIAS",
             source="src B", sink="sink B", invariant="inv B"),
    )

    expected = {
        "nc1_shared_sha_distinct_mechanism": "DISTINCT",
        "nc2_same_mechanism_shared_sha_no_identity": "CONFLICT",
        "nc3_same_mechanism_key_no_identity": "CONFLICT",
        "nc4_same_id_same_mechanism": "DUPLICATE",
        "nc5_formal_alias_same_mechanism": "DUPLICATE",
        "nc6_same_id_distinct_mechanism": "ALIAS_SAME_COMPONENT",
        "nc7_row_local_formal_alias_not_cross_row": "DISTINCT",
    }
    failures = {k: (results[k], expected[k]) for k in expected if results[k] != expected[k]}
    return {
        "schema_version": SCHEMA_VERSION,
        "pass": not failures,
        "expected": expected,
        "observed": results,
        "failures": failures,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("--root", type=Path, required=True)

    check_parser = sub.add_parser("check")
    check_parser.add_argument("--proposals", type=Path, required=True)
    check_parser.add_argument("--reference", type=Path, required=True)
    check_parser.add_argument("--alias-map", type=Path, default=None,
                              help="dispositions JSONL for first-party alias evidence")
    check_parser.add_argument("--output", type=Path, default=None)

    sub.add_parser("self-test")

    args = parser.parse_args(argv)

    if args.mode == "self-test":
        result = self_test()
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result["pass"] else 1

    if args.mode == "audit":
        result = audit(args.root)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    proposals = load_rows(args.proposals)
    reference = load_rows(args.reference)
    alias_map: dict[str, str] = {}
    if args.alias_map and args.alias_map.is_file():
        alias_map = build_alias_map_from_dispositions(load_jsonl(args.alias_map))
    else:
        alias_map = build_alias_map(reference)
    result = check(proposals, reference, alias_map)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n")
        print(f"WROTE {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
