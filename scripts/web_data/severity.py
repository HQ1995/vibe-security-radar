"""CVSS and severity parsing utilities for web data generation."""

from __future__ import annotations

import math

# ---------------------------------------------------------------------------
# CVSS 3.1 metric weight maps (from the CVSS v3.1 specification)
# ---------------------------------------------------------------------------

_CONF_MAP = {"high": 0.95, "medium": 0.7, "low": 0.4}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# ---------------------------------------------------------------------------
# Keyword-based severity inference for OSS-Fuzz and similar advisories
# ---------------------------------------------------------------------------

_SEVERITY_KEYWORDS: list[tuple[str, list[str]]] = [
    ("HIGH", [
        "heap-buffer-overflow", "use-after-free", "stack-buffer-overflow",
        "out-of-bounds-write", "double-free", "memory-corruption",
        "buffer-overflow", "arbitrary code execution", "remote code execution",
    ]),
    ("MEDIUM", [
        "integer-overflow", "null-dereference", "out-of-bounds-read",
        "divide-by-zero", "assertion-failure", "uninitialized-value",
        "denial of service",
    ]),
    ("LOW", [
        "timeout", "oom", "out-of-memory",
    ]),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_cvss_vector(vector_str: str) -> dict[str, str]:
    """Parse a CVSS:3.x vector string into a dict of metric -> value.

    Example: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    Returns: {"AV": "N", "AC": "L", "PR": "L", ...}
    """
    metrics: dict[str, str] = {}
    if not vector_str or not vector_str.startswith("CVSS:3"):
        return metrics

    parts = vector_str.split("/")
    for part in parts[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    return metrics


def _compute_cvss_score(metrics: dict[str, str]) -> float:
    """Compute a CVSS 3.1 base score from parsed metric values.

    Implements the official CVSS 3.1 scoring algorithm.
    Returns 0.0 if metrics are incomplete or invalid.
    """
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"

        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        pr = pr_table[metrics["PR"]]

        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return 0.0

    # Impact Sub-Score (ISS)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    # Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Base Score
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    # Round up to one decimal (CVSS spec: "round up")
    return math.ceil(base * 10) / 10


def _parse_cvss4_severity(vector_str: str) -> str:
    """Approximate severity label from a CVSS 4.0 vector string.

    CVSS 4.0 scoring is complex; we approximate using the impact metrics
    (VC/VI/VA for the vulnerable system) and exploitability (AV/AC/AT/PR/UI).

    Returns one of: CRITICAL, HIGH, MEDIUM, LOW, or empty string if unparseable.
    """
    if not vector_str or not vector_str.startswith("CVSS:4"):
        return ""

    metrics: dict[str, str] = {}
    parts = vector_str.split("/")
    for part in parts[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    # Vulnerable system impact: VC, VI, VA (H=High, L=Low, N=None)
    vc = metrics.get("VC", "N")
    vi = metrics.get("VI", "N")
    va = metrics.get("VA", "N")

    # Exploitability factors
    av = metrics.get("AV", "N")  # N=Network, A=Adjacent, L=Local, P=Physical
    ac = metrics.get("AC", "L")  # L=Low, H=High
    pr = metrics.get("PR", "N")  # N=None, L=Low, H=High
    ui = metrics.get("UI", "N")  # N=None, P=Passive, A=Active

    # Simple heuristic scoring
    impact_high = sum(1 for x in (vc, vi, va) if x == "H")
    impact_low = sum(1 for x in (vc, vi, va) if x == "L")
    no_impact = (vc == "N" and vi == "N" and va == "N")

    if no_impact:
        # Check subsequent system impact (SC/SI/SA)
        sc = metrics.get("SC", "N")
        si = metrics.get("SI", "N")
        sa = metrics.get("SA", "N")
        sub_high = sum(1 for x in (sc, si, sa) if x == "H")
        sub_low = sum(1 for x in (sc, si, sa) if x == "L")
        if sub_high == 0 and sub_low == 0:
            return "LOW"
        impact_high = sub_high
        impact_low = sub_low

    easy_exploit = (av == "N" and ac == "L" and pr == "N" and ui == "N")
    moderate_exploit = (av == "N" and ac == "L")

    if impact_high >= 3 and easy_exploit:
        return "CRITICAL"
    if impact_high >= 2 and moderate_exploit:
        return "CRITICAL" if easy_exploit else "HIGH"
    if impact_high >= 1:
        return "HIGH" if moderate_exploit else "MEDIUM"
    if impact_low >= 2:
        return "MEDIUM" if moderate_exploit else "LOW"
    if impact_low >= 1:
        return "LOW"
    return "LOW"


def _parse_severity_label(severity_str: str) -> str:
    """Convert a severity string to a label.

    Handles: CVSS V3 vectors, CVSS V4 vectors, plain text labels.
    Returns one of: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.
    """
    if not severity_str:
        return "UNKNOWN"

    # Plain text label (from GitHub Advisory API or GHSA database_specific)
    upper = severity_str.strip().upper()
    if upper == "MODERATE":
        upper = "MEDIUM"
    if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return upper

    # CVSS V3 vector
    if severity_str.startswith("CVSS:3"):
        score = _extract_cvss_score(severity_str)
        if score > 0:
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"

    # CVSS V4 vector
    if severity_str.startswith("CVSS:4"):
        label = _parse_cvss4_severity(severity_str)
        if label:
            return label

    return "UNKNOWN"


def _infer_severity_from_description(description: str, vuln_type: str = "") -> str:
    """Infer a severity label from description/vuln_type keywords.

    Checks HIGH keywords first, then MEDIUM, then LOW.
    Returns the highest severity found, or empty string if no match.
    """
    combined = f"{description} {vuln_type}".lower()
    for severity, keywords in _SEVERITY_KEYWORDS:
        for kw in keywords:
            if kw in combined:
                return severity
    return ""


def _score_to_label(score: float) -> str:
    """Convert a numeric CVSS score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_cvss_score(severity_str: str, pre_score: float = 0.0) -> float:
    """Extract a numeric CVSS score from a severity string or pre-computed value.

    If pre_score > 0, returns it directly.
    Otherwise attempts to parse the CVSS vector in severity_str.
    Returns 0.0 for empty or unparseable strings.
    """
    if pre_score > 0:
        return pre_score
    return _extract_cvss_score(severity_str)


def _extract_cvss_score(severity_str: str) -> float:
    """Extract a numeric CVSS score from a CVSS vector string.

    Handles CVSS V3 (exact) and V4 (approximate).
    Returns 0.0 for empty or unparseable strings.
    """
    if not severity_str:
        return 0.0
    # CVSS V3: exact scoring
    if severity_str.startswith("CVSS:3"):
        metrics = _parse_cvss_vector(severity_str)
        if metrics:
            return _compute_cvss_score(metrics)
    # CVSS V4: approximate from severity label
    if severity_str.startswith("CVSS:4"):
        label = _parse_cvss4_severity(severity_str)
        # Return midpoint of range as approximate score
        approx = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.5}
        return approx.get(label, 0.0)
    return 0.0


def parse_severity(
    severity_str: str,
    cvss_score: float = 0.0,
    ghsa_severity: str = "",
    description: str = "",
    vuln_type: str = "",
) -> str:
    """Unified severity resolution with full fallback chain.

    Resolution order:
    1. If cvss_score > 0, derive label from pre-computed score
    2. Try CVSS vector parsing from severity_str
    3. Try plain text label from severity_str
    4. Try GHSA severity fallback
    5. Try description/vuln_type keyword inference
    6. Return "UNKNOWN"

    Args:
        severity_str: Raw severity string (CVSS vector or plain label).
        cvss_score: Pre-computed CVSS score (takes priority when > 0).
        ghsa_severity: GHSA database severity label fallback.
        description: CVE description text for keyword inference.
        vuln_type: Vulnerability type string for keyword inference.

    Returns:
        One of: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.
    """
    # Step 1: pre-computed score overrides everything
    if cvss_score > 0:
        label = _parse_severity_label(severity_str)
        if label == "UNKNOWN":
            label = _score_to_label(cvss_score)
        return label

    # Step 2 & 3: CVSS vector parsing and plain label
    label = _parse_severity_label(severity_str)
    if label != "UNKNOWN":
        return label

    # Step 4: GHSA fallback
    if ghsa_severity:
        ghsa_label = _parse_severity_label(ghsa_severity)
        if ghsa_label != "UNKNOWN":
            return ghsa_label

    # Step 5: description keyword inference
    if description or vuln_type:
        inferred = _infer_severity_from_description(description, vuln_type)
        if inferred:
            return inferred

    return "UNKNOWN"
