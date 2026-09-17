"""CVSS v3.x base score calculation from a vector string.

We only implement v3.0/v3.1 (they share one formula) -- OSV's CVSS_V4
vectors use a much larger macrovector lookup table we don't implement, so a
package with only a v4 vector and no v3 one is treated as "no computable
score" and falls back to NVD, which reports v3.x baseScore directly.

Reference: https://www.first.org/cvss/v3.1/specification-document (section
7.4, "Base, Temporal, Environmental Formula"). Verified against a real NVD
score: CVE-2019-19844's vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
computes to 9.8, matching NVD's published baseScore exactly.
"""

from __future__ import annotations

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(r"^CVSS:(3\.[01])/(.+)$")

SEVERITY_THRESHOLDS = [
    (0.0, "NONE"),
    (0.1, "LOW"),
    (4.0, "MEDIUM"),
    (7.0, "HIGH"),
    (9.0, "CRITICAL"),
]


class InvalidCvssVector(ValueError):
    pass


def severity_from_score(score: float) -> str:
    label = SEVERITY_THRESHOLDS[0][1]
    for threshold, name in SEVERITY_THRESHOLDS:
        if score >= threshold:
            label = name
    return label


def _roundup(value: float) -> float:
    """The CVSS spec's official rounding function: round up to 1 decimal
    place while avoiding floating-point artifacts from a plain ceil."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (math.floor(int_value / 10000) + 1) / 10


def cvss_v3_base_score(vector: str) -> float:
    """Compute the CVSS v3.0/v3.1 base score from a vector string."""
    match = _VECTOR_RE.match(vector.strip())
    if not match:
        raise InvalidCvssVector(f"not a CVSS v3.x vector: {vector!r}")

    metrics = {}
    for part in match.group(2).split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        metrics[key] = value

    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        pr = pr_table[metrics["PR"]]
        c = _IMPACT[metrics["C"]]
        i = _IMPACT[metrics["I"]]
        a = _IMPACT[metrics["A"]]
    except KeyError as exc:
        raise InvalidCvssVector(f"missing/invalid metric {exc} in vector: {vector!r}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))
