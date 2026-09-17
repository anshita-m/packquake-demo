"""Pure functions: raw OSV/NVD/EPSS JSON in, plain data out.

No network, no disk, no Neo4j in this module -- fully unit-testable against
saved fixture JSON (see tests/fixtures/{osv,nvd,epss}/).
"""

from __future__ import annotations

from dataclasses import dataclass

from .cvss import InvalidCvssVector, cvss_v3_base_score, severity_from_score


@dataclass(frozen=True)
class CvssInfo:
    score: float
    severity: str
    vector: str
    version: str
    source: str  # "osv" | "nvd"


def extract_identity(osv_vuln: dict) -> tuple[str | None, str | None]:
    """Returns (cve_id, ghsa_id) from a full OSV vuln detail object.

    Either can come from the vuln's own `id` or from its `aliases`. A vuln
    can lack a CVE alias entirely (GHSA-only advisories happen); it cannot
    lack both, in practice, but callers should treat (None, None) as
    "unusable, skip it".
    """
    vuln_id = osv_vuln.get("id") or ""
    aliases = osv_vuln.get("aliases") or []

    cve_id = vuln_id if vuln_id.startswith("CVE-") else next(
        (a for a in aliases if a.startswith("CVE-")), None
    )
    ghsa_id = vuln_id if vuln_id.startswith("GHSA-") else next(
        (a for a in aliases if a.startswith("GHSA-")), None
    )
    return cve_id, ghsa_id


def extract_cvss_from_osv(osv_vuln: dict) -> CvssInfo | None:
    """Parse whatever CVSS OSV already gives us for this vuln.

    Prefers a CVSS_V3(.0/.1) vector, since we can compute a numeric base
    score from it ourselves (see cvss.py). A CVSS_V4-only vuln is treated as
    "no computable score" (we don't implement v4's macrovector table) and
    falls back to the caller trying NVD. The qualitative severity label
    prefers OSV/GHSA's own `database_specific.severity` (it's already been
    reviewed by a human) over one we derive from the score ourselves.
    """
    severity_entries = osv_vuln.get("severity") or []
    vector = next((e["score"] for e in severity_entries if e.get("type") == "CVSS_V3"), None)
    if vector is None:
        return None  # CVSS_V4-only or nothing at all -> let the caller fall back to NVD

    try:
        score = cvss_v3_base_score(vector)
    except InvalidCvssVector:
        return None

    label = (osv_vuln.get("database_specific") or {}).get("severity") or severity_from_score(score)
    version = vector.split("/", 1)[0].removeprefix("CVSS:")
    return CvssInfo(score=score, severity=label, vector=vector, version=version, source="osv")


_NVD_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30")


def extract_cvss_from_nvd(nvd_response: dict) -> CvssInfo | None:
    """Parse the primary CVSS v3.x metric out of an NVD CVE 2.0 API response.

    Falls back to CVSS v2 only if no v3 metric exists at all (rare for
    anything published after ~2016, but NVD does still carry v2 data for
    very old CVEs).
    """
    vulnerabilities = nvd_response.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve") or {}
    metrics = cve.get("metrics") or {}

    for key in _NVD_METRIC_KEYS:
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            score = float(data["baseScore"])
            severity = data.get("baseSeverity") or severity_from_score(score)
            return CvssInfo(
                score=score, severity=severity, vector=data.get("vectorString", ""),
                version=data.get("version", key[-2] + "." + key[-1]), source="nvd",
            )

    v2_entries = metrics.get("cvssMetricV2")
    if v2_entries:
        entry = v2_entries[0]
        data = entry["cvssData"]
        score = float(data["baseScore"])
        severity = entry.get("baseSeverity") or severity_from_score(score)
        return CvssInfo(score=score, severity=severity, vector=data.get("vectorString", ""), version="2.0", source="nvd")

    return None


def extract_epss(epss_row: dict | None) -> tuple[float, float] | None:
    """Parse one row of a FIRST.org EPSS API response. `epss_row` may be
    None if the CVE wasn't in EPSS's dataset -- returns None in that case."""
    if not epss_row:
        return None
    return float(epss_row["epss"]), float(epss_row["percentile"])
