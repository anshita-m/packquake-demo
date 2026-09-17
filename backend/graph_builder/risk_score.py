"""Phase 6: composite risk score.

Two layers of pure functions, deliberately separate:
  - the 5 raw factor functions (this module's `compute_raw_factors` and its
    pieces) take already-fetched package data and return floats in [0,1] --
    unit-testable with hand-built inputs, no Neo4j needed.
  - `score_package` takes those raw factors plus a weights config and does
    the weighted-sum math -- this is what makes retuning weights cheap (a
    re-sum over stored raw factors, not a full pipeline rerun) and it's
    also what a later "explain reasoning" feature would call.
"""

from __future__ import annotations

from typing import Iterable, Mapping

RAW_FACTOR_NAMES = (
    "cvss_normalized",
    "exploitability",
    "centrality_normalized",
    "blast_radius_ratio",
    "runtime_exposure",
)

# Start equal; retuning is just editing this dict and calling score_package
# again over already-stored raw factors.
DEFAULT_WEIGHTS: dict[str, float] = {name: 0.2 for name in RAW_FACTOR_NAMES}


def cvss_normalized(vulnerabilities: Iterable[Mapping]) -> float:
    """Worst-case CVE drives the score: max cvss_score among the package's
    Vulnerability nodes, divided by 10. 0.0 if there are none (or Phase 3
    hasn't enriched this package yet) -- not None, not an error."""
    scores = [v["cvss_score"] for v in vulnerabilities if v.get("cvss_score") is not None]
    return max(scores) / 10 if scores else 0.0


def exploitability(vulnerabilities: Iterable[Mapping]) -> float:
    """Same aggregation as cvss_normalized (max across vulnerabilities),
    using epss_score, which is already in [0,1]."""
    scores = [v["epss_score"] for v in vulnerabilities if v.get("epss_score") is not None]
    return max(scores) if scores else 0.0


def centrality_normalized(betweenness_centrality: float | None) -> float:
    """The package's Phase 4 betweenness_centrality, used as-is --
    networkx's betweenness_centrality is normalized to [0,1] by default
    (structural_metrics.compute_betweenness_centrality leaves that on), so
    no re-normalization here. None (property never written) counts as 0."""
    return betweenness_centrality if betweenness_centrality is not None else 0.0


def blast_radius_ratio(blast_radius_apps: Iterable[str], total_apps: int) -> float:
    """Fraction of all Applications in the graph this package would affect
    if compromised. 0.0 if there are no apps at all (can't divide by zero)."""
    if total_apps <= 0:
        return 0.0
    return len(list(blast_radius_apps)) / total_apps


def compute_raw_factors(
    *,
    vulnerabilities: Iterable[Mapping],
    betweenness_centrality: float | None,
    blast_radius_apps: Iterable[str],
    total_apps: int,
    runtime_exposure: float,
) -> dict[str, float]:
    """All 5 raw factors for one package, as a {factor_name: value} dict."""
    vulnerabilities = list(vulnerabilities)
    return {
        "cvss_normalized": cvss_normalized(vulnerabilities),
        "exploitability": exploitability(vulnerabilities),
        "centrality_normalized": centrality_normalized(betweenness_centrality),
        "blast_radius_ratio": blast_radius_ratio(blast_radius_apps, total_apps),
        "runtime_exposure": runtime_exposure,
    }


def score_package(raw_factors: Mapping[str, float], weights: Mapping[str, float] = DEFAULT_WEIGHTS) -> dict:
    """weighted_terms = {factor: weight * raw_value}, risk_score = sum(weighted_terms.values())."""
    weighted_terms = {name: weights[name] * raw_factors[name] for name in raw_factors}
    risk_score = sum(weighted_terms.values())
    return {"weighted_terms": weighted_terms, "risk_score": risk_score}
