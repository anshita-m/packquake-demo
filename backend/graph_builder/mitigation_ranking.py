"""Phase 7: mitigation ranking.

The key thing this deliberately does NOT do: re-touch graph structure.
"What if this package were patched" only zeroes its own two
vulnerability-derived raw factors (cvss_normalized, exploitability) --
centrality/blast_radius/runtime_exposure don't change, because patching a
CVE doesn't change who depends on the package. Reuses Phase 6's
score_package directly for both the before and after score; no second
scoring implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from .cvss import severity_from_score
from .mitigation_effort import classify_version_jump
from .models import PackageKey
from .risk_score import DEFAULT_WEIGHTS, score_package

EXPLOITABILITY_MENTION_THRESHOLD = 0.5  # EPSS above this counts as "actively exploited"


@dataclass
class PackageMitigationInput:
    """Already-loaded data for one vulnerable package -- no Neo4j/network
    calls happen inside rank_mitigations itself, only over data like this."""

    package: PackageKey
    raw_factors: dict[str, float]
    vulnerabilities: list[dict]  # non-empty is what makes a package eligible at all
    blast_radius_apps: list[str] = field(default_factory=list)
    total_apps: int = 0
    fixed_version: str | None = None


def _phrase_cvss(raw_factors: Mapping[str, float]) -> str | None:
    score = raw_factors["cvss_normalized"] * 10
    if score <= 0:
        return None
    return f"{severity_from_score(score).lower()} CVE (CVSS {score:.1f})"


def _phrase_exploitability(raw_factors: Mapping[str, float]) -> str | None:
    epss = raw_factors["exploitability"]
    if epss > EXPLOITABILITY_MENTION_THRESHOLD:
        return f"actively exploited (EPSS {epss:.2f})"
    return None


def _phrase_centrality(raw_factors: Mapping[str, float]) -> str | None:
    if raw_factors["centrality_normalized"] <= 0:
        return None
    return "structurally central in the dependency graph"


def _phrase_blast_radius(raw_factors: Mapping[str, float], blast_radius_apps: list[str], total_apps: int) -> str | None:
    if not blast_radius_apps or total_apps <= 0:
        return None
    return f"affects {len(blast_radius_apps)} of {total_apps} apps"


def _phrase_runtime_exposure(raw_factors: Mapping[str, float]) -> str | None:
    if raw_factors["runtime_exposure"] <= 0:
        return None
    return "internet-facing exposure"


_PHRASE_BUILDERS = {
    "cvss_normalized": lambda raw, ctx: _phrase_cvss(raw),
    "exploitability": lambda raw, ctx: _phrase_exploitability(raw),
    "centrality_normalized": lambda raw, ctx: _phrase_centrality(raw),
    "blast_radius_ratio": lambda raw, ctx: _phrase_blast_radius(raw, ctx["blast_radius_apps"], ctx["total_apps"]),
    "runtime_exposure": lambda raw, ctx: _phrase_runtime_exposure(raw),
}


def explain_package(
    raw_factors: Mapping[str, float],
    weighted_terms: Mapping[str, float],
    blast_radius_apps: list[str],
    total_apps: int,
) -> str:
    """A deterministic one-sentence explanation naming the 1-2 largest
    contributing factors. "Largest contributing" is ranked by weighted-term
    magnitude (what actually drove risk_score up), not raw factor magnitude
    -- a factor with a small weight shouldn't outrank one with a bigger
    weight just because its raw value happens to be larger. A factor whose
    phrase-builder has nothing worth saying (e.g. exploitability below the
    EPSS threshold, or a genuinely-zero factor) is skipped in favor of the
    next-ranked one, not left as a gap.
    """
    ctx = {"blast_radius_apps": blast_radius_apps, "total_apps": total_apps}
    ranked_names = sorted(weighted_terms, key=lambda name: -weighted_terms[name])

    phrases = []
    for name in ranked_names:
        phrase = _PHRASE_BUILDERS[name](raw_factors, ctx)
        if phrase:
            phrases.append(phrase)
        if len(phrases) == 2:
            break

    return ", ".join(phrases) if phrases else "no significant risk factors"


def rank_mitigations(packages: list[PackageMitigationInput], weights: Mapping[str, float] = DEFAULT_WEIGHTS) -> list[dict]:
    """Ranked mitigation list, most worth fixing first.

    Sorted by `priority`, consistently, for every row: `risk_reduction /
    effort` when a patch-effort estimate exists, or `risk_reduction` alone
    when it doesn't (no fixed version found in the cached OSV data) --
    `effort` itself stays None in that row so callers can tell the
    difference, but `priority` is always a plain number so one sort key
    works for the whole list.

    Packages with no AFFECTED_BY vulnerabilities at all are excluded
    entirely (nothing to patch), not included with risk_reduction=0.
    """
    results = []

    for item in packages:
        if not item.vulnerabilities:
            continue

        before = score_package(item.raw_factors, weights)
        patched_factors = {**item.raw_factors, "cvss_normalized": 0.0, "exploitability": 0.0}
        after = score_package(patched_factors, weights)

        risk_score_before = before["risk_score"]
        risk_score_after = after["risk_score"]
        risk_reduction = risk_score_before - risk_score_after

        effort = classify_version_jump(item.package.version, item.fixed_version) if item.fixed_version else None
        priority = risk_reduction / effort if effort else risk_reduction

        explanation = explain_package(item.raw_factors, before["weighted_terms"], item.blast_radius_apps, item.total_apps)

        results.append({
            "package": {"name": item.package.name, "version": item.package.version, "ecosystem": item.package.ecosystem},
            "risk_score_before": risk_score_before,
            "risk_score_after": risk_score_after,
            "risk_reduction": risk_reduction,
            "fixed_version": item.fixed_version,
            "effort": effort,
            "priority": priority,
            "explanation": explanation,
        })

    results.sort(key=lambda r: -r["priority"])
    return results
