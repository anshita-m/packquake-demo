import pytest

from graph_builder.mitigation_ranking import PackageMitigationInput, explain_package, rank_mitigations
from graph_builder.models import PackageKey
from graph_builder.risk_score import DEFAULT_WEIGHTS, compute_raw_factors

WERKZEUG = PackageKey("werkzeug", "0.15.2", "pypi")
CLEAN_PKG = PackageKey("clean-pkg", "1.0.0", "npm")


def _raw_factors(**overrides):
    base = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        betweenness_centrality=0.5,
        blast_radius_apps=["app1", "app2"],
        total_apps=4,
        runtime_exposure=0.8,
    )
    base.update(overrides)
    return base


# --- Test 1: hand-computed risk_reduction ---

def test_risk_reduction_matches_hand_computation():
    # Same numbers as the Phase 6 hand-computed test: risk_score_before =
    # 0.696 (0.196 + 0.14 + 0.1 + 0.1 + 0.16). After patching, cvss_normalized
    # and exploitability go to 0, so risk_score_after = 0.1 + 0.1 + 0.16 = 0.36.
    # risk_reduction = 0.696 - 0.36 = 0.336.
    raw = _raw_factors()
    item = PackageMitigationInput(
        package=WERKZEUG, raw_factors=raw, vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        blast_radius_apps=["app1", "app2"], total_apps=4,
    )

    ranked = rank_mitigations([item], DEFAULT_WEIGHTS)

    assert len(ranked) == 1
    entry = ranked[0]
    assert entry["risk_score_before"] == pytest.approx(0.696)
    assert entry["risk_score_after"] == pytest.approx(0.36)
    assert entry["risk_reduction"] == pytest.approx(0.336)


def test_risk_reduction_only_zeroes_the_two_vuln_factors():
    raw = _raw_factors()
    item = PackageMitigationInput(
        package=WERKZEUG, raw_factors=raw, vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        blast_radius_apps=["app1", "app2"], total_apps=4,
    )
    ranked = rank_mitigations([item], DEFAULT_WEIGHTS)
    entry = ranked[0]
    # after-score should equal centrality + blast_radius + runtime_exposure weighted terms only
    expected_after = DEFAULT_WEIGHTS["centrality_normalized"] * raw["centrality_normalized"] \
        + DEFAULT_WEIGHTS["blast_radius_ratio"] * raw["blast_radius_ratio"] \
        + DEFAULT_WEIGHTS["runtime_exposure"] * raw["runtime_exposure"]
    assert entry["risk_score_after"] == pytest.approx(expected_after)


# --- Test 2: zero-vulnerability packages excluded entirely ---

def test_package_with_no_vulnerabilities_excluded_entirely():
    clean_raw = compute_raw_factors(
        vulnerabilities=[], betweenness_centrality=0.9, blast_radius_apps=["app1", "app2", "app3"],
        total_apps=4, runtime_exposure=0.9,
    )
    item = PackageMitigationInput(package=CLEAN_PKG, raw_factors=clean_raw, vulnerabilities=[])

    ranked = rank_mitigations([item], DEFAULT_WEIGHTS)

    assert ranked == []  # not included with risk_reduction=0 -- excluded entirely


def test_mixed_list_only_vulnerable_package_appears():
    vulnerable = PackageMitigationInput(
        package=WERKZEUG, raw_factors=_raw_factors(), vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        blast_radius_apps=["app1"], total_apps=4,
    )
    clean_raw = compute_raw_factors(vulnerabilities=[], betweenness_centrality=0.1, blast_radius_apps=[], total_apps=4, runtime_exposure=0.0)
    clean = PackageMitigationInput(package=CLEAN_PKG, raw_factors=clean_raw, vulnerabilities=[])

    ranked = rank_mitigations([vulnerable, clean], DEFAULT_WEIGHTS)

    assert len(ranked) == 1
    assert ranked[0]["package"]["name"] == "werkzeug"


# --- priority / sorting ---

def test_priority_uses_effort_when_fixed_version_known():
    raw = _raw_factors()
    item = PackageMitigationInput(
        package=WERKZEUG, raw_factors=raw, vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        fixed_version="1.0.0",  # major jump from 0.15.2 -> effort HIGH (3)
    )
    ranked = rank_mitigations([item], DEFAULT_WEIGHTS)
    entry = ranked[0]
    assert entry["effort"] == 3
    assert entry["priority"] == pytest.approx(entry["risk_reduction"] / 3)


def test_priority_falls_back_to_risk_reduction_when_no_fixed_version():
    raw = _raw_factors()
    item = PackageMitigationInput(
        package=WERKZEUG, raw_factors=raw, vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        fixed_version=None,
    )
    ranked = rank_mitigations([item], DEFAULT_WEIGHTS)
    entry = ranked[0]
    assert entry["effort"] is None
    assert entry["priority"] == pytest.approx(entry["risk_reduction"])


def test_results_sorted_by_priority_descending():
    high_priority = PackageMitigationInput(
        package=PackageKey("high", "1.0.0", "npm"),
        raw_factors=_raw_factors(),
        vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.9}],
        fixed_version="1.0.1",  # patch-level -> effort 1, cheap+effective
    )
    low_priority = PackageMitigationInput(
        package=PackageKey("low", "1.0.0", "npm"),
        raw_factors=_raw_factors(cvss_normalized=0.1, exploitability=0.05),
        vulnerabilities=[{"cvss_score": 1.0, "epss_score": 0.05}],
        fixed_version="2.0.0",  # major jump -> effort 3, expensive+low-value
    )

    ranked = rank_mitigations([low_priority, high_priority], DEFAULT_WEIGHTS)

    assert [e["package"]["name"] for e in ranked] == ["high", "low"]
    assert ranked[0]["priority"] >= ranked[1]["priority"]


def test_return_shape_is_json_serializable():
    import json
    raw = _raw_factors()
    item = PackageMitigationInput(
        package=WERKZEUG, raw_factors=raw, vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        blast_radius_apps=["app1"], total_apps=4, fixed_version="0.15.3",
    )
    ranked = rank_mitigations([item], DEFAULT_WEIGHTS)
    json.dumps(ranked)  # must not raise


# --- Test 4: explanation generator names the dominant factor(s) ---

def test_explanation_names_cvss_when_dominant():
    raw = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 9.6, "epss_score": 0.1}],
        betweenness_centrality=0.0, blast_radius_apps=[], total_apps=4, runtime_exposure=0.0,
    )
    weighted = {name: DEFAULT_WEIGHTS[name] * raw[name] for name in raw}
    explanation = explain_package(raw, weighted, [], 4)
    assert "CVSS 9.6" in explanation


def test_explanation_names_blast_radius_when_dominant():
    raw = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 1.0, "epss_score": 0.01}],  # small
        betweenness_centrality=0.0, blast_radius_apps=["a", "b", "c"], total_apps=4, runtime_exposure=0.0,
    )
    weighted = {name: DEFAULT_WEIGHTS[name] * raw[name] for name in raw}
    explanation = explain_package(raw, weighted, ["a", "b", "c"], 4)
    assert "affects 3 of 4 apps" in explanation


def test_explanation_switches_dominant_factor_based_on_inputs():
    # Prove it's not always mentioning the same factor -- two different
    # inputs should produce different leading explanations.
    cvss_dominant_raw = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 9.9, "epss_score": 0.0}], betweenness_centrality=0.0,
        blast_radius_apps=[], total_apps=4, runtime_exposure=0.0,
    )
    centrality_dominant_raw = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 0.1, "epss_score": 0.0}], betweenness_centrality=0.9,
        blast_radius_apps=[], total_apps=4, runtime_exposure=0.0,
    )
    w1 = {name: DEFAULT_WEIGHTS[name] * cvss_dominant_raw[name] for name in cvss_dominant_raw}
    w2 = {name: DEFAULT_WEIGHTS[name] * centrality_dominant_raw[name] for name in centrality_dominant_raw}

    exp1 = explain_package(cvss_dominant_raw, w1, [], 4)
    exp2 = explain_package(centrality_dominant_raw, w2, [], 4)

    assert exp1 != exp2
    assert "CVSS" in exp1
    assert "structurally central" in exp2


def test_explanation_omits_exploitability_below_threshold():
    raw = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 9.9, "epss_score": 0.2}],  # EPSS below 0.5 threshold
        betweenness_centrality=0.0, blast_radius_apps=[], total_apps=4, runtime_exposure=0.0,
    )
    weighted = {name: DEFAULT_WEIGHTS[name] * raw[name] for name in raw}
    explanation = explain_package(raw, weighted, [], 4)
    assert "exploited" not in explanation


def test_explanation_includes_exploitability_above_threshold():
    raw = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 5.0, "epss_score": 0.8}],
        betweenness_centrality=0.0, blast_radius_apps=[], total_apps=4, runtime_exposure=0.0,
    )
    weighted = {name: DEFAULT_WEIGHTS[name] * raw[name] for name in raw}
    explanation = explain_package(raw, weighted, [], 4)
    assert "actively exploited" in explanation
    assert "0.80" in explanation


def test_explanation_all_zero_factors_has_graceful_fallback():
    raw = {name: 0.0 for name in ("cvss_normalized", "exploitability", "centrality_normalized", "blast_radius_ratio", "runtime_exposure")}
    weighted = {name: 0.0 for name in raw}
    explanation = explain_package(raw, weighted, [], 4)
    assert explanation  # non-empty, doesn't crash
