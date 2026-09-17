import pytest

from graph_builder.risk_score import (
    DEFAULT_WEIGHTS,
    RAW_FACTOR_NAMES,
    blast_radius_ratio,
    centrality_normalized,
    compute_raw_factors,
    cvss_normalized,
    exploitability,
    score_package,
)


# --- individual raw factors ---

def test_cvss_normalized_takes_max_and_divides_by_ten():
    vulns = [{"cvss_score": 4.0, "epss_score": 0.1}, {"cvss_score": 9.8, "epss_score": 0.05}]
    assert cvss_normalized(vulns) == pytest.approx(0.98)


def test_cvss_normalized_empty_is_zero():
    assert cvss_normalized([]) == 0.0


def test_cvss_normalized_ignores_missing_scores():
    vulns = [{"cvss_score": None, "epss_score": 0.1}, {"cvss_score": 5.0, "epss_score": None}]
    assert cvss_normalized(vulns) == pytest.approx(0.5)


def test_cvss_normalized_all_missing_is_zero():
    vulns = [{"cvss_score": None}, {"cvss_score": None}]
    assert cvss_normalized(vulns) == 0.0


def test_exploitability_takes_max_no_division():
    vulns = [{"cvss_score": 9.0, "epss_score": 0.3}, {"cvss_score": 5.0, "epss_score": 0.7}]
    assert exploitability(vulns) == pytest.approx(0.7)


def test_exploitability_empty_is_zero():
    assert exploitability([]) == 0.0


def test_centrality_normalized_passes_through():
    assert centrality_normalized(0.1667) == pytest.approx(0.1667)


def test_centrality_normalized_none_is_zero():
    assert centrality_normalized(None) == 0.0


def test_blast_radius_ratio_basic():
    assert blast_radius_ratio(["a", "b"], 4) == pytest.approx(0.5)


def test_blast_radius_ratio_empty_apps_is_zero():
    assert blast_radius_ratio([], 4) == 0.0


def test_blast_radius_ratio_zero_total_apps_is_zero_not_a_crash():
    assert blast_radius_ratio(["a"], 0) == 0.0


# --- compute_raw_factors ---

def test_compute_raw_factors_zero_vulnerabilities_gives_zero_not_none_or_nan():
    factors = compute_raw_factors(
        vulnerabilities=[],
        betweenness_centrality=0.3,
        blast_radius_apps=["app1"],
        total_apps=4,
        runtime_exposure=0.5,
    )
    assert factors["cvss_normalized"] == 0.0
    assert factors["exploitability"] == 0.0
    assert all(isinstance(v, float) for v in factors.values())


def test_compute_raw_factors_empty_blast_radius_gives_zero_runtime_exposure_and_ratio():
    factors = compute_raw_factors(
        vulnerabilities=[],
        betweenness_centrality=0.0,
        blast_radius_apps=[],
        total_apps=4,
        runtime_exposure=0.0,  # caller is responsible for passing 0 when blast_radius_apps is empty
    )
    assert factors["blast_radius_ratio"] == 0.0
    assert factors["runtime_exposure"] == 0.0


def test_compute_raw_factors_returns_all_five_names():
    factors = compute_raw_factors(
        vulnerabilities=[], betweenness_centrality=0.0, blast_radius_apps=[], total_apps=4, runtime_exposure=0.0,
    )
    assert set(factors.keys()) == set(RAW_FACTOR_NAMES)


# --- score_package: the hand-worked-out test case ---

def test_score_package_matches_hand_computation():
    # CVSS=9.8 -> 0.98, EPSS=0.7, centrality=0.5, blast_radius 2/4 apps=0.5,
    # runtime_exposure=0.8, equal weights 0.2 each:
    #   0.2*0.98 + 0.2*0.7 + 0.2*0.5 + 0.2*0.5 + 0.2*0.8
    # = 0.196 + 0.14 + 0.1 + 0.1 + 0.16 = 0.696
    raw_factors = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        betweenness_centrality=0.5,
        blast_radius_apps=["app1", "app2"],
        total_apps=4,
        runtime_exposure=0.8,
    )
    result = score_package(raw_factors, DEFAULT_WEIGHTS)

    assert result["weighted_terms"]["cvss_normalized"] == pytest.approx(0.196)
    assert result["weighted_terms"]["exploitability"] == pytest.approx(0.14)
    assert result["weighted_terms"]["centrality_normalized"] == pytest.approx(0.1)
    assert result["weighted_terms"]["blast_radius_ratio"] == pytest.approx(0.1)
    assert result["weighted_terms"]["runtime_exposure"] == pytest.approx(0.16)
    assert result["risk_score"] == pytest.approx(0.696)


def test_score_package_stores_each_weighted_term_separately():
    raw_factors = {name: 0.5 for name in RAW_FACTOR_NAMES}
    result = score_package(raw_factors, DEFAULT_WEIGHTS)
    assert set(result["weighted_terms"].keys()) == set(RAW_FACTOR_NAMES)
    assert all(v == pytest.approx(0.1) for v in result["weighted_terms"].values())


# --- the retune path ---

def test_retuning_weights_changes_risk_score_without_touching_raw_factors():
    raw_factors = compute_raw_factors(
        vulnerabilities=[{"cvss_score": 9.8, "epss_score": 0.7}],
        betweenness_centrality=0.5,
        blast_radius_apps=["app1", "app2"],
        total_apps=4,
        runtime_exposure=0.8,
    )

    equal_weight_result = score_package(raw_factors, DEFAULT_WEIGHTS)

    cvss_heavy_weights = {
        "cvss_normalized": 0.6,
        "exploitability": 0.1,
        "centrality_normalized": 0.1,
        "blast_radius_ratio": 0.1,
        "runtime_exposure": 0.1,
    }
    retuned_result = score_package(raw_factors, cvss_heavy_weights)

    # same raw_factors dict passed to both calls -- proving no Neo4j/networkx
    # re-derivation was needed, just a different weights config.
    assert retuned_result["risk_score"] != pytest.approx(equal_weight_result["risk_score"])
    expected_retuned = 0.6 * 0.98 + 0.1 * 0.7 + 0.1 * 0.5 + 0.1 * 0.5 + 0.1 * 0.8
    assert retuned_result["risk_score"] == pytest.approx(expected_retuned)
    assert retuned_result["weighted_terms"]["cvss_normalized"] == pytest.approx(0.6 * 0.98)


def test_default_weights_are_equal_and_sum_to_one():
    assert len(set(DEFAULT_WEIGHTS.values())) == 1
    assert sum(DEFAULT_WEIGHTS.values()) == pytest.approx(1.0)
