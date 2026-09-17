from graph_builder.models import PackageKey
from graph_builder.neo4j_risk_writer import Neo4jRiskWriter
from graph_builder.risk_score import DEFAULT_WEIGHTS, compute_raw_factors, score_package

from .fakes import FakeDriver

LODASH = PackageKey("lodash", "4.17.21", "npm")


def _scored_entry():
    raw_factors = compute_raw_factors(
        vulnerabilities=[], betweenness_centrality=0.0, blast_radius_apps=["a", "b"], total_apps=4, runtime_exposure=0.7,
    )
    result = score_package(raw_factors, DEFAULT_WEIGHTS)
    return {"raw_factors": raw_factors, **result}


def test_write_risk_scores_uses_match_and_set():
    driver = FakeDriver()
    Neo4jRiskWriter(driver).write_risk_scores({LODASH: _scored_entry()})

    query, params = driver.calls[0]
    assert "MATCH (p:Package" in query
    assert "SET" in query
    assert "MERGE" not in query


def test_write_risk_scores_rows_carry_raw_and_weighted_and_risk_score():
    driver = FakeDriver()
    Neo4jRiskWriter(driver).write_risk_scores({LODASH: _scored_entry()})

    row = driver.calls[0][1]["rows"][0]
    assert row["name"] == "lodash"
    assert "cvss_normalized" in row
    assert "weighted_cvss_normalized" in row
    assert "risk_score" in row
    assert row["blast_radius_ratio"] == 0.5
    assert row["weighted_blast_radius_ratio"] == 0.1


def test_write_risk_scores_batched():
    driver = FakeDriver()
    scored = {
        PackageKey(f"pkg{i}", "1.0.0", "npm"): _scored_entry() for i in range(5)
    }
    Neo4jRiskWriter(driver, batch_size=2).write_risk_scores(scored)
    assert len(driver.calls) == 3  # ceil(5/2)


def test_write_risk_scores_empty_dict_emits_nothing():
    driver = FakeDriver()
    Neo4jRiskWriter(driver).write_risk_scores({})
    assert driver.calls == []
