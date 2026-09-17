from graph_builder.models import PackageKey
from graph_builder.neo4j_metrics_writer import Neo4jMetricsWriter
from graph_builder.structural_metrics import PackageMetrics

from .fakes import FakeDriver

LODASH = PackageKey("lodash", "4.17.21", "npm")
REQUESTS = PackageKey("requests", "2.31.0", "pypi")


def _metrics():
    return {
        LODASH: PackageMetrics(fan_in=2, depth=1, betweenness_centrality=0.15, blast_radius_apps=["hackathon-starter", "node-realworld"]),
        REQUESTS: PackageMetrics(fan_in=2, depth=1, betweenness_centrality=0.0, blast_radius_apps=["flack", "microblog"]),
    }


def test_write_metrics_uses_match_and_set_not_merge():
    driver = FakeDriver()
    Neo4jMetricsWriter(driver).write_metrics(_metrics())

    query, params = driver.calls[0]
    assert "MATCH (p:Package" in query
    assert "SET p.fan_in" in query
    assert "SET p.blast_radius_apps" not in query  # single SET clause, not one per field
    assert "MERGE" not in query


def test_write_metrics_rows_carry_all_four_properties():
    driver = FakeDriver()
    Neo4jMetricsWriter(driver).write_metrics(_metrics())

    rows = driver.calls[0][1]["rows"]
    row = next(r for r in rows if r["name"] == "lodash")
    assert row["fan_in"] == 2
    assert row["depth"] == 1
    assert row["betweenness_centrality"] == 0.15
    assert row["blast_radius_apps"] == ["hackathon-starter", "node-realworld"]


def test_write_metrics_is_batched():
    driver = FakeDriver()
    metrics = {
        PackageKey(f"pkg{i}", "1.0.0", "npm"): PackageMetrics(fan_in=1, depth=1, betweenness_centrality=0.0, blast_radius_apps=["app"])
        for i in range(5)
    }
    Neo4jMetricsWriter(driver, batch_size=2).write_metrics(metrics)
    assert len(driver.calls) == 3  # ceil(5/2)


def test_write_metrics_empty_dict_emits_no_queries():
    driver = FakeDriver()
    Neo4jMetricsWriter(driver).write_metrics({})
    assert driver.calls == []
