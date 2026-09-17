from graph_builder.models import DependsOnEdge, Graph, PackageKey
from graph_builder.neo4j_writer import Neo4jWriter

from .fakes import FakeDriver

LODASH = PackageKey("lodash", "4.17.21", "npm")
REQUESTS = PackageKey("requests", "2.31.0", "pypi")


def _graph():
    g = Graph()
    g.applications = {"hackathon-starter", "node-realworld"}
    g.packages = {LODASH, REQUESTS}
    g.depends_on = {
        ("hackathon-starter", LODASH): DependsOnEdge("hackathon-starter", LODASH, True, 1),
        ("node-realworld", LODASH): DependsOnEdge("node-realworld", LODASH, True, 1),
    }
    g.requires = {(LODASH, REQUESTS)}
    return g


def test_write_graph_issues_constraints_first():
    driver = FakeDriver()
    Neo4jWriter(driver).write_graph(_graph())

    assert "CREATE CONSTRAINT app_id_unique" in driver.calls[0][0]
    assert "CREATE CONSTRAINT package_key_unique" in driver.calls[1][0]


def test_write_graph_uses_merge_for_every_node_and_edge_type():
    driver = FakeDriver()
    Neo4jWriter(driver).write_graph(_graph())

    queries = [q for q, _ in driver.calls]
    assert any("MERGE (a:Application" in q for q in queries)
    assert any("MERGE (p:Package" in q for q in queries)
    assert any("MERGE (a)-[r:DEPENDS_ON]->(p)" in q for q in queries)
    assert any("MERGE (p1)-[:REQUIRES]->(p2)" in q for q in queries)


def test_depends_on_rows_carry_direct_and_depth():
    driver = FakeDriver()
    Neo4jWriter(driver).write_graph(_graph())

    depends_on_calls = [(q, params) for q, params in driver.calls if "DEPENDS_ON" in q]
    assert len(depends_on_calls) == 1
    rows = depends_on_calls[0][1]["rows"]
    assert len(rows) == 2
    assert all("direct" in row and "depth" in row for row in rows)


def test_writes_are_batched():
    driver = FakeDriver()
    graph = Graph()
    graph.applications = {f"app{i}" for i in range(5)}
    graph.packages = set()
    graph.depends_on = {}
    graph.requires = set()

    Neo4jWriter(driver, batch_size=2).write_graph(graph)

    app_calls = [(q, params) for q, params in driver.calls if "Application" in q and "MERGE" in q]
    assert len(app_calls) == 3  # ceil(5/2)
    assert [len(params["rows"]) for _, params in app_calls] == [2, 2, 1]


def test_empty_collections_emit_no_queries():
    driver = FakeDriver()
    Neo4jWriter(driver).write_graph(Graph())

    # Only the two constraint queries should run when there's nothing to write.
    assert len(driver.calls) == 2
