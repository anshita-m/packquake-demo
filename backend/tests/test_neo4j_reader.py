from graph_builder.models import PackageKey
from graph_builder.neo4j_reader import read_graph_from_neo4j


class FakeRecord(dict):
    def __getitem__(self, key):
        return dict.__getitem__(self, key)


class FakeReadSession:
    """Returns a canned row-list per query, matched by a substring so test
    setup doesn't have to hardcode query text verbatim."""

    def __init__(self, routing: list[tuple[str, list[dict]]]):
        self._routing = routing

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return None

    def run(self, query: str, **_kwargs):
        for substring, rows in self._routing:
            if substring in query:
                return [FakeRecord(r) for r in rows]
        raise AssertionError(f"no fake response configured for query: {query}")


class FakeReadDriver:
    def __init__(self, routing: list[tuple[str, list[dict]]]):
        self._routing = routing

    def session(self):
        return FakeReadSession(self._routing)


LODASH = {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}


def _driver():
    return FakeReadDriver([
        ("MATCH (a:Application) RETURN", [{"app_id": "hackathon-starter"}, {"app_id": "node-realworld"}]),
        ("MATCH (p:Package) RETURN", [LODASH]),
        (
            "MATCH (a:Application)-[r:DEPENDS_ON]->(p:Package)",
            [
                {"app_id": "hackathon-starter", **LODASH, "direct": True, "depth": 1},
                {"app_id": "node-realworld", **LODASH, "direct": True, "depth": 1},
            ],
        ),
        ("MATCH (p1:Package)-[r:REQUIRES]->(p2:Package)", []),
    ])


def test_read_graph_builds_application_and_package_nodes():
    graph = read_graph_from_neo4j(_driver())

    assert graph.nodes["hackathon-starter"]["node_type"] == "application"
    assert graph.nodes["node-realworld"]["node_type"] == "application"

    key = PackageKey("lodash", "4.17.21", "npm")
    assert graph.nodes[key]["node_type"] == "package"
    assert graph.nodes[key]["name"] == "lodash"


def test_read_graph_builds_depends_on_edges_with_properties():
    graph = read_graph_from_neo4j(_driver())
    key = PackageKey("lodash", "4.17.21", "npm")

    edge = graph.edges["hackathon-starter", key]
    assert edge["edge_type"] == "DEPENDS_ON"
    assert edge["direct"] is True
    assert edge["depth"] == 1


def test_read_graph_builds_requires_edges():
    driver = FakeReadDriver([
        ("MATCH (a:Application) RETURN", []),
        (
            "MATCH (p:Package) RETURN",
            [
                {"name": "a", "version": "1.0.0", "ecosystem": "npm"},
                {"name": "b", "version": "1.0.0", "ecosystem": "npm"},
            ],
        ),
        ("MATCH (a:Application)-[r:DEPENDS_ON]->(p:Package)", []),
        (
            "MATCH (p1:Package)-[r:REQUIRES]->(p2:Package)",
            [{"n1": "a", "v1": "1.0.0", "e1": "npm", "n2": "b", "v2": "1.0.0", "e2": "npm", "blocks_propagation": None}],
        ),
    ])

    graph = read_graph_from_neo4j(driver)
    a = PackageKey("a", "1.0.0", "npm")
    b = PackageKey("b", "1.0.0", "npm")
    assert graph.edges[a, b]["edge_type"] == "REQUIRES"


def test_read_graph_requires_edge_carries_blocks_propagation_when_set():
    driver = FakeReadDriver([
        ("MATCH (a:Application) RETURN", []),
        (
            "MATCH (p:Package) RETURN",
            [
                {"name": "a", "version": "1.0.0", "ecosystem": "npm"},
                {"name": "b", "version": "1.0.0", "ecosystem": "npm"},
            ],
        ),
        ("MATCH (a:Application)-[r:DEPENDS_ON]->(p:Package)", []),
        (
            "MATCH (p1:Package)-[r:REQUIRES]->(p2:Package)",
            [{"n1": "a", "v1": "1.0.0", "e1": "npm", "n2": "b", "v2": "1.0.0", "e2": "npm", "blocks_propagation": True}],
        ),
    ])

    graph = read_graph_from_neo4j(driver)
    a = PackageKey("a", "1.0.0", "npm")
    b = PackageKey("b", "1.0.0", "npm")
    assert graph.edges[a, b]["blocks_propagation"] is True


def test_read_graph_requires_edge_blocks_propagation_defaults_none_when_absent():
    driver = FakeReadDriver([
        ("MATCH (a:Application) RETURN", []),
        (
            "MATCH (p:Package) RETURN",
            [
                {"name": "a", "version": "1.0.0", "ecosystem": "npm"},
                {"name": "b", "version": "1.0.0", "ecosystem": "npm"},
            ],
        ),
        ("MATCH (a:Application)-[r:DEPENDS_ON]->(p:Package)", []),
        (
            "MATCH (p1:Package)-[r:REQUIRES]->(p2:Package)",
            # no "blocks_propagation" key at all in the row, matching a real
            # driver Record's .get() behavior when the property was never set
            [{"n1": "a", "v1": "1.0.0", "e1": "npm", "n2": "b", "v2": "1.0.0", "e2": "npm"}],
        ),
    ])

    graph = read_graph_from_neo4j(driver)
    a = PackageKey("a", "1.0.0", "npm")
    b = PackageKey("b", "1.0.0", "npm")
    assert graph.edges[a, b]["blocks_propagation"] is None


def test_read_graph_handles_empty_database():
    driver = FakeReadDriver([
        ("MATCH (a:Application) RETURN", []),
        ("MATCH (p:Package) RETURN", []),
        ("MATCH (a:Application)-[r:DEPENDS_ON]->(p:Package)", []),
        ("MATCH (p1:Package)-[r:REQUIRES]->(p2:Package)", []),
    ])
    graph = read_graph_from_neo4j(driver)
    assert len(graph.nodes) == 0
    assert len(graph.edges) == 0
