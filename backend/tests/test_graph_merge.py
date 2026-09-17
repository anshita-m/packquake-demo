from graph_builder.graph_merge import merge_apps
from graph_builder.models import DependsOnEdge, PackageKey, ParsedApp, RequiresEdge

LODASH = PackageKey("lodash", "4.17.21", "npm")


def test_shared_package_dedups_to_one_node_two_edges():
    app1 = ParsedApp(
        app_id="hackathon-starter",
        depends_on=[DependsOnEdge(app_id="hackathon-starter", package=LODASH, direct=True, depth=1)],
    )
    app2 = ParsedApp(
        app_id="node-realworld",
        depends_on=[DependsOnEdge(app_id="node-realworld", package=LODASH, direct=True, depth=1)],
    )

    graph = merge_apps([app1, app2])

    assert graph.packages == {LODASH}
    assert len(graph.depends_on) == 2
    assert graph.applications == {"hackathon-starter", "node-realworld"}


def test_merge_keeps_shortest_depth_on_duplicate_app_package_pair():
    edge_far = DependsOnEdge(app_id="app", package=LODASH, direct=False, depth=3)
    edge_near = DependsOnEdge(app_id="app", package=LODASH, direct=True, depth=1)
    app = ParsedApp(app_id="app", depends_on=[edge_far, edge_near])

    graph = merge_apps([app])

    kept = graph.depends_on[("app", LODASH)]
    assert kept.depth == 1
    assert kept.direct is True


def test_requires_edges_dedup_across_apps():
    a = PackageKey("a", "1.0.0", "npm")
    b = PackageKey("b", "1.0.0", "npm")
    app1 = ParsedApp(app_id="app1", requires=[RequiresEdge(source=a, target=b)])
    app2 = ParsedApp(app_id="app2", requires=[RequiresEdge(source=a, target=b)])

    graph = merge_apps([app1, app2])

    assert graph.requires == {(a, b)}
    assert graph.packages == {a, b}


def test_empty_input_yields_empty_graph():
    graph = merge_apps([])
    assert graph.applications == set()
    assert graph.packages == set()
    assert graph.depends_on == {}
    assert graph.requires == set()
