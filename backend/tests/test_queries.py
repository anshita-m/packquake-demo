from graph_builder.graph_merge import merge_apps
from graph_builder.models import DependsOnEdge, PackageKey, ParsedApp, VulnGraph, Vulnerability
from graph_builder.queries import apps_depending_on, package_node_count, vulnerabilities_for_app, vulnerabilities_for_package

LODASH = PackageKey("lodash", "4.17.21", "npm")


def _app(app_id, package):
    return ParsedApp(app_id=app_id, depends_on=[DependsOnEdge(app_id=app_id, package=package, direct=True, depth=1)])


def test_apps_depending_on_returns_all_depending_apps_sorted():
    graph = merge_apps([_app("node-realworld", LODASH), _app("hackathon-starter", LODASH)])

    assert apps_depending_on(graph, "lodash", "4.17.21", "npm") == ["hackathon-starter", "node-realworld"]


def test_apps_depending_on_empty_when_package_absent():
    graph = merge_apps([_app("hackathon-starter", LODASH)])

    assert apps_depending_on(graph, "left-pad", "1.0.0", "npm") == []


def test_package_node_count_is_one_for_shared_package_not_two():
    graph = merge_apps([_app("hackathon-starter", LODASH), _app("node-realworld", LODASH)])

    assert package_node_count(graph, "lodash", "4.17.21", "npm") == 1
    assert len(graph.packages) == 1


def test_vulnerabilities_for_package_and_app():
    django = PackageKey("django", "1.10.5", "pypi")
    graph = merge_apps([_app("django-realworld", django)])

    vuln = Vulnerability(vuln_id="CVE-2019-19844", id_type="cve", cvss_score=9.8)
    vuln_graph = VulnGraph(vulnerabilities={"CVE-2019-19844": vuln}, affected_by={(django, "CVE-2019-19844")})

    assert vulnerabilities_for_package(vuln_graph, django) == [vuln]
    result = vulnerabilities_for_app(graph, vuln_graph, "django-realworld")
    assert result == {django: [vuln]}


def test_vulnerabilities_for_app_excludes_clean_packages():
    clean = PackageKey("clean-pkg", "1.0.0", "npm")
    graph = merge_apps([_app("hackathon-starter", clean)])
    vuln_graph = VulnGraph()

    assert vulnerabilities_for_app(graph, vuln_graph, "hackathon-starter") == {}
