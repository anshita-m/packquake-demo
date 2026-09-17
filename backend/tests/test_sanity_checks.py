import pytest

from graph_builder.graph_merge import merge_apps
from graph_builder.models import DependsOnEdge, PackageKey, ParsedApp
from graph_builder.sanity_checks import SanityCheckError, check_shared_package

LODASH = PackageKey("lodash", "4.17.21", "npm")


def _app(app_id, package, depth=1, direct=True):
    return ParsedApp(app_id=app_id, depends_on=[DependsOnEdge(app_id=app_id, package=package, direct=direct, depth=depth)])


def test_passes_when_all_expected_apps_present():
    graph = merge_apps([_app("hackathon-starter", LODASH), _app("node-realworld", LODASH)])

    check_shared_package(graph, "lodash", "4.17.21", "npm", ["hackathon-starter", "node-realworld"])


def test_raises_not_found_with_specific_diagnosis():
    graph = merge_apps([_app("hackathon-starter", PackageKey("lodash", "4.17.20", "npm"))])

    with pytest.raises(SanityCheckError, match="not found as a Package node"):
        check_shared_package(graph, "lodash", "4.17.21", "npm", ["hackathon-starter", "node-realworld"])


def test_raises_fan_in_too_low_with_specific_diagnosis():
    graph = merge_apps([_app("hackathon-starter", LODASH)])  # node-realworld missing

    with pytest.raises(SanityCheckError, match="fan-in too low") as exc_info:
        check_shared_package(graph, "lodash", "4.17.21", "npm", ["hackathon-starter", "node-realworld"])
    assert "node-realworld" in str(exc_info.value)


def test_extra_apps_beyond_expected_still_pass():
    graph = merge_apps([
        _app("microblog", PackageKey("requests", "2.31.0", "pypi")),
        _app("django-realworld", PackageKey("requests", "2.31.0", "pypi")),
        _app("flack", PackageKey("requests", "2.31.0", "pypi")),
        _app("bonus-app", PackageKey("requests", "2.31.0", "pypi")),
    ])

    check_shared_package(graph, "requests", "2.31.0", "pypi", ["microblog", "django-realworld", "flack"])
