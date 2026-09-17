import pytest

from graph_builder.models import PackageKey
from graph_builder.neo4j_propagation import get_blocks_propagation, set_blocks_propagation

X = PackageKey("x", "1.0.0", "npm")
LODASH = PackageKey("lodash", "4.17.21", "npm")


class FakeResult:
    def __init__(self, record):
        self._record = record

    def single(self):
        return self._record


class FakeSession:
    def __init__(self, driver):
        self._driver = driver

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return None

    def run(self, query, **params):
        self._driver.calls.append((query, params))
        edge = (params["dn"], params["dv"], params["de"], params["en"], params["ev"], params["ee"])
        if edge not in self._driver.edges:
            return FakeResult(None)
        if "SET" in query:
            self._driver.edges[edge] = params["blocks"]
            return FakeResult({"r": "matched"})
        return FakeResult({"blocks_propagation": self._driver.edges[edge]})


class FakeDriver:
    def __init__(self, edges: dict):
        self.edges = edges  # {(dn,dv,de,en,ev,ee): bool|None}
        self.calls = []

    def session(self):
        return FakeSession(self)


def _key(p: PackageKey):
    return (p.name, p.version, p.ecosystem)


EDGE_KEY = _key(X) + _key(LODASH)


def test_set_blocks_propagation_writes_the_value():
    driver = FakeDriver({EDGE_KEY: None})
    set_blocks_propagation(driver, X, LODASH, True)
    assert driver.edges[EDGE_KEY] is True


def test_set_blocks_propagation_missing_edge_raises():
    driver = FakeDriver({})
    with pytest.raises(ValueError, match="no REQUIRES edge"):
        set_blocks_propagation(driver, X, LODASH, True)


def test_get_blocks_propagation_returns_current_value():
    driver = FakeDriver({EDGE_KEY: True})
    assert get_blocks_propagation(driver, X, LODASH) is True


def test_get_blocks_propagation_unset_defaults_false():
    driver = FakeDriver({EDGE_KEY: None})
    assert get_blocks_propagation(driver, X, LODASH) is False


def test_get_blocks_propagation_missing_edge_raises():
    driver = FakeDriver({})
    with pytest.raises(ValueError, match="no REQUIRES edge"):
        get_blocks_propagation(driver, X, LODASH)


def test_set_then_get_round_trips():
    driver = FakeDriver({EDGE_KEY: None})
    set_blocks_propagation(driver, X, LODASH, True)
    assert get_blocks_propagation(driver, X, LODASH) is True
    set_blocks_propagation(driver, X, LODASH, False)
    assert get_blocks_propagation(driver, X, LODASH) is False
