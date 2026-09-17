from graph_builder.models import PackageKey
from graph_builder.neo4j_risk_reader import (
    read_packages_for_mitigation,
    read_packages_for_risk_scoring,
    read_total_apps,
)


class FakeRecord(dict):
    def __getitem__(self, key):
        return dict.__getitem__(self, key)


class FakeResult:
    def __init__(self, rows):
        self._rows = [FakeRecord(r) for r in rows]

    def __iter__(self):
        return iter(self._rows)

    def single(self):
        return self._rows[0] if self._rows else None


class FakeSession:
    def __init__(self, routing):
        self._routing = routing

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return None

    def run(self, query, **_kwargs):
        for substring, rows in self._routing:
            if substring in query:
                return FakeResult(rows)
        raise AssertionError(f"no fake response configured for query: {query}")


class FakeDriver:
    def __init__(self, routing):
        self._routing = routing

    def session(self):
        return FakeSession(self._routing)


def test_read_total_apps():
    driver = FakeDriver([("MATCH (a:Application) RETURN count(a)", [{"n": 4}])])
    assert read_total_apps(driver) == 4


def test_read_packages_with_vulnerabilities():
    driver = FakeDriver([
        (
            "MATCH (p:Package)",
            [{
                "name": "django", "version": "1.10.5", "ecosystem": "pypi",
                "betweenness_centrality": 0.1, "blast_radius_apps": ["app1"],
                "vulnerabilities": [{"cvss_score": 9.8, "epss_score": 0.5}],
            }],
        ),
    ])

    results = read_packages_for_risk_scoring(driver)

    assert len(results) == 1
    r = results[0]
    assert r.package == PackageKey("django", "1.10.5", "pypi")
    assert r.betweenness_centrality == 0.1
    assert r.blast_radius_apps == ["app1"]
    assert r.vulnerabilities == [{"cvss_score": 9.8, "epss_score": 0.5}]


def test_read_packages_with_no_vulnerabilities_gets_empty_list():
    driver = FakeDriver([
        (
            "MATCH (p:Package)",
            [{
                "name": "lodash", "version": "4.17.21", "ecosystem": "npm",
                "betweenness_centrality": 0.0, "blast_radius_apps": ["app1", "app2"],
                "vulnerabilities": [],
            }],
        ),
    ])

    results = read_packages_for_risk_scoring(driver)
    assert results[0].vulnerabilities == []


def test_read_packages_null_properties_default_gracefully():
    driver = FakeDriver([
        (
            "MATCH (p:Package)",
            [{
                "name": "brand-new-pkg", "version": "1.0.0", "ecosystem": "npm",
                "betweenness_centrality": None,  # Phase 4 hasn't run on this one
                "blast_radius_apps": None,
                "vulnerabilities": [],
            }],
        ),
    ])

    results = read_packages_for_risk_scoring(driver)
    r = results[0]
    assert r.betweenness_centrality is None
    assert r.blast_radius_apps == []


def test_read_packages_for_mitigation_reads_stored_raw_factors_directly():
    driver = FakeDriver([
        (
            "MATCH (p:Package)",
            [{
                "name": "werkzeug", "version": "0.15.2", "ecosystem": "pypi",
                "cvss_normalized": 0.98, "exploitability": 0.7, "centrality_normalized": 0.1,
                "blast_radius_ratio": 0.5, "runtime_exposure": 0.8,
                "blast_radius_apps": ["flack"],
                "vulnerabilities": [{"cvss_score": 9.8, "epss_score": 0.7}],
            }],
        ),
    ])

    results = read_packages_for_mitigation(driver)

    assert len(results) == 1
    r = results[0]
    assert r.package == PackageKey("werkzeug", "0.15.2", "pypi")
    assert r.raw_factors == {
        "cvss_normalized": 0.98, "exploitability": 0.7, "centrality_normalized": 0.1,
        "blast_radius_ratio": 0.5, "runtime_exposure": 0.8,
    }
    assert r.blast_radius_apps == ["flack"]
    assert r.vulnerabilities == [{"cvss_score": 9.8, "epss_score": 0.7}]


def test_read_packages_for_mitigation_raw_factors_none_when_phase6_hasnt_run():
    driver = FakeDriver([
        (
            "MATCH (p:Package)",
            [{
                "name": "brand-new-pkg", "version": "1.0.0", "ecosystem": "npm",
                "cvss_normalized": None, "exploitability": None, "centrality_normalized": None,
                "blast_radius_ratio": None, "runtime_exposure": None,
                "blast_radius_apps": None,
                "vulnerabilities": [{"cvss_score": 5.0, "epss_score": 0.1}],
            }],
        ),
    ])

    results = read_packages_for_mitigation(driver)

    assert results[0].raw_factors is None
    assert results[0].vulnerabilities == [{"cvss_score": 5.0, "epss_score": 0.1}]
