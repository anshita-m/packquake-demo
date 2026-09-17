import json
from pathlib import Path

from graph_builder.enrichment import enrich_graph
from graph_builder.models import Graph, PackageKey

FIXTURES = Path(__file__).parent / "fixtures"


def _load(*parts):
    with open(FIXTURES.joinpath(*parts)) as f:
        return json.load(f)


class FakeOsvClient:
    def __init__(self, stubs_by_package, details_by_id):
        self._stubs_by_package = stubs_by_package
        self._details_by_id = details_by_id
        self.query_vuln_stubs_calls = 0
        self.get_vuln_details_calls = 0

    def query_vuln_stubs(self, packages):
        self.query_vuln_stubs_calls += 1
        return {pkg: self._stubs_by_package.get(pkg, []) for pkg in packages}

    def get_vuln_details(self, vuln_ids):
        self.get_vuln_details_calls += 1
        return {vid: self._details_by_id[vid] for vid in vuln_ids if vid in self._details_by_id}


class FakeNvdClient:
    def __init__(self, responses=None):
        self._responses = responses or {}
        self.calls = []

    def get_cve(self, cve_id):
        self.calls.append(cve_id)
        return self._responses.get(cve_id)


class FakeEpssClient:
    def __init__(self, rows=None):
        self._rows = rows or {}
        self.calls = []

    def get_scores(self, cve_ids):
        self.calls.append(list(cve_ids))
        return {cid: self._rows.get(cid) for cid in cve_ids}


DJANGO = PackageKey("django", "1.10.5", "pypi")
PYJWT = PackageKey("pyjwt", "1.4.2", "pypi")


def _django_details():
    vulns = _load("osv", "django-1.10.5.json")["vulns"]
    return {v["id"]: v for v in vulns}


def test_enrich_graph_finds_real_django_cves_with_cvss():
    graph = Graph(packages={DJANGO})
    details = _django_details()
    stubs = {DJANGO: [{"id": vid} for vid in details]}

    osv = FakeOsvClient(stubs, details)
    vuln_graph = enrich_graph(graph, osv, FakeNvdClient(), FakeEpssClient())

    assert "CVE-2019-19844" in vuln_graph.vulnerabilities
    v = vuln_graph.vulnerabilities["CVE-2019-19844"]
    assert v.cvss_score == 9.8
    assert v.cvss_severity == "CRITICAL"
    assert v.cvss_source == "osv"
    assert (DJANGO, "CVE-2019-19844") in vuln_graph.affected_by


def test_enrich_graph_dedups_pysec_twin_onto_same_vulnerability():
    graph = Graph(packages={DJANGO})
    details = _django_details()
    stubs = {DJANGO: [{"id": vid} for vid in details]}

    osv = FakeOsvClient(stubs, details)
    vuln_graph = enrich_graph(graph, osv, FakeNvdClient(), FakeEpssClient())

    # GHSA-vfq6-hq5r-27r6 and PYSEC-2019-16 both alias CVE-2019-19844 --
    # must collapse to ONE Vulnerability node, not two.
    matching_keys = [k for k in vuln_graph.vulnerabilities if k == "CVE-2019-19844"]
    assert len(matching_keys) == 1
    # and the package should only have ONE affected_by edge to it, even
    # though two OSV ids both pointed at it.
    edges_to_it = [(p, v) for (p, v) in vuln_graph.affected_by if v == "CVE-2019-19844"]
    assert len(edges_to_it) == 1


def test_enrich_graph_falls_back_to_nvd_when_osv_has_no_cvss():
    key = PackageKey("mystery", "0.0.1", "pypi")
    graph = Graph(packages={key})
    no_cvss_vuln = _load("osv", "synthetic-no-cvss.json")
    stubs = {key: [{"id": no_cvss_vuln["id"]}]}
    details = {no_cvss_vuln["id"]: no_cvss_vuln}

    nvd_response = _load("nvd", "CVE-2016-0001-synthetic.json")
    nvd = FakeNvdClient({"CVE-2016-0001": nvd_response})

    osv = FakeOsvClient(stubs, details)
    vuln_graph = enrich_graph(graph, osv, nvd, FakeEpssClient())

    v = vuln_graph.vulnerabilities["CVE-2016-0001"]
    assert v.cvss_score == 9.8
    assert v.cvss_source == "nvd"
    assert nvd.calls == ["CVE-2016-0001"]


def test_enrich_graph_never_calls_nvd_for_ghsa_only_vulns():
    key = PackageKey("mystery", "0.0.1", "npm")
    graph = Graph(packages={key})
    ghsa_only = _load("osv", "synthetic-ghsa-only-no-cve.json")
    stubs = {key: [{"id": ghsa_only["id"]}]}
    details = {ghsa_only["id"]: ghsa_only}

    nvd = FakeNvdClient()
    osv = FakeOsvClient(stubs, details)
    enrich_graph(graph, osv, nvd, FakeEpssClient())

    assert nvd.calls == []  # this one already had CVSS from OSV; and it's GHSA-only anyway


def test_enrich_graph_skips_epss_for_ghsa_only_vulns():
    key = PackageKey("mystery", "0.0.1", "npm")
    graph = Graph(packages={key})
    ghsa_only = _load("osv", "synthetic-ghsa-only-no-cve.json")
    stubs = {key: [{"id": ghsa_only["id"]}]}
    details = {ghsa_only["id"]: ghsa_only}

    epss = FakeEpssClient()
    vuln_graph = enrich_graph(graph, FakeOsvClient(stubs, details), FakeNvdClient(), epss)

    assert epss.calls == []  # no CVE-keyed vulns to look up EPSS for
    ghsa_vuln = next(iter(vuln_graph.vulnerabilities.values()))
    assert ghsa_vuln.epss_score is None


def test_enrich_graph_attaches_epss_scores_for_cve_vulns():
    graph = Graph(packages={DJANGO})
    details = _django_details()
    stubs = {DJANGO: [{"id": "GHSA-vfq6-hq5r-27r6"}]}
    epss_row = {"cve": "CVE-2019-19844", "epss": "0.5", "percentile": "0.9"}

    osv = FakeOsvClient(stubs, details)
    epss = FakeEpssClient({"CVE-2019-19844": epss_row})
    vuln_graph = enrich_graph(graph, osv, FakeNvdClient(), epss)

    v = vuln_graph.vulnerabilities["CVE-2019-19844"]
    assert v.epss_score == 0.5
    assert v.epss_percentile == 0.9


def test_enrich_graph_handles_package_with_no_vulns():
    key = PackageKey("clean-pkg", "1.0.0", "npm")
    graph = Graph(packages={key})

    vuln_graph = enrich_graph(graph, FakeOsvClient({}, {}), FakeNvdClient(), FakeEpssClient())

    assert vuln_graph.vulnerabilities == {}
    assert vuln_graph.affected_by == set()
