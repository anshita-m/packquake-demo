from graph_builder.models import PackageKey, VulnGraph, Vulnerability
from graph_builder.neo4j_vuln_writer import Neo4jVulnWriter

from .fakes import FakeDriver

DJANGO = PackageKey("django", "1.10.5", "pypi")


def _vuln_graph():
    vg = VulnGraph()
    vg.vulnerabilities = {
        "CVE-2019-19844": Vulnerability(
            vuln_id="CVE-2019-19844", id_type="cve", cvss_score=9.8, cvss_severity="CRITICAL",
            cvss_source="osv", epss_score=0.5, epss_percentile=0.9,
        ),
    }
    vg.affected_by = {(DJANGO, "CVE-2019-19844")}
    return vg


def test_write_vuln_graph_issues_constraint_first():
    driver = FakeDriver()
    Neo4jVulnWriter(driver).write_vuln_graph(_vuln_graph())
    assert "CREATE CONSTRAINT vuln_id_unique" in driver.calls[0][0]


def test_write_vuln_graph_merges_vulnerability_node_with_all_fields():
    driver = FakeDriver()
    Neo4jVulnWriter(driver).write_vuln_graph(_vuln_graph())

    vuln_calls = [(q, p) for q, p in driver.calls if "MERGE (v:Vulnerability" in q]
    assert len(vuln_calls) == 1
    row = vuln_calls[0][1]["rows"][0]
    assert row["vuln_id"] == "CVE-2019-19844"
    assert row["cvss_score"] == 9.8
    assert row["epss_score"] == 0.5


def test_write_vuln_graph_merges_affected_by_edge_matching_existing_package():
    driver = FakeDriver()
    Neo4jVulnWriter(driver).write_vuln_graph(_vuln_graph())

    edge_calls = [(q, p) for q, p in driver.calls if "AFFECTED_BY" in q]
    assert len(edge_calls) == 1
    row = edge_calls[0][1]["rows"][0]
    assert row["name"] == "django" and row["version"] == "1.10.5" and row["vuln_id"] == "CVE-2019-19844"
    assert "MATCH (p:Package" in edge_calls[0][0]  # assumes Package already exists, doesn't create it


def test_empty_vuln_graph_emits_only_constraint():
    driver = FakeDriver()
    Neo4jVulnWriter(driver).write_vuln_graph(VulnGraph())
    assert len(driver.calls) == 1


def test_writes_are_batched():
    driver = FakeDriver()
    vg = VulnGraph()
    vg.vulnerabilities = {
        f"CVE-2020-000{i}": Vulnerability(vuln_id=f"CVE-2020-000{i}", id_type="cve") for i in range(5)
    }
    Neo4jVulnWriter(driver, batch_size=2).write_vuln_graph(vg)

    vuln_calls = [(q, p) for q, p in driver.calls if "MERGE (v:Vulnerability" in q]
    assert len(vuln_calls) == 3  # ceil(5/2)
