from graph_builder.cache import DiskCache
from graph_builder.models import PackageKey
from graph_builder.osv_client import OsvClient

from .http_fakes import FakeResponse, FakeSession

LODASH = PackageKey("lodash", "4.17.21", "npm")
REQUESTS_PKG = PackageKey("requests", "2.31.0", "pypi")
UNMAPPED = PackageKey("weird", "1.0.0", "some-unknown-ecosystem")


def _client(tmp_path, responses):
    pkg_cache = DiskCache(tmp_path / "pkg")
    vuln_cache = DiskCache(tmp_path / "vuln")
    session = FakeSession(responses)
    return OsvClient(pkg_cache, vuln_cache, session=session), session, pkg_cache, vuln_cache


def test_query_vuln_stubs_uses_querybatch_and_ecosystem_mapping(tmp_path):
    response = FakeResponse(200, {"results": [{"vulns": [{"id": "GHSA-aaaa"}]}, {}]})
    client, session, _, _ = _client(tmp_path, [response])

    result = client.query_vuln_stubs([LODASH, REQUESTS_PKG])

    assert result[LODASH] == [{"id": "GHSA-aaaa"}]
    assert result[REQUESTS_PKG] == []
    method, url, kwargs = session.calls[0]
    assert method == "POST" and "querybatch" in url
    queries = kwargs["json"]["queries"]
    assert queries[0]["package"]["ecosystem"] == "npm"
    assert queries[1]["package"]["ecosystem"] == "PyPI"


def test_query_vuln_stubs_caches_per_package(tmp_path):
    response = FakeResponse(200, {"results": [{"vulns": [{"id": "GHSA-aaaa"}]}]})
    client, session, pkg_cache, _ = _client(tmp_path, [response])

    client.query_vuln_stubs([LODASH])
    assert pkg_cache.stats.misses == 1

    # second call, fresh client sharing the same cache dir: zero network calls
    client2, session2, _, _ = _client(tmp_path, [])
    client2.package_cache = pkg_cache
    result = client2.query_vuln_stubs([LODASH])
    assert result[LODASH] == [{"id": "GHSA-aaaa"}]
    assert session2.calls == []
    assert pkg_cache.stats.hits == 1


def test_unmapped_ecosystem_is_skipped_not_fatal(tmp_path, caplog):
    client, session, _, _ = _client(tmp_path, [])
    with caplog.at_level("WARNING"):
        result = client.query_vuln_stubs([UNMAPPED])
    assert result[UNMAPPED] == []
    assert session.calls == []  # never even attempted a request
    assert any("No OSV ecosystem mapping" in m for m in caplog.messages)


def test_get_vuln_details_fetches_each_id_and_caches(tmp_path):
    responses = [
        FakeResponse(200, {"id": "GHSA-aaaa", "aliases": ["CVE-2020-0001"]}),
        FakeResponse(200, {"id": "GHSA-bbbb", "aliases": ["CVE-2020-0002"]}),
    ]
    client, session, _, vuln_cache = _client(tmp_path, responses)

    details = client.get_vuln_details({"GHSA-aaaa", "GHSA-bbbb"})

    assert details["GHSA-aaaa"]["aliases"] == ["CVE-2020-0001"]
    assert details["GHSA-bbbb"]["aliases"] == ["CVE-2020-0002"]
    assert len(session.calls) == 2
    assert vuln_cache.stats.misses == 2


def test_get_vuln_details_second_run_hits_cache_zero_network_calls(tmp_path):
    responses = [FakeResponse(200, {"id": "GHSA-aaaa", "aliases": []})]
    client, _session, _, vuln_cache = _client(tmp_path, responses)
    client.get_vuln_details({"GHSA-aaaa"})

    client2, session2, _, _ = _client(tmp_path, [])
    client2.vuln_cache = vuln_cache
    details = client2.get_vuln_details({"GHSA-aaaa"})

    assert details["GHSA-aaaa"]["id"] == "GHSA-aaaa"
    assert session2.calls == []


def test_get_vuln_details_404_skipped_not_fatal(tmp_path, caplog):
    client, session, _, _ = _client(tmp_path, [FakeResponse(404)])
    with caplog.at_level("WARNING"):
        details = client.get_vuln_details({"GHSA-ghost"})
    assert details == {}
    assert any("404" in m for m in caplog.messages)


def test_batching_splits_requests_by_batch_size(tmp_path):
    responses = [
        FakeResponse(200, {"results": [{"vulns": []}, {"vulns": []}]}),
        FakeResponse(200, {"results": [{"vulns": []}]}),
    ]
    pkg_cache = DiskCache(tmp_path / "pkg")
    vuln_cache = DiskCache(tmp_path / "vuln")
    session = FakeSession(responses)
    client = OsvClient(pkg_cache, vuln_cache, session=session, batch_size=2)

    pkgs = [PackageKey(f"pkg{i}", "1.0.0", "npm") for i in range(3)]
    client.query_vuln_stubs(pkgs)

    assert len(session.calls) == 2
    assert len(session.calls[0][2]["json"]["queries"]) == 2
    assert len(session.calls[1][2]["json"]["queries"]) == 1
