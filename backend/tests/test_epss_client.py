from graph_builder.cache import DiskCache
from graph_builder.epss_client import EpssClient

from .http_fakes import FakeResponse, FakeSession


def test_get_scores_batches_into_one_comma_separated_request(tmp_path):
    response = FakeResponse(200, {"data": [
        {"cve": "CVE-1", "epss": "0.5", "percentile": "0.9"},
        {"cve": "CVE-2", "epss": "0.1", "percentile": "0.2"},
    ]})
    cache = DiskCache(tmp_path)
    session = FakeSession([response])
    client = EpssClient(cache, session=session)

    result = client.get_scores(["CVE-1", "CVE-2"])

    assert len(session.calls) == 1
    _method, _url, kwargs = session.calls[0]
    assert kwargs["params"]["cve"] == "CVE-1,CVE-2"
    assert result["CVE-1"]["epss"] == "0.5"
    assert result["CVE-2"]["percentile"] == "0.2"


def test_cve_missing_from_epss_dataset_cached_as_none_not_refetched(tmp_path):
    response = FakeResponse(200, {"data": []})  # EPSS doesn't know this CVE
    cache = DiskCache(tmp_path)
    session = FakeSession([response])
    client = EpssClient(cache, session=session)

    result = client.get_scores(["CVE-unknown"])
    assert result["CVE-unknown"] is None

    client2 = EpssClient(cache, session=FakeSession([]))
    result2 = client2.get_scores(["CVE-unknown"])
    assert result2["CVE-unknown"] is None
    assert client2.session.calls == []


def test_second_run_all_cached_zero_network_calls(tmp_path):
    response = FakeResponse(200, {"data": [{"cve": "CVE-1", "epss": "0.5", "percentile": "0.9"}]})
    cache = DiskCache(tmp_path)
    client = EpssClient(cache, session=FakeSession([response]))
    client.get_scores(["CVE-1"])

    client2 = EpssClient(cache, session=FakeSession([]))
    result = client2.get_scores(["CVE-1"])
    assert result["CVE-1"]["epss"] == "0.5"
    assert client2.session.calls == []


def test_batching_respects_batch_size(tmp_path):
    responses = [
        FakeResponse(200, {"data": [{"cve": f"CVE-{i}", "epss": "0.1", "percentile": "0.1"} for i in range(2)]}),
        FakeResponse(200, {"data": [{"cve": "CVE-2", "epss": "0.1", "percentile": "0.1"}]}),
    ]
    cache = DiskCache(tmp_path)
    session = FakeSession(responses)
    client = EpssClient(cache, session=session, batch_size=2)

    client.get_scores([f"CVE-{i}" for i in range(3)])

    assert len(session.calls) == 2
    assert session.calls[0][2]["params"]["cve"].count(",") == 1  # 2 CVEs
    assert session.calls[1][2]["params"]["cve"].count(",") == 0  # 1 CVE
