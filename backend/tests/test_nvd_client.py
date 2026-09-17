import pytest

from graph_builder.cache import MISSING, DiskCache
from graph_builder.nvd_client import AUTHENTICATED_MIN_INTERVAL, UNAUTHENTICATED_MIN_INTERVAL, NvdClient

from .http_fakes import FakeResponse, FakeSession


@pytest.fixture(autouse=True)
def _no_real_nvd_api_key(monkeypatch):
    # Don't let a developer's real NVD_API_KEY (if set in their shell) change
    # which throttle interval these tests exercise.
    monkeypatch.delenv("NVD_API_KEY", raising=False)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def monotonic(self) -> float:
        return self.now


def _client(tmp_path, responses, api_key=None):
    cache = DiskCache(tmp_path)
    session = FakeSession(responses)
    clock = FakeClock()
    client = NvdClient(cache, session=session, api_key=api_key, sleep_fn=clock.sleep, clock_fn=clock.monotonic)
    return client, session, cache, clock


def test_get_cve_success_and_caches(tmp_path):
    response = FakeResponse(200, {"vulnerabilities": [{"cve": {"id": "CVE-2019-19844"}}]})
    client, session, cache, _clock = _client(tmp_path, [response])

    data = client.get_cve("CVE-2019-19844")
    assert data["vulnerabilities"][0]["cve"]["id"] == "CVE-2019-19844"
    assert len(session.calls) == 1
    assert cache.stats.misses == 1


def test_second_lookup_is_cached_zero_network_calls(tmp_path):
    response = FakeResponse(200, {"vulnerabilities": []})
    client, session, cache, clock = _client(tmp_path, [response])
    client.get_cve("CVE-2019-19844")

    client2, session2, _, _ = _client(tmp_path, [])
    client2.cache = cache
    client2.get_cve("CVE-2019-19844")

    assert session2.calls == []
    assert cache.stats.hits == 1


def test_404_returns_none_and_is_not_cached(tmp_path):
    client, _session, cache, _clock = _client(tmp_path, [FakeResponse(404)])
    result = client.get_cve("CVE-9999-0000")
    assert result is None
    # not written to cache -- NVD might publish this CVE later, so we
    # shouldn't permanently remember "not found" the way EPSS does.
    assert cache.get("CVE-9999-0000") is MISSING


def test_throttles_between_requests_unauthenticated(tmp_path):
    responses = [FakeResponse(200, {"vulnerabilities": []}) for _ in range(2)]
    client, _session, _cache, clock = _client(tmp_path, responses)

    client.get_cve("CVE-1")
    client.get_cve("CVE-2")

    assert clock.sleeps == [UNAUTHENTICATED_MIN_INTERVAL]


def test_authenticated_uses_shorter_interval_and_sends_api_key_header(tmp_path):
    responses = [FakeResponse(200, {"vulnerabilities": []}) for _ in range(2)]
    client, session, _cache, clock = _client(tmp_path, responses, api_key="secret-key")

    client.get_cve("CVE-1")
    client.get_cve("CVE-2")

    assert clock.sleeps == [AUTHENTICATED_MIN_INTERVAL]
    _method, _url, kwargs = session.calls[0]
    assert kwargs["headers"]["apiKey"] == "secret-key"


def test_reads_api_key_from_environment_when_not_passed(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "env-key")
    cache = DiskCache(tmp_path)
    client = NvdClient(cache, session=FakeSession([]))
    assert client.api_key == "env-key"
    assert client.min_interval == AUTHENTICATED_MIN_INTERVAL


def test_429_backs_off_exponentially_then_succeeds(tmp_path):
    responses = [FakeResponse(429), FakeResponse(429), FakeResponse(200, {"vulnerabilities": []})]
    client, session, _cache, clock = _client(tmp_path, responses)

    client.get_cve("CVE-1")

    assert len(session.calls) == 3
    # exponential backoff sleeps (1.0 then 2.0) happened, interleaved with
    # throttle sleeps between attempts
    assert 1.0 in clock.sleeps
    assert 2.0 in clock.sleeps


def test_429_exhausting_retries_raises(tmp_path):
    responses = [FakeResponse(429) for _ in range(5)]
    client, _session, _cache, _clock = _client(tmp_path, responses)

    try:
        client.get_cve("CVE-1")
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "rate limited" in str(exc)
