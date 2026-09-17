from graph_builder.cache import MISSING, DiskCache


def test_miss_then_hit(tmp_path):
    cache = DiskCache(tmp_path)
    assert cache.get("k") is MISSING
    assert cache.stats.misses == 1 and cache.stats.hits == 0

    cache.set("k", {"a": 1})
    assert cache.get("k") == {"a": 1}
    assert cache.stats.hits == 1


def test_caching_a_none_value_is_still_a_hit_next_time(tmp_path):
    """EPSS rows for CVEs with no score are legitimately None -- must not
    be indistinguishable from 'not cached'."""
    cache = DiskCache(tmp_path)
    cache.set("no-data-cve", None)

    result = cache.get("no-data-cve")
    assert result is None  # a real, cached None -- not MISSING
    assert cache.stats.hits == 1
    assert cache.stats.misses == 0


def test_caching_empty_list_is_still_a_hit(tmp_path):
    cache = DiskCache(tmp_path)
    cache.set("no-vulns-pkg", [])
    assert cache.get("no-vulns-pkg") == []
    assert cache.stats.hits == 1


def test_keys_with_unsafe_filename_characters_round_trip(tmp_path):
    cache = DiskCache(tmp_path)
    key = "pkg__npm__@angular/core__12.0.0"
    cache.set(key, {"ok": True})
    assert cache.get(key) == {"ok": True}


def test_separate_caches_are_independent(tmp_path):
    cache_a = DiskCache(tmp_path / "a")
    cache_b = DiskCache(tmp_path / "b")
    cache_a.set("k", "from-a")
    assert cache_b.get("k") is MISSING
