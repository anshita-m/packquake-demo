import pytest

from graph_builder.cache import DiskCache
from graph_builder.mitigation_effort import (
    EFFORT_HIGH,
    EFFORT_LOW,
    EFFORT_MEDIUM,
    classify_version_jump,
    extract_fixed_versions,
    find_fixed_version_from_cache,
    parse_version_tuple,
    pick_target_fixed_version,
)
from graph_builder.models import PackageKey
from graph_builder.osv_client import package_cache_key


# --- parse_version_tuple ---

def test_parse_version_tuple_basic():
    assert parse_version_tuple("1.2.3") == (1, 2, 3)


def test_parse_version_tuple_unparseable_returns_none():
    assert parse_version_tuple("1.2.3rc1") is None
    assert parse_version_tuple("not-a-version") is None


# --- classify_version_jump: the required concrete pairs ---

def test_major_version_jump_is_high_effort():
    assert classify_version_jump("1.2.3", "2.0.0") == EFFORT_HIGH


def test_minor_version_jump_is_medium_effort():
    assert classify_version_jump("1.2.3", "1.3.0") == EFFORT_MEDIUM


def test_patch_version_jump_is_low_effort():
    assert classify_version_jump("1.2.3", "1.2.4") == EFFORT_LOW


def test_unparseable_pair_falls_back_to_low_effort_without_crashing():
    assert classify_version_jump("1.2.3", "1.2.3rc1") == EFFORT_LOW
    assert classify_version_jump("not-a-version", "also-not") == EFFORT_LOW


def test_identical_versions_is_low_effort():
    assert classify_version_jump("1.2.3", "1.2.3") == EFFORT_LOW


def test_shorter_version_strings_treated_as_zero_padded():
    # "1.2" vs "1.2.0" -- same major/minor, missing patch treated as 0.
    assert classify_version_jump("1.2", "1.2.0") == EFFORT_LOW
    assert classify_version_jump("1", "2") == EFFORT_HIGH


# --- extract_fixed_versions ---

def test_extract_fixed_versions_from_real_shaped_osv_detail():
    osv_detail = {
        "affected": [
            {
                "package": {"name": "werkzeug", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.15.3"}]}],
            }
        ]
    }
    assert extract_fixed_versions(osv_detail, "werkzeug") == ["0.15.3"]


def test_extract_fixed_versions_ignores_entries_for_other_packages():
    osv_detail = {
        "affected": [
            {"package": {"name": "other-pkg"}, "ranges": [{"events": [{"fixed": "9.9.9"}]}]},
        ]
    }
    assert extract_fixed_versions(osv_detail, "werkzeug") == []


def test_extract_fixed_versions_no_affected_key_returns_empty():
    assert extract_fixed_versions({}, "werkzeug") == []


def test_extract_fixed_versions_multiple_ranges_and_events():
    osv_detail = {
        "affected": [
            {
                "package": {"name": "werkzeug"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "0.15.3"}]},
                    {"events": [{"introduced": "0.14"}, {"fixed": "0.14.1"}]},
                ],
            }
        ]
    }
    assert set(extract_fixed_versions(osv_detail, "werkzeug")) == {"0.15.3", "0.14.1"}


# --- pick_target_fixed_version ---

def test_pick_target_fixed_version_picks_highest_parseable():
    assert pick_target_fixed_version(["0.15.3", "0.14.1", "1.0.0"]) == "1.0.0"


def test_pick_target_fixed_version_empty_is_none():
    assert pick_target_fixed_version([]) is None


def test_pick_target_fixed_version_none_parseable_returns_first():
    assert pick_target_fixed_version(["1.0.0rc1", "abc"]) == "1.0.0rc1"


# --- find_fixed_version_from_cache (disk I/O, using DiskCache) ---

WERKZEUG = PackageKey("werkzeug", "0.15.2", "pypi")


def test_find_fixed_version_from_cache_happy_path(tmp_path):
    pkg_cache = DiskCache(tmp_path / "packages")
    vuln_cache = DiskCache(tmp_path / "vulns")

    pkg_cache.set(package_cache_key(WERKZEUG), [{"id": "GHSA-xxxx", "modified": "2024-01-01"}])
    vuln_cache.set("GHSA-xxxx", {
        "id": "GHSA-xxxx",
        "affected": [{"package": {"name": "werkzeug"}, "ranges": [{"events": [{"fixed": "0.15.3"}]}]}],
    })

    result = find_fixed_version_from_cache(WERKZEUG, pkg_cache, vuln_cache)
    assert result == "0.15.3"


def test_find_fixed_version_from_cache_not_enriched_returns_none(tmp_path):
    pkg_cache = DiskCache(tmp_path / "packages")
    vuln_cache = DiskCache(tmp_path / "vulns")
    # nothing cached at all for this package
    assert find_fixed_version_from_cache(WERKZEUG, pkg_cache, vuln_cache) is None


def test_find_fixed_version_from_cache_no_vulns_returns_none(tmp_path):
    pkg_cache = DiskCache(tmp_path / "packages")
    vuln_cache = DiskCache(tmp_path / "vulns")
    pkg_cache.set(package_cache_key(WERKZEUG), [])  # enriched, clean
    assert find_fixed_version_from_cache(WERKZEUG, pkg_cache, vuln_cache) is None


def test_find_fixed_version_from_cache_vuln_detail_missing_is_skipped_not_fatal(tmp_path):
    pkg_cache = DiskCache(tmp_path / "packages")
    vuln_cache = DiskCache(tmp_path / "vulns")
    pkg_cache.set(package_cache_key(WERKZEUG), [{"id": "GHSA-ghost"}])
    # vuln detail was never cached (e.g. a 404 during enrichment) -- no crash
    assert find_fixed_version_from_cache(WERKZEUG, pkg_cache, vuln_cache) is None
