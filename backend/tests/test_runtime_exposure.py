import json

import pytest

from graph_builder.runtime_exposure import (
    INTERNET_FACING_WEIGHT,
    REQUEST_VOLUME_WEIGHT,
    RESOURCE_CRITICALITY_WEIGHT,
    get_runtime_exposure,
    runtime_exposure_for_package,
)


@pytest.fixture
def config_path(tmp_path):
    path = tmp_path / "runtime_exposure.json"
    path.write_text(json.dumps({
        "high-exposure-app": {"internet_facing": True, "request_volume_normalized": 1.0, "resource_criticality": 1.0},
        "low-exposure-app": {"internet_facing": False, "request_volume_normalized": 0.1, "resource_criticality": 0.1},
        "internal-tool": {"internet_facing": False, "request_volume_normalized": 0.0, "resource_criticality": 0.0},
    }))
    return path


def test_weights_sum_to_one():
    assert INTERNET_FACING_WEIGHT + REQUEST_VOLUME_WEIGHT + RESOURCE_CRITICALITY_WEIGHT == pytest.approx(1.0)


def test_fully_exposed_app_scores_one(config_path):
    assert get_runtime_exposure("high-exposure-app", config_path) == pytest.approx(1.0)


def test_fully_internal_app_scores_near_zero(config_path):
    assert get_runtime_exposure("internal-tool", config_path) == pytest.approx(0.0)


def test_internet_facing_dominates_over_low_volume_and_criticality(config_path):
    # internet_facing=False but request_volume/criticality=0.1 should still
    # score well below an internet_facing=True app with low other signals,
    # because internet_facing carries half the weight.
    low = get_runtime_exposure("low-exposure-app", config_path)
    assert low == pytest.approx(REQUEST_VOLUME_WEIGHT * 0.1 + RESOURCE_CRITICALITY_WEIGHT * 0.1)
    assert low < 0.5  # nowhere near a fully internet_facing app regardless of volume/criticality


def test_missing_app_id_raises_clear_error(config_path):
    with pytest.raises(ValueError, match="no runtime_exposure config entry"):
        get_runtime_exposure("nonexistent-app", config_path)


def test_runtime_exposure_for_package_uses_max_not_average(config_path):
    # One highly-exposed consumer should dominate, not get diluted by a
    # low-exposure one.
    result = runtime_exposure_for_package(["high-exposure-app", "internal-tool"], config_path)
    assert result == pytest.approx(get_runtime_exposure("high-exposure-app", config_path))


def test_runtime_exposure_for_package_empty_list_is_zero(config_path):
    assert runtime_exposure_for_package([], config_path) == 0.0


def test_runtime_exposure_for_package_single_app(config_path):
    result = runtime_exposure_for_package(["internal-tool"], config_path)
    assert result == pytest.approx(get_runtime_exposure("internal-tool", config_path))
