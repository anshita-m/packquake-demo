"""Runtime exposure: a Netdata stand-in.

Standing up real Netdata against all 4 apps needs them actually running as
monitored services -- real infra work the plan flags as the first thing to
cut under time pressure. This reads a small config file instead
(data/runtime_exposure.json) with the same three signals Netdata would
plausibly give per app: internet_facing, request_volume_normalized,
resource_criticality.

To swap in a real Netdata client later: replace `_load_runtime_signals`'s
body (or point DEFAULT_CONFIG_PATH's caller at a Netdata-backed function
with the same `app_id -> RuntimeSignals` shape). `get_runtime_exposure`'s
signature -- and the combining math in `_combine_signals` -- don't need to
change either way.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "data" / "runtime_exposure.json"

# internet_facing matters most for exposure; request volume and resource
# criticality matter, but neither alone (or even together) should outweigh
# whether the app is reachable from the internet at all.
INTERNET_FACING_WEIGHT = 0.5
REQUEST_VOLUME_WEIGHT = 0.25
RESOURCE_CRITICALITY_WEIGHT = 0.25


@dataclass(frozen=True)
class RuntimeSignals:
    internet_facing: bool
    request_volume_normalized: float
    resource_criticality: float


def _load_runtime_signals(app_id: str, config_path: Path = DEFAULT_CONFIG_PATH) -> RuntimeSignals:
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    if app_id not in config:
        raise ValueError(f"no runtime_exposure config entry for app_id {app_id!r} in {config_path}")

    entry = config[app_id]
    return RuntimeSignals(
        internet_facing=bool(entry["internet_facing"]),
        request_volume_normalized=float(entry["request_volume_normalized"]),
        resource_criticality=float(entry["resource_criticality"]),
    )


def _combine_signals(signals: RuntimeSignals) -> float:
    return (
        INTERNET_FACING_WEIGHT * float(signals.internet_facing)
        + REQUEST_VOLUME_WEIGHT * signals.request_volume_normalized
        + RESOURCE_CRITICALITY_WEIGHT * signals.resource_criticality
    )


def get_runtime_exposure(app_id: str, config_path: Path = DEFAULT_CONFIG_PATH) -> float:
    """Runtime exposure for one app, in [0, 1]. Netdata stand-in -- see
    module docstring for how this gets swapped for the real thing later."""
    return _combine_signals(_load_runtime_signals(app_id, config_path))


def runtime_exposure_for_package(blast_radius_apps: list[str], config_path: Path = DEFAULT_CONFIG_PATH) -> float:
    """max(get_runtime_exposure(app) for app in blast_radius_apps), 0.0 if
    empty. max, not average: a package used by one highly-exposed app
    should score as exposed even if its other consumers are low-exposure
    internal tools -- averaging would dilute that."""
    return max((get_runtime_exposure(app_id, config_path) for app_id in blast_radius_apps), default=0.0)
