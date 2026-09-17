import json
from pathlib import Path

import pytest

from graph_builder.cli import run

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_sbom(dir_path: Path, app_id: str, root_ref: str, components: list[dict], dependencies: list[dict]):
    doc = {
        "metadata": {"component": {"bom-ref": root_ref, "type": "application", "name": app_id, "version": "1.0.0"}},
        "components": components,
        "dependencies": dependencies,
    }
    (dir_path / f"{app_id}.json").write_text(json.dumps(doc))


def _pkg(ecosystem, name, version):
    purl = f"pkg:{ecosystem}/{name}@{version}"
    return {"bom-ref": purl, "type": "library", "name": name, "version": version, "purl": purl}


def test_cli_parses_and_passes_sanity_checks_on_minimal_fixtures(tmp_path, capsys):
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir()

    accepts = _pkg("npm", "accepts", "1.3.8")

    _write_sbom(sbom_dir, "hackathon-starter", "urn:app:hackathon-starter", [accepts],
                [{"ref": "urn:app:hackathon-starter", "dependsOn": [accepts["bom-ref"]]}])
    _write_sbom(sbom_dir, "node-realworld", "urn:app:node-realworld", [accepts],
                [{"ref": "urn:app:node-realworld", "dependsOn": [accepts["bom-ref"]]}])

    exit_code = run(["--sbom-dir", str(sbom_dir)])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Applications:     2" in out
    assert "Packages:         1" in out
    assert "[sanity] OK: accepts@1.3.8" in out


def test_cli_fails_when_sanity_check_fails(tmp_path, capsys):
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir()
    accepts = _pkg("npm", "accepts", "1.3.8")
    # Only one app depends on accepts -- fan-in too low for the sanity check.
    _write_sbom(sbom_dir, "hackathon-starter", "urn:app:hackathon-starter", [accepts],
                [{"ref": "urn:app:hackathon-starter", "dependsOn": [accepts["bom-ref"]]}])

    exit_code = run(["--sbom-dir", str(sbom_dir)])

    err = capsys.readouterr().err
    assert exit_code == 1
    assert "[sanity] FAILED" in err


def test_cli_errors_cleanly_on_empty_sbom_dir(tmp_path, capsys):
    sbom_dir = tmp_path / "empty"
    sbom_dir.mkdir()

    exit_code = run(["--sbom-dir", str(sbom_dir)])

    assert exit_code == 1
    assert "No SBOM files found" in capsys.readouterr().err


def test_cli_against_real_generated_fixtures(capsys):
    """Runs against the actual data/sbom/ fixtures checked into the repo --
    the literal command from the Phase 2 'Done when' criteria, minus
    --load-neo4j."""
    sbom_dir = REPO_ROOT / "data" / "sbom"
    if not sbom_dir.exists() or not any(sbom_dir.glob("*.json")):
        pytest.skip("data/sbom fixtures not present")

    exit_code = run(["--sbom-dir", str(sbom_dir)])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Applications:     4" in out
    assert "[sanity] OK: accepts@1.3.8" in out
