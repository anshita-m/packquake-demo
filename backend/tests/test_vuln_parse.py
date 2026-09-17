import json
from pathlib import Path

import pytest

from graph_builder.vuln_parse import extract_cvss_from_nvd, extract_cvss_from_osv, extract_epss, extract_identity

FIXTURES = Path(__file__).parent / "fixtures"


def _load(*parts):
    with open(FIXTURES.joinpath(*parts)) as f:
        return json.load(f)


def _django_vulns():
    return _load("osv", "django-1.10.5.json")["vulns"]


def _by_id(vulns, vuln_id):
    return next(v for v in vulns if v["id"] == vuln_id)


def test_extract_identity_from_real_ghsa_with_cve_alias():
    vuln = _by_id(_django_vulns(), "GHSA-vfq6-hq5r-27r6")
    cve_id, ghsa_id = extract_identity(vuln)
    assert cve_id == "CVE-2019-19844"
    assert ghsa_id == "GHSA-vfq6-hq5r-27r6"


def test_extract_identity_pysec_twin_resolves_same_cve():
    vuln = _by_id(_django_vulns(), "PYSEC-2019-16")
    cve_id, _ghsa_id = extract_identity(vuln)
    assert cve_id == "CVE-2019-19844"  # same CVE as the GHSA twin above


def test_extract_identity_synthetic_ghsa_only_has_no_cve():
    vuln = _load("osv", "synthetic-ghsa-only-no-cve.json")
    cve_id, ghsa_id = extract_identity(vuln)
    assert cve_id is None
    assert ghsa_id == "GHSA-0000-aaaa-bbbb"


def test_extract_cvss_from_osv_matches_known_nvd_score():
    vuln = _by_id(_django_vulns(), "GHSA-vfq6-hq5r-27r6")  # CVE-2019-19844
    cvss = extract_cvss_from_osv(vuln)
    assert cvss is not None
    assert cvss.score == 9.8
    assert cvss.severity == "CRITICAL"
    assert cvss.source == "osv"


def test_extract_cvss_from_osv_prefers_database_specific_severity_label():
    # GHSA-37hp-765x-j95x's database_specific.severity is "MODERATE" even
    # though our own score->label mapping would say "MEDIUM" for 6.1.
    vuln = _by_id(_django_vulns(), "GHSA-37hp-765x-j95x")
    cvss = extract_cvss_from_osv(vuln)
    assert cvss.score == 6.1
    assert cvss.severity == "MODERATE"


def test_extract_cvss_from_osv_returns_none_when_genuinely_missing():
    vuln = _load("osv", "synthetic-no-cvss.json")
    assert extract_cvss_from_osv(vuln) is None


def test_extract_cvss_from_nvd_real_fixture():
    nvd_response = _load("nvd", "CVE-2019-19844.json")
    cvss = extract_cvss_from_nvd(nvd_response)
    assert cvss.score == 9.8
    assert cvss.severity == "CRITICAL"
    assert cvss.source == "nvd"
    assert cvss.version == "3.1"


def test_extract_cvss_from_nvd_synthetic_fixture():
    nvd_response = _load("nvd", "CVE-2016-0001-synthetic.json")
    cvss = extract_cvss_from_nvd(nvd_response)
    assert cvss.score == 9.8
    assert cvss.severity == "CRITICAL"


def test_extract_cvss_from_nvd_empty_response_returns_none():
    assert extract_cvss_from_nvd({"vulnerabilities": []}) is None


def test_extract_epss_real_fixture():
    epss_response = _load("epss", "batch-3cve.json")
    row = next(r for r in epss_response["data"] if r["cve"] == "CVE-2019-19844")
    result = extract_epss(row)
    assert result is not None
    score, percentile = result
    assert 0.0 <= score <= 1.0
    assert 0.0 <= percentile <= 1.0


def test_extract_epss_none_row_returns_none():
    assert extract_epss(None) is None
