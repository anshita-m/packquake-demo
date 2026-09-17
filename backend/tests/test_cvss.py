import pytest

from graph_builder.cvss import InvalidCvssVector, cvss_v3_base_score, severity_from_score


def test_known_critical_vector_matches_real_nvd_score():
    # CVE-2019-19844's actual NVD-published vector and baseScore (9.8).
    score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8


def test_known_medium_vector_matches_real_nvd_score():
    # CVE-2017-7233's actual NVD-published vector (CVSS v3.0) and baseScore (6.1).
    score = cvss_v3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert score == 6.1


def test_scope_changed_uses_different_pr_table_and_multiplier():
    # A scope-changed vector should not silently fall back to unchanged math.
    score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert 9.0 <= score <= 10.0


def test_zero_impact_scores_zero():
    score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0


@pytest.mark.parametrize(
    "score,expected",
    [(0.0, "NONE"), (0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"), (6.9, "MEDIUM"), (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"), (10.0, "CRITICAL")],
)
def test_severity_thresholds(score, expected):
    assert severity_from_score(score) == expected


def test_non_cvss3_vector_raises():
    with pytest.raises(InvalidCvssVector):
        cvss_v3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


def test_garbage_vector_raises():
    with pytest.raises(InvalidCvssVector):
        cvss_v3_base_score("not a vector")


def test_missing_metric_raises():
    with pytest.raises(InvalidCvssVector):
        cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # missing A
