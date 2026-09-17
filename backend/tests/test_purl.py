import pytest

from graph_builder.purl import parse_purl


def test_pypi_purl():
    assert parse_purl("pkg:pypi/requests@2.31.0") == ("pypi", "requests", "2.31.0")


def test_npm_purl():
    assert parse_purl("pkg:npm/lodash@4.17.21") == ("npm", "lodash", "4.17.21")


def test_npm_scoped_purl():
    assert parse_purl("pkg:npm/%40angular/core@12.0.0") == ("npm", "@angular/core", "12.0.0")


def test_maven_namespaced_purl():
    assert parse_purl("pkg:maven/org.springframework/spring-core@5.3.0") == (
        "maven", "org.springframework/spring-core", "5.3.0",
    )


def test_purl_with_qualifiers_and_subpath_stripped():
    assert parse_purl("pkg:npm/lodash@4.17.21?os=linux#sub/path") == ("npm", "lodash", "4.17.21")


def test_purl_without_version():
    assert parse_purl("pkg:npm/lodash") == ("npm", "lodash", "")


def test_purl_ecosystem_lowercased():
    assert parse_purl("pkg:PyPI/requests@2.31.0")[0] == "pypi"


def test_not_a_purl_raises():
    with pytest.raises(ValueError):
        parse_purl("lodash@4.17.21")


def test_empty_purl_raises():
    with pytest.raises(ValueError):
        parse_purl("")


def test_malformed_purl_raises():
    with pytest.raises(ValueError):
        parse_purl("pkg:")
