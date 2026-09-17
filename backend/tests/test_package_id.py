import pytest

from graph_builder.models import PackageKey
from graph_builder.package_id import InvalidPackageId, from_package_id, to_package_id


def test_round_trip_basic():
    pkg = PackageKey("lodash", "4.17.21", "npm")
    assert from_package_id(to_package_id(pkg)) == pkg


def test_encoding_format():
    pkg = PackageKey("lodash", "4.17.21", "npm")
    assert to_package_id(pkg) == "npm:lodash@4.17.21"


def test_round_trip_scoped_npm_name_with_slash_and_at():
    pkg = PackageKey("@babel/helper-string-parser", "7.29.7", "npm")
    encoded = to_package_id(pkg)
    assert encoded == "npm:@babel/helper-string-parser@7.29.7"
    assert from_package_id(encoded) == pkg


def test_round_trip_pypi_package():
    pkg = PackageKey("werkzeug", "0.15.2", "pypi")
    assert from_package_id(to_package_id(pkg)) == pkg


def test_malformed_id_no_colon_raises():
    with pytest.raises(InvalidPackageId):
        from_package_id("lodash@4.17.21")


def test_malformed_id_no_at_raises():
    with pytest.raises(InvalidPackageId):
        from_package_id("npm:lodash")


def test_malformed_id_empty_string_raises():
    with pytest.raises(InvalidPackageId):
        from_package_id("")
