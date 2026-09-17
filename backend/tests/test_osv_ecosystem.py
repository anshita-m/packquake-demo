from graph_builder.osv_ecosystem import to_osv_ecosystem


def test_npm_stays_npm():
    assert to_osv_ecosystem("npm") == "npm"


def test_pypi_capitalized():
    assert to_osv_ecosystem("pypi") == "PyPI"


def test_maven_capitalized():
    assert to_osv_ecosystem("maven") == "Maven"


def test_cargo_maps_to_crates_io():
    assert to_osv_ecosystem("cargo") == "crates.io"


def test_golang_maps_to_go():
    assert to_osv_ecosystem("golang") == "Go"


def test_gem_maps_to_rubygems():
    assert to_osv_ecosystem("gem") == "RubyGems"


def test_nuget_stays_nuget_but_correct_casing():
    assert to_osv_ecosystem("nuget") == "NuGet"


def test_composer_maps_to_packagist():
    assert to_osv_ecosystem("composer") == "Packagist"


def test_case_insensitive_input():
    assert to_osv_ecosystem("PyPI") == "PyPI"
    assert to_osv_ecosystem("NPM") == "npm"


def test_unmapped_ecosystem_returns_none_not_a_guess():
    assert to_osv_ecosystem("some-made-up-ecosystem") is None
